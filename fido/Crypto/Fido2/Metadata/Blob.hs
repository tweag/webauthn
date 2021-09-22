{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Fido2.Metadata.Blob
  ( getPayload,
    RootCertificate (..),
    MetadataBlobPayload (..),
    module Crypto.Fido2.Metadata.Model,
  )
where

import Control.Lens ((^.), (^?), _Just)
import Control.Monad.Except (ExceptT, MonadError (throwError), liftIO)
import Crypto.Fido2.EncodingUtils (modifyTypeField)
import Crypto.Fido2.Metadata.Model (Entry)
import Crypto.JOSE (fromX509Certificate)
import Crypto.JOSE.JWK.Store (VerificationKeyStore (getVerificationKeys))
import Crypto.JWT (Error (JWSInvalidSignature), HasX5c (x5c), JWSHeader, JWTError (JWSError), SignedJWT, decodeCompact, defaultJWTValidationSettings, param, unregisteredClaims, verifyClaims)
import Data.Aeson (FromJSON, ToJSON, Value (Object), genericToJSON)
import Data.Aeson.Types
  ( FromJSON (parseJSON),
    Options (fieldLabelModifier),
    ToJSON (toJSON),
    defaultOptions,
    genericParseJSON,
  )
import qualified Data.ByteString.Lazy as LBS
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import Data.Time (Day)
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509
import GHC.Generics (Generic)

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary
data MetadataBlobPayload = MetadataBlobPayload
  { metadataNo :: Int,
    metadataNextUpdate :: Day,
    metadataLegalHeader :: Text,
    metadataEntries :: [Entry]
  }
  deriving (Show, Eq, Generic)

instance FromJSON MetadataBlobPayload where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "metadata"
        }

instance ToJSON MetadataBlobPayload where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "metadata"
        }

data RootCertificate = RootCertificate
  { -- | The root certificate itself
    rootCertificate :: X509.SignedCertificate,
    -- | The hostname it is for
    rootCertificateHostName :: X509.HostName
  }

instance VerificationKeyStore (ExceptT JWTError IO) (JWSHeader ()) p RootCertificate where
  getVerificationKeys header _ (RootCertificate rootCert hostName) = do
    -- TODO: Implement step 4 of the spec, which says to try to get the chain from x5u first before trying x5c
    -- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules
    chain <- case header ^? x5c . _Just . param of
      Nothing ->
        -- FIXME: Return a better error here, but we can't modify the jose libraries error type
        throwError $ JWSError JWSInvalidSignature
      Just chain -> return chain

    validationErrors <-
      liftIO $
        -- TODO: Check CRLs, see https://github.com/tweag/haskell-fido2/issues/23
        X509.validate
          -- TODO: Does the SHA256 choice matter here?
          -- I think it's probably only for the cache, which we don't use
          X509.HashSHA256
          X509.defaultHooks
          X509.defaultChecks
          (X509.makeCertificateStore [rootCert])
          (X509.exceptionValidationCache [])
          (hostName, "")
          (X509.CertificateChain (NE.toList chain))

    case validationErrors of
      [] -> do
        -- Create a JWK from the leaf certificate, which is used to sign the payload
        jwk <- fromX509Certificate (NE.head chain)
        return [jwk]
      _errors ->
        -- FIXME: We're currently discarding these errors by necessity, because we're bound by the JOSE libraries error type
        throwError $ JWSError JWSInvalidSignature

-- | Decodes and verifies a FIDO Metadata Service blob according to https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
getPayload ::
  -- | The bytes of the blob
  LBS.ByteString ->
  -- | The root certificate the blob is signed with
  RootCertificate ->
  ExceptT JWTError IO Value
getPayload blob rootCert = do
  jwt :: SignedJWT <- decodeCompact blob
  claims <- verifyClaims (defaultJWTValidationSettings (const True)) rootCert jwt
  return $ Object (claims ^. unregisteredClaims)
