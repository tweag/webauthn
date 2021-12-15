{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

module Crypto.WebAuthn.Metadata.Service.Processing
  ( RootCertificate (..),
    jwtToJson,
    jsonToPayload,
  )
where

import Control.Lens ((^.), (^?), _Just)
import Control.Monad.Except (MonadError, runExcept, throwError)
import Control.Monad.Reader (MonadReader, ask, runReaderT)
import Crypto.JOSE (fromX509Certificate)
import Crypto.JOSE.JWK.Store (VerificationKeyStore (getVerificationKeys))
import Crypto.JWT (Error (JWSInvalidSignature), HasX5c (x5c), JWSHeader, JWTError (JWSError), SignedJWT, decodeCompact, defaultJWTValidationSettings, param, unregisteredClaims, verifyClaims)
import Crypto.WebAuthn.DateOrphans ()
import Crypto.WebAuthn.Metadata.Service.Decode (decodeMetadataPayload)
import qualified Crypto.WebAuthn.Metadata.Service.Types as Service
import Data.Aeson (Value (Object))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Hourglass (DateTime)
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509

-- | A root certificate along with the host it should be verified against
data RootCertificate = RootCertificate
  { -- | The root certificate itself
    rootCertificate :: X509.SignedCertificate,
    -- | The hostname it is for
    rootCertificateHostName :: X509.HostName
  }

instance (MonadError JWTError m, MonadReader DateTime m) => VerificationKeyStore m (JWSHeader ()) p RootCertificate where
  getVerificationKeys header _ (RootCertificate rootCert hostName) = do
    -- TODO: Implement step 4 of the spec, which says to try to get the chain from x5u first before trying x5c
    -- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules
    chain <- case header ^? x5c . _Just . param of
      Nothing ->
        -- FIXME: Return a better error here, but we can't modify the jose libraries error type
        throwError $ JWSError JWSInvalidSignature
      Just chain -> return chain

    now <- ask

    -- TODO: Check CRLs, see https://github.com/tweag/haskell-fido2/issues/23
    let validationErrors =
          X509.validatePure
            now
            X509.defaultHooks
            X509.defaultChecks
            (X509.makeCertificateStore [rootCert])
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

-- | Extracts a FIDO Metadata payload JSON value from a JWT bytestring according to https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
jwtToJson ::
  -- | The bytes of the JWT blob
  BS.ByteString ->
  -- | The root certificate the blob is signed with
  RootCertificate ->
  -- | The current time for which to validate the JWT blob
  DateTime ->
  Either JWTError Value
jwtToJson blob rootCert now = runExcept $ do
  jwt :: SignedJWT <- decodeCompact $ LBS.fromStrict blob
  claims <- runReaderT (verifyClaims (defaultJWTValidationSettings (const True)) rootCert jwt) now
  return $ Object (claims ^. unregisteredClaims)

-- | Decodes a FIDO Metadata payload JSON value to a 'Service.MetadataPayload',
-- returning an error when the JSON is invalid, and ignoring any entries not
-- relevant for webauthn
jsonToPayload :: Value -> Either Text Service.MetadataPayload
jsonToPayload value = case Aeson.fromJSON value of
  Aeson.Error err -> Left $ Text.pack err
  Aeson.Success payload -> case decodeMetadataPayload payload of
    Left err -> Left err
    Right result -> pure result
