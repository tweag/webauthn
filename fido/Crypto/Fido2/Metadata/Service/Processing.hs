{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

module Crypto.Fido2.Metadata.Service.Processing
  ( getPayload,
    RootCertificate (..),
    createMetadataRegistry,
    metadataByKeyIdentifier,
    metadataByAaguid,
  )
where

import Control.Lens ((^.), (^?), _Just)
import Control.Monad.Except (ExceptT, MonadError (throwError), liftIO, withExceptT)
import qualified Crypto.Fido2.Metadata.Service.IDL as Service
import qualified Crypto.Fido2.Metadata.Statement.IDL as Statement
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.UAF as UAF
import Crypto.JOSE (fromX509Certificate)
import Crypto.JOSE.JWK.Store (VerificationKeyStore (getVerificationKeys))
import Crypto.JWT (Error (JWSInvalidSignature), HasX5c (x5c), JWSHeader, JWTError (JWSError), SignedJWT, decodeCompact, defaultJWTValidationSettings, param, unregisteredClaims, verifyClaims)
import Data.Aeson (Value (Object))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Lazy as LBS
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HashMap
import qualified Data.List.NonEmpty as NE
import Data.Maybe (mapMaybe)
import qualified Data.Text.Encoding as Text
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509

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

data MetadataServiceError
  = MetadataServiceErrorJWTError JWTError
  | MetadataServiceErrorJSONDecodingError String

-- | Decodes and verifies a FIDO Metadata Service blob according to https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
getPayload ::
  -- | The bytes of the blob
  LBS.ByteString ->
  -- | The root certificate the blob is signed with
  RootCertificate ->
  ExceptT MetadataServiceError IO Service.MetadataBLOBPayload
getPayload blob rootCert = do
  value <- withExceptT MetadataServiceErrorJWTError $ do
    jwt :: SignedJWT <- decodeCompact blob
    claims <- verifyClaims (defaultJWTValidationSettings (const True)) rootCert jwt
    return $ Object (claims ^. unregisteredClaims)
  case Aeson.fromJSON value of
    Aeson.Success payload -> return payload
    Aeson.Error err -> throwError $ MetadataServiceErrorJSONDecodingError err

data MetadataServiceRegistry = MetadataServiceRegistry
  { fido2Entries :: HashMap UUID Service.MetadataBLOBPayloadEntry,
    fidoU2FEntries :: HashMap BS.ByteString Service.MetadataBLOBPayloadEntry
  }

createMetadataRegistry :: Service.MetadataBLOBPayload -> MetadataServiceRegistry
createMetadataRegistry payload = MetadataServiceRegistry {..}
  where
    fido2Entries :: HashMap UUID Service.MetadataBLOBPayloadEntry
    fido2Entries = HashMap.fromList $ mapMaybe extractFido2Entry $ Service.entries payload

    fidoU2FEntries :: HashMap BS.ByteString Service.MetadataBLOBPayloadEntry
    fidoU2FEntries = HashMap.fromList $ foldMap extractFidoU2FEntry $ Service.entries payload

    extractFido2Entry entry = do
      Statement.AAGUID aaguidText <- Service.aaguid entry
      uuid <- UUID.fromText aaguidText
      pure (uuid, entry)

    extractFidoU2FEntry
      entry@Service.MetadataBLOBPayloadEntry
        { Service.attestationCertificateKeyIdentifiers = Just keyIds
        } =
        map (,entry) (mapMaybe getKeyId (NE.toList keyIds))
    extractFidoU2FEntry _ = []

    getKeyId (UAF.KeyIdentifier keyId) = case Base16.decode (Text.encodeUtf8 keyId) of
      Left _err -> Nothing
      Right result -> return result

metadataByKeyIdentifier :: X509.ExtSubjectKeyId -> MetadataServiceRegistry -> Maybe Service.MetadataBLOBPayloadEntry
metadataByKeyIdentifier (X509.ExtSubjectKeyId keyId) registry =
  HashMap.lookup keyId (fidoU2FEntries registry)

metadataByAaguid :: M.AAGUID -> MetadataServiceRegistry -> Maybe Service.MetadataBLOBPayloadEntry
metadataByAaguid (M.AAGUID aaguid) registry = do
  HashMap.lookup aaguid (fido2Entries registry)
