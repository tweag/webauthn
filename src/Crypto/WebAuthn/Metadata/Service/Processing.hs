{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}

module Crypto.WebAuthn.Metadata.Service.Processing
  ( RootCertificate (..),
    createMetadataRegistry,
    queryMetadata,
    jwtToJson,
    jsonToPayload,
    fidoAllianceRootCertificate,
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
import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.SubjectKeyIdentifier (SubjectKeyIdentifier)
import Data.Aeson (Value (Object))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.FileEmbed (embedFile)
import qualified Data.HashMap.Strict as HashMap
import Data.Hourglass (DateTime)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (mapMaybe)
import Data.Singletons (SingI, sing)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509

-- | A root certificate along with the host it should be verified against
data RootCertificate = RootCertificate
  { -- | The root certificate itself
    rootCertificateStore :: X509.CertificateStore,
    -- | The hostname it is for
    rootCertificateHostName :: X509.HostName
  }

-- | The root certificate used for the blob downloaded from <https://mds.fidoalliance.org/>,
-- which can be found in [here](https://valid.r3.roots.globalsign.com/),
-- see also <https://fidoalliance.org/metadata/>
fidoAllianceRootCertificate :: RootCertificate
fidoAllianceRootCertificate =
  RootCertificate
    { rootCertificateStore = X509.makeCertificateStore [rootCert],
      rootCertificateHostName = "mds.fidoalliance.org"
    }
  where
    bytes :: BS.ByteString
    bytes = $(embedFile "root-certs/metadata/root.crt")
    rootCert :: X509.SignedCertificate
    rootCert = case X509.decodeSignedCertificate bytes of
      Left err -> error err
      Right cert -> cert

instance (MonadError JWTError m, MonadReader DateTime m) => VerificationKeyStore m (JWSHeader ()) p RootCertificate where
  getVerificationKeys header _ (RootCertificate rootStore hostName) = do
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
            rootStore
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

-- | Creates a 'Service.MetadataServiceRegistry' from a list of
-- 'Service.SomeMetadataEntry', which can either be obtained from a
-- 'Service.MetadataPayload's 'Service.mpEntries' field, or be constructed
-- directly
--
-- The resulting structure can be queried efficiently for
-- 'Service.MetadataEntry' using 'metadataByAaguid' and 'metadataBySubjectKeyIdentifier'
createMetadataRegistry :: [Service.SomeMetadataEntry] -> Service.MetadataServiceRegistry
createMetadataRegistry entries = Service.MetadataServiceRegistry {..}
  where
    fido2Entries = HashMap.fromList $ mapMaybe getFido2Pairs entries
    fidoU2FEntries = HashMap.fromList $ mapMaybe getFidoU2FPairs entries

    getFido2Pairs (Service.SomeMetadataEntry ident entry) = getFido2Pairs' ident entry
    getFidoU2FPairs (Service.SomeMetadataEntry ident entry) = getFidoU2FPairs' ident entry

    getFido2Pairs' ::
      forall p.
      SingI p =>
      M.AuthenticatorIdentifier p ->
      Service.MetadataEntry p ->
      Maybe (M.AAGUID, Service.MetadataEntry 'M.Fido2)
    getFido2Pairs' ident entry = case sing @p of
      M.SFido2 ->
        Just (M.idAaguid ident, entry)
      _ -> Nothing

    getFidoU2FPairs' ::
      forall p.
      SingI p =>
      M.AuthenticatorIdentifier p ->
      Service.MetadataEntry p ->
      Maybe (SubjectKeyIdentifier, Service.MetadataEntry 'M.FidoU2F)
    getFidoU2FPairs' ident entry = case sing @p of
      M.SFidoU2F ->
        Just (M.idSubjectKeyIdentifier ident, entry)
      _ -> Nothing

-- | Query a 'Service.MetadataEntry' for an 'M.AuthenticatorIdentifier'
queryMetadata ::
  Service.MetadataServiceRegistry ->
  M.AuthenticatorIdentifier p ->
  Maybe (Service.MetadataEntry p)
queryMetadata registry (M.AuthenticatorIdentifierFido2 aaguid) =
  HashMap.lookup aaguid (Service.fido2Entries registry)
queryMetadata registry (M.AuthenticatorIdentifierFidoU2F subjectKeyIdentifier) =
  HashMap.lookup subjectKeyIdentifier (Service.fidoU2FEntries registry)
