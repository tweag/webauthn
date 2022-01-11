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
    ProcessingError (..),
    createMetadataRegistry,
    queryMetadata,
    jwtToJson,
    jsonToPayload,
    fidoAllianceRootCertificate,
  )
where

import Control.Lens ((^.), (^?), _Just)
import Control.Lens.Combinators (makeClassyPrisms)
import Control.Monad.Except (MonadError, runExcept, throwError)
import Control.Monad.Reader (MonadReader, ask, runReaderT)
import Crypto.JOSE (AsError (_Error), fromX509Certificate)
import Crypto.JOSE.JWK.Store (VerificationKeyStore (getVerificationKeys))
import Crypto.JOSE.Types (URI)
import Crypto.JWT
  ( AsJWTError (_JWTError),
    Error,
    HasX5c (x5c),
    HasX5u (x5u),
    JWSHeader,
    JWTError,
    SignedJWT,
    decodeCompact,
    defaultJWTValidationSettings,
    param,
    unregisteredClaims,
    verifyClaims,
  )
import Crypto.WebAuthn.Identifier
  ( AAGUID,
    AuthenticatorIdentifier
      ( AuthenticatorIdentifierFido2,
        AuthenticatorIdentifierFidoU2F,
        idAaguid,
        idSubjectKeyIdentifier
      ),
    SubjectKeyIdentifier,
  )
import Crypto.WebAuthn.Internal.DateOrphans ()
import qualified Crypto.WebAuthn.Internal.X509Validation as X509
import Crypto.WebAuthn.Metadata.Service.Decode (decodeMetadataPayload)
import qualified Crypto.WebAuthn.Metadata.Service.Types as Service
import qualified Crypto.WebAuthn.Model.Types as M
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

-- | Errors related to the processing of the metadata
data ProcessingError
  = -- | An error wrapping the errors encountered by the X509 Validation
    ProcessingValidationErrors (NE.NonEmpty X509.FailedReason)
  | -- | There was no x5c header present in the metadata JWT
    ProcessingMissingX5CHeader
  | -- | An error wrapping the general Errors from the JOSE library
    ProcessingJWSError Error
  | -- | An error wrapping the JWT specific Errors from the JOSE library
    ProcessingJWTError JWTError
  | -- | There was a x5u header present in the metadata JWT but this is unimplemented
    -- TODO: Implement step 4 of the
    -- [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules)
    ProcessingX5UPresent URI
  deriving (Show, Eq)

-- | Create Prisms for the error type, used in the AsError and AsJWTError
-- instances below
makeClassyPrisms ''ProcessingError

-- | Instantiate JOSE's AsError typeclass as a simple cast to our own error
-- type. This allows using our own error type in JOSE operations.
instance AsError ProcessingError where
  _Error = _ProcessingJWSError

-- | Instantiate JOSE's AsJWTError typeclass as a simple cast to our own error
-- type. This allows using our own error type in JWT operations.
instance AsJWTError ProcessingError where
  _JWTError = _ProcessingJWTError

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

instance (MonadError ProcessingError m, MonadReader DateTime m) => VerificationKeyStore m (JWSHeader ()) p RootCertificate where
  getVerificationKeys header _ (RootCertificate rootStore hostName) = do
    -- TODO: Implement step 4 of the spec, which says to try to get the chain
    -- from x5u first before trying x5c. See:
    -- <https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules>
    -- and <https://github.com/tweag/webauthn/issues/23>
    --
    -- In order to prevent issues due to the lack of an implementation for x5u,
    -- we do check if it is empty before continuing. If not empty, we result in
    -- an error instead.
    case header ^? x5u . _Just . param of
      Nothing -> pure ()
      Just uri -> throwError $ ProcessingX5UPresent uri

    chain <- case header ^? x5c . _Just . param of
      Nothing ->
        throwError ProcessingMissingX5CHeader
      Just chain -> return chain

    now <- ask

    -- TODO: Check CRLs, see <https://github.com/tweag/haskell-fido2/issues/23>
    let validationErrors =
          X509.validatePure
            now
            X509.defaultHooks
            X509.defaultChecks
            rootStore
            (hostName, "")
            (X509.CertificateChain (NE.toList chain))

    case NE.nonEmpty validationErrors of
      Nothing -> do
        -- Create a JWK from the leaf certificate, which is used to sign the payload
        jwk <- fromX509Certificate (NE.head chain)
        return [jwk]
      Just errors ->
        throwError $ ProcessingValidationErrors errors

-- | Extracts a FIDO Metadata payload JSON value from a JWT bytestring according to https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
jwtToJson ::
  -- | The bytes of the JWT blob
  BS.ByteString ->
  -- | The root certificate the blob is signed with
  RootCertificate ->
  -- | The current time for which to validate the JWT blob
  DateTime ->
  Either ProcessingError Value
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
      AuthenticatorIdentifier p ->
      Service.MetadataEntry p ->
      Maybe (AAGUID, Service.MetadataEntry 'M.Fido2)
    getFido2Pairs' ident entry = case sing @p of
      M.SFido2 ->
        Just (idAaguid ident, entry)
      _ -> Nothing

    getFidoU2FPairs' ::
      forall p.
      SingI p =>
      AuthenticatorIdentifier p ->
      Service.MetadataEntry p ->
      Maybe (SubjectKeyIdentifier, Service.MetadataEntry 'M.FidoU2F)
    getFidoU2FPairs' ident entry = case sing @p of
      M.SFidoU2F ->
        Just (idSubjectKeyIdentifier ident, entry)
      _ -> Nothing

-- | Query a 'Service.MetadataEntry' for an 'M.AuthenticatorIdentifier'
queryMetadata ::
  Service.MetadataServiceRegistry ->
  AuthenticatorIdentifier p ->
  Maybe (Service.MetadataEntry p)
queryMetadata registry (AuthenticatorIdentifierFido2 aaguid) =
  HashMap.lookup aaguid (Service.fido2Entries registry)
queryMetadata registry (AuthenticatorIdentifierFidoU2F subjectKeyIdentifier) =
  HashMap.lookup subjectKeyIdentifier (Service.fidoU2FEntries registry)
