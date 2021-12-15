{-# LANGUAGE RecordWildCards #-}

module Crypto.WebAuthn.Metadata.Service.Decode
  ( decodeMetadataPayload,
    decodeMetadataEntry,
  )
where

import qualified Crypto.WebAuthn.Metadata.Service.IDL as ServiceIDL
import qualified Crypto.WebAuthn.Metadata.Service.Types as ServiceTypes
import Crypto.WebAuthn.Metadata.Statement.Decode (decodeAAGUID, decodeCertificate, decodeMetadataStatement, decodeSubjectKeyIdentifier)
import Crypto.WebAuthn.Metadata.Statement.Types (MetadataEntryIdentifier (MetadataEntryIdentifierFido2, MetadataEntryIdentifierFidoU2F))
import qualified Crypto.WebAuthn.WebIDL as IDL
import Data.Bifunctor (first)
import Data.Hourglass (Date, DateTime (dtDate), ISO8601_Date (ISO8601_Date), timeParse)
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import qualified Data.Text as Text

-- | Decodes a 'ServiceTypes.MetadataPayload' from a 'ServiceIDL.MetadataBLOBPayload',
-- discarding any 'ServiceIDL.MetadataBLOBPayloadEntry' that are not relevant to webauthn.
-- This includes entries of the protocol family 'StatementIDL.ProtocolFamilyUAF'
-- and entries whose 'StatementIDL.attestationTypes' doesn't include either
-- 'Registry.ATTESTATION_BASIC_FULL' or 'Registry.ATTESTATION_ATTCA'
decodeMetadataPayload :: ServiceIDL.MetadataBLOBPayload -> Either Text ServiceTypes.MetadataPayload
decodeMetadataPayload ServiceIDL.MetadataBLOBPayload {..} = do
  let mpLegalHeader = legalHeader
      mpNo = no
  mpNextUpdate <- decodeDate nextUpdate
  mpEntries <- sequence $ mapMaybe decodeMetadataEntry entries
  pure ServiceTypes.MetadataPayload {..}

liftEitherMaybe :: Either (Maybe a) b -> Maybe (Either a b)
liftEitherMaybe (Left Nothing) = Nothing
liftEitherMaybe (Left (Just a)) = Just $ Left a
liftEitherMaybe (Right b) = Just $ Right b

decodeMetadataEntry :: ServiceIDL.MetadataBLOBPayloadEntry -> Maybe (Either Text ServiceTypes.SomeMetadataEntry)
decodeMetadataEntry ServiceIDL.MetadataBLOBPayloadEntry {..} = liftEitherMaybe $
  case (aaid, aaguid, attestationCertificateKeyIdentifiers) of
    (Just _aaid, Nothing, Nothing) ->
      -- This is an UAF entry, we can skip it since it's not relevant for webauthn
      Left Nothing
    (Nothing, Just aaguid, Nothing) -> do
      -- This is a FIDO 2 entry
      meIdentifier <-
        first Just $
          MetadataEntryIdentifierFido2
            <$> decodeAAGUID aaguid
      meMetadataStatement <- traverse (decodeMetadataStatement meIdentifier) metadataStatement
      meStatusReports <- first Just $ traverse decodeStatusReport statusReports
      meTimeOfLastStatusChange <- first Just $ decodeDate timeOfLastStatusChange
      Right $ ServiceTypes.SomeMetadataEntry $ ServiceTypes.MetadataEntry {..}
    (Nothing, Nothing, Just attestationCertificateKeyIdentifiers) -> do
      -- This is a FIDO U2F entry
      meIdentifier <-
        first Just $
          MetadataEntryIdentifierFidoU2F
            <$> traverse decodeSubjectKeyIdentifier attestationCertificateKeyIdentifiers
      meMetadataStatement <- traverse (decodeMetadataStatement meIdentifier) metadataStatement
      meStatusReports <- first Just $ traverse decodeStatusReport statusReports
      meTimeOfLastStatusChange <- first Just $ decodeDate timeOfLastStatusChange
      Right $ ServiceTypes.SomeMetadataEntry $ ServiceTypes.MetadataEntry {..}
    (Nothing, Nothing, Nothing) ->
      Left $ Just "None of aaid, aaguid or attestationCertificateKeyIdentifiers are set for this entry"
    _ ->
      Left $ Just "Multiple of aaid, aaguid and/or attestationCertificateKeyIdentifiers are set for this entry"

decodeStatusReport :: ServiceIDL.StatusReport -> Either Text ServiceTypes.StatusReport
decodeStatusReport ServiceIDL.StatusReport {..} = do
  let srStatus = status
  srEffectiveDate <- traverse decodeDate effectiveDate
  let srAuthenticatorVersion = authenticatorVersion
  srCertificate <- traverse decodeCertificate certificate
  let srUrl = url
      srCertificationDescriptor = certificationDescriptor
      srCertificateNumber = certificateNumber
      srCertificationPolicyVersion = certificationPolicyVersion
      srCertificationRequirementsVersion = certificationRequirementsVersion
  pure ServiceTypes.StatusReport {..}

decodeDate :: IDL.DOMString -> Either Text Date
decodeDate text = case timeParse ISO8601_Date (Text.unpack text) of
  Nothing -> Left $ "Could not parse ISO 8601 date: " <> text
  Just dt -> Right $ dtDate dt
