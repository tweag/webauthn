{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Crypto.WebAuthn.Metadata.Service.Decode
  ( decodeMetadataPayload,
    decodeMetadataEntry,
  )
where

import qualified Crypto.WebAuthn.Metadata.Service.IDL as ServiceIDL
import qualified Crypto.WebAuthn.Metadata.Service.Types as ServiceTypes
import Crypto.WebAuthn.Metadata.Statement.Decode (decodeAAGUID, decodeCertificate, decodeMetadataStatement, decodeSubjectKeyIdentifier)
import qualified Crypto.WebAuthn.WebIDL as IDL
import Data.Bifunctor (first)
import Data.Hourglass (Date, DateTime (dtDate), ISO8601_Date (ISO8601_Date), timeParse)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
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
  decodedEntries <- sequence $ mapMaybe decodeMetadataEntry entries
  let mpEntries = foldMap NE.toList decodedEntries
  pure ServiceTypes.MetadataPayload {..}

liftEitherMaybe :: Either (Maybe a) b -> Maybe (Either a b)
liftEitherMaybe (Left Nothing) = Nothing
liftEitherMaybe (Left (Just a)) = Just $ Left a
liftEitherMaybe (Right b) = Just $ Right b

decodeMetadataEntry :: ServiceIDL.MetadataBLOBPayloadEntry -> Maybe (Either Text (NonEmpty ServiceTypes.SomeMetadataEntry))
decodeMetadataEntry ServiceIDL.MetadataBLOBPayloadEntry {..} = liftEitherMaybe $
  case (aaid, aaguid, attestationCertificateKeyIdentifiers) of
    (Just _aaid, Nothing, Nothing) ->
      -- This is an UAF entry, we can skip it since it's not relevant for webauthn
      Left Nothing
    (Nothing, Just aaguid, Nothing) -> do
      -- This is a FIDO 2 entry
      identifier <- first Just $ decodeAAGUID aaguid
      meMetadataStatement <- traverse decodeMetadataStatement metadataStatement
      meStatusReports <- first Just $ traverse decodeStatusReport statusReports
      meTimeOfLastStatusChange <- first Just $ decodeDate timeOfLastStatusChange
      Right $ pure $ ServiceTypes.SomeMetadataEntry identifier ServiceTypes.MetadataEntry {..}
    (Nothing, Nothing, Just attestationCertificateKeyIdentifiers) -> do
      -- This is a FIDO U2F entry
      identifiers <- first Just $ traverse decodeSubjectKeyIdentifier attestationCertificateKeyIdentifiers
      meMetadataStatement <- traverse decodeMetadataStatement metadataStatement
      meStatusReports <- first Just $ traverse decodeStatusReport statusReports
      meTimeOfLastStatusChange <- first Just $ decodeDate timeOfLastStatusChange
      let entry = ServiceTypes.MetadataEntry {..}
      Right $ fmap (`ServiceTypes.SomeMetadataEntry` entry) identifiers
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
