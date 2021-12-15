{-# LANGUAGE DuplicateRecordFields #-}

-- | <https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html>
module Crypto.WebAuthn.Metadata.Service.IDL
  ( MetadataBLOBPayloadEntry (..),
    BiometricStatusReport (..),
    StatusReport (..),
    AuthenticatorStatus (..),
    MetadataBLOBPayload (..),
  )
where

-- Note from https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#notation :
-- Unless otherwise specified, if a WebIDL dictionary member is DOMString, it MUST NOT be empty.
-- Unless otherwise specified, if a WebIDL dictionary member is a List, it MUST NOT be an empty list.

import Crypto.WebAuthn.EncodingUtils (CustomJSON (CustomJSON), JSONEncoding)
import Crypto.WebAuthn.Metadata.Statement.IDL (AAGUID, MetadataStatement)
import qualified Crypto.WebAuthn.UAF as UAF
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.List.NonEmpty (NonEmpty)
import GHC.Generics (Generic)

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary)
data MetadataBLOBPayloadEntry = MetadataBLOBPayloadEntry
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-aaid)
    aaid :: Maybe UAF.AAID,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-aaguid)
    aaguid :: Maybe AAGUID,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-attestationcertificatekeyidentifiers)
    attestationCertificateKeyIdentifiers :: Maybe (NonEmpty IDL.DOMString),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-metadatastatement)
    metadataStatement :: Maybe MetadataStatement,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-biometricstatusreports)
    biometricStatusReports :: Maybe (NonEmpty BiometricStatusReport),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-statusreports)
    statusReports :: NonEmpty StatusReport,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-timeoflaststatuschange)
    timeOfLastStatusChange :: IDL.DOMString
    -- Unused in the current blob, also annoying to implement
    -- entryRogueListURL :: IDL.DOMString,
    -- entryRogueListHash :: IDL.DOMString
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding MetadataBLOBPayloadEntry

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary)
data BiometricStatusReport = BiometricStatusReport
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certlevel)
    certLevel :: IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-modality)
    modality :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-effectivedate)
    effectiveDate :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certificationdescriptor)
    certificationDescriptor :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certificatenumber)
    certificateNumber :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certificationpolicyversion)
    certificationPolicyVersion :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-biometricstatusreport-certificationrequirementsversion)
    certificationRequirementsVersion :: Maybe IDL.DOMString
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding BiometricStatusReport

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary)
data StatusReport = StatusReport
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-status)
    status :: AuthenticatorStatus,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-effectivedate)
    effectiveDate :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-authenticatorversion)
    authenticatorVersion :: Maybe IDL.UnsignedLong,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificate)
    certificate :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-url)
    url :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificationdescriptor)
    certificationDescriptor :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificatenumber)
    certificateNumber :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificationpolicyversion)
    certificationPolicyVersion :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificationrequirementsversion)
    certificationRequirementsVersion :: Maybe IDL.DOMString
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding StatusReport

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum)
data AuthenticatorStatus
  = NOT_FIDO_CERTIFIED
  | FIDO_CERTIFIED
  | USER_VERIFICATION_BYPASS
  | ATTESTATION_KEY_COMPROMISE
  | USER_KEY_REMOTE_COMPROMISE
  | USER_KEY_PHYSICAL_COMPROMISE
  | UPDATE_AVAILABLE
  | REVOKED
  | SELF_ASSERTION_SUBMITTED
  | FIDO_CERTIFIED_L1
  | FIDO_CERTIFIED_L1plus
  | FIDO_CERTIFIED_L2
  | FIDO_CERTIFIED_L2plus
  | FIDO_CERTIFIED_L3
  | FIDO_CERTIFIED_L3plus
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding AuthenticatorStatus

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary)
data MetadataBLOBPayload = MetadataBLOBPayload
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-legalheader)
    legalHeader :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-no)
    no :: Int,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-nextupdate)
    nextUpdate :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-entries)
    entries :: [MetadataBLOBPayloadEntry]
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding MetadataBLOBPayload
