{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}

-- | Stability: experimental
-- This module contains additional Haskell-specific type definitions for the
-- [FIDO Metadata Service](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html)
-- specification
module Crypto.WebAuthn.Metadata.Service.Types
  ( MetadataServiceRegistry (..),
    MetadataPayload (..),
    MetadataEntry (..),
    SomeMetadataEntry (..),
    StatusReport (..),
  )
where

import qualified Crypto.WebAuthn.Metadata.Service.WebIDL as ServiceIDL
import Crypto.WebAuthn.Metadata.Statement.Types (MetadataStatement)
import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.Model.Identifier (AAGUID, AuthenticatorIdentifier, SubjectKeyIdentifier)
import Data.Aeson (ToJSON)
import Data.HashMap.Strict (HashMap)
import Data.Hourglass (Date)
import Data.List.NonEmpty (NonEmpty)
import Data.Singletons (SingI)
import Data.Text (Text)
import Data.Word (Word32)
import qualified Data.X509 as X509
import GHC.Generics (Generic)

-- | A registry of 'MetadataEntry's, allowing fast lookup using 'M.AAGUID's or
-- 'SubjectKeyIdentifier's. This is used by 'Crypto.WebAuthn.Operation.Registration.verifyRegistrationResponse'
-- as a way to look up root certificates of authenticators and return meta information.
-- Using 'Crypto.WebAuthn.Metadata.Service.Processing.createMetadataRegistry'
-- it's also possible to create additional custom entries, which can be merged
-- with '<>'. Meanwhile 'mempty' can be used if no metadata is needed.
data MetadataServiceRegistry = MetadataServiceRegistry
  { fido2Entries :: HashMap AAGUID (MetadataEntry 'M.Fido2),
    fidoU2FEntries :: HashMap SubjectKeyIdentifier (MetadataEntry 'M.FidoU2F)
  }

instance Semigroup MetadataServiceRegistry where
  MetadataServiceRegistry l2 lu2f <> MetadataServiceRegistry r2 ru2f =
    MetadataServiceRegistry (l2 <> r2) (lu2f <> ru2f)

instance Monoid MetadataServiceRegistry where
  mempty = MetadataServiceRegistry mempty mempty

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary)
-- Same as 'StatementIDL.MetadataBLOBPayload', but fully decoded. However all
-- 'StatementIDL.entries' not relevant for webauthn are discarded
data MetadataPayload = MetadataPayload
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-legalheader)
    -- The legalHeader, which MUST be in each BLOB, is an indication of the
    -- acceptance of the relevant legal agreement for using the MDS.
    mpLegalHeader :: Maybe Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-no)
    -- The serial number of this UAF Metadata BLOB Payload. Serial numbers MUST
    -- be consecutive and strictly monotonic, i.e. the successor BLOB will have
    -- a no value exactly incremented by one.
    mpNo :: Int,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-nextupdate)
    -- Date when the next update will be provided at latest.
    mpNextUpdate :: Date,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-entries)
    -- List of zero or more entries. This can be passed to
    -- 'Crypto.WebAuthn.Metadata.Service.Processing.createMetadataRegistry'
    mpEntries :: [SomeMetadataEntry]
  }

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary)
-- Same as 'StatementIDL.MetadataBLOBPayloadEntry', but fully decoded. This type
-- is parametrized over the 'StatementIDL.ProtocolFamily' this metadata entry is for
data MetadataEntry (p :: M.ProtocolKind) = MetadataEntry
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-aaguid) or [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-attestationcertificatekeyidentifiers)
    meIdentifier :: AuthenticatorIdentifier p,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-metadatastatement)
    meMetadataStatement :: Maybe MetadataStatement,
    -- TODO: Implement this, currently not used in the blob however
    -- meBiometricStatusReports :: Maybe (NonEmpty BiometricStatusReport),

    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-statusreports)
    meStatusReports :: NonEmpty StatusReport,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-timeoflaststatuschange)
    meTimeOfLastStatusChange :: Date
    -- rogueListURL, rogueListHash. TODO, but not currently used in the
    -- BLOB and difficult to implement since it involves JWT
  }
  deriving (Eq, Show, Generic, ToJSON)

-- | Same as 'MetadataEntry', but with its type parameter erased
data SomeMetadataEntry = forall p. SingI p => SomeMetadataEntry (MetadataEntry p)

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary)
-- Same as 'StatementIDL.StatusReport', but fully decoded.
data StatusReport = StatusReport
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-status)
    srStatus :: ServiceIDL.AuthenticatorStatus,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-effectivedate)
    srEffectiveDate :: Maybe Date,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-authenticatorversion)
    srAuthenticatorVersion :: Maybe Word32,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificate)
    srCertificate :: Maybe X509.SignedCertificate,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-url)
    srUrl :: Maybe Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificationdescriptor)
    srCertificationDescriptor :: Maybe Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificatenumber)
    srCertificateNumber :: Maybe Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificationpolicyversion)
    srCertificationPolicyVersion :: Maybe Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-statusreport-certificationrequirementsversion)
    srCertificationRequirementsVersion :: Maybe Text
  }
  deriving (Eq, Show, Generic, ToJSON)
