{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.WebAuthn.Metadata.Service.Types
  ( MetadataPayload (..),
    MetadataEntry (..),
    SomeMetadataEntry (..),
    StatusReport (..),
  )
where

import qualified Crypto.WebAuthn.Metadata.Service.IDL as ServiceIDL
import Crypto.WebAuthn.Metadata.Statement.Types (MetadataStatement)
import qualified Crypto.WebAuthn.Model as M
import Data.Hourglass (Date)
import Data.List.NonEmpty (NonEmpty)
import Data.Singletons (SingI)
import Data.Text (Text)
import Data.Word (Word32)
import qualified Data.X509 as X509

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary)
-- Same as 'StatementIDL.MetadataBLOBPayload', but fully decoded. However all
-- 'StatementIDL.entries' not relevant for webauthn are discarded
data MetadataPayload = MetadataPayload
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-legalheader)
    mpLegalHeader :: Maybe Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-no)
    mpNo :: Int,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-nextupdate)
    mpNextUpdate :: Date,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayload-entries)
    mpEntries :: [SomeMetadataEntry]
  }

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary)
-- Same as 'StatementIDL.MetadataBLOBPayloadEntry', but fully decoded. This type
-- is parametrized over the 'StatementIDL.ProtocolFamily' this metadata entry is for
data MetadataEntry (p :: M.ProtocolKind) = MetadataEntry
  { -- [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-metadatastatement)
    meMetadataStatement :: Maybe (MetadataStatement p),
    -- TODO: Implement this, currently not used in the blob however
    -- meBiometricStatusReports :: Maybe (NonEmpty BiometricStatusReport),

    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-statusreports)
    meStatusReports :: NonEmpty StatusReport,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-timeoflaststatuschange)
    meTimeOfLastStatusChange :: Date
    -- rogueListURL, rogueListHash. TODO, but not currently used in the
    -- BLOB and difficult to implement since it involves JWT
  }
  deriving (Eq, Show)

-- | Same as 'MetadataEntry', but with its type parameter erased
data SomeMetadataEntry = forall p. SingI p => SomeMetadataEntry (M.AuthenticatorIdentifier p) (MetadataEntry p)

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
  deriving (Eq, Show)
