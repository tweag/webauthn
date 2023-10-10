{-# LANGUAGE StandaloneDeriving #-}

-- | Stability: experimental
-- This module contains additional Haskell-specific type definitions for the
-- [FIDO Metadata Statement](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html)
-- specification
module Crypto.WebAuthn.Metadata.Statement.Types
  ( MetadataStatement (..),
    PNGBytes (..),
    WebauthnAttestationType (..),
  )
where

import Crypto.WebAuthn.Internal.ToJSONOrphans (PrettyHexByteString (PrettyHexByteString))
import qualified Crypto.WebAuthn.Metadata.FidoRegistry as Registry
import qualified Crypto.WebAuthn.Metadata.Statement.WebIDL as StatementIDL
import qualified Crypto.WebAuthn.Metadata.UAF as UAF
import Data.Aeson (ToJSON)
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import Data.Word (Word32)
import qualified Data.X509 as X509
import GHC.Generics (Generic)
import GHC.Word (Word16)

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys)
data MetadataStatement = MetadataStatement
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-legalheader)
    msLegalHeader :: Text,
    -- msAaid, msAaguid, attestationCertificateKeyIdentifiers: These fields are the key of the hashmaps in MetadataServiceRegistry

    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-description)
    msDescription :: Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-alternativedescriptions)
    msAlternativeDescriptions :: Maybe StatementIDL.AlternativeDescriptions,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorversion)
    msAuthenticatorVersion :: Word32,
    -- protocolFamily, encoded as the type-level p
    -- msSchema, this is always schema version 3

    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-upv)
    msUpv :: NonEmpty UAF.Version,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticationalgorithms)
    msAuthenticationAlgorithms :: NonEmpty Registry.AuthenticationAlgorithm,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-publickeyalgandencodings)
    msPublicKeyAlgAndEncodings :: NonEmpty Registry.PublicKeyRepresentationFormat,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationtypes)
    msAttestationTypes :: NonEmpty WebauthnAttestationType,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-userverificationdetails)
    msUserVerificationDetails :: NonEmpty StatementIDL.VerificationMethodANDCombinations,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-keyprotection)
    msKeyProtection :: NonEmpty Registry.KeyProtectionType,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-iskeyrestricted)
    msIsKeyRestricted :: Maybe Bool,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-isfreshuserverificationrequired)
    msIsFreshUserVerificationRequired :: Maybe Bool,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-matcherprotection)
    msMatcherProtection :: NonEmpty Registry.MatcherProtectionType,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-cryptostrength)
    msCryptoStrength :: Maybe Word16,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attachmenthint)
    msAttachmentHint :: NonEmpty Registry.AuthenticatorAttachmentHint,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplay)
    msTcDisplay :: [Registry.TransactionConfirmationDisplayType],
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplaycontenttype)
    msTcDisplayContentType :: Maybe Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplaypngcharacteristics)
    msTcDisplayPNGCharacteristics :: Maybe (NonEmpty StatementIDL.DisplayPNGCharacteristicsDescriptor),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationrootcertificates)
    msAttestationRootCertificates :: NonEmpty X509.SignedCertificate,
    -- msEcdaaTrustAnchors, not needed for the subset we implement, FIDO 2 and FIDO U2F

    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-icon)
    msIcon :: Maybe PNGBytes,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-supportedextensions)
    msSupportedExtensions :: Maybe (NonEmpty StatementIDL.ExtensionDescriptor),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorgetinfo)
    msAuthenticatorGetInfo :: Maybe StatementIDL.AuthenticatorGetInfo
  }
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON MetadataStatement

-- | Type-safe wrapper for binary representation of the images.
newtype PNGBytes = PNGBytes {unPNGBytes :: BS.ByteString}
  deriving newtype (Eq)
  deriving (Show, ToJSON) via PrettyHexByteString

-- | Values of 'Registry.AuthenticatorAttestationType' but limited to the ones possible with Webauthn, see https://www.w3.org/TR/webauthn-2/#sctn-attestation-types
data WebauthnAttestationType
  = WebauthnAttestationBasic
  | WebauthnAttestationAttCA
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON WebauthnAttestationType
