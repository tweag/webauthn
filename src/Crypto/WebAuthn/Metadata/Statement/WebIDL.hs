{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DuplicateRecordFields #-}

-- | Stability: experimental
-- Type definitions directly corresponding to the
-- [FIDO Metadata Service](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html)
-- specification.
module Crypto.WebAuthn.Metadata.Statement.WebIDL
  ( -- * Types
    AAGUID (..),
    CodeAccuracyDescriptor (..),
    BiometricAccuracyDescriptor (..),
    PatternAccuracyDescriptor (..),
    VerificationMethodDescriptor (..),
    VerificationMethodANDCombinations (..),
    RgbPaletteEntry (..),
    DisplayPNGCharacteristicsDescriptor (..),
    EcdaaTrustAnchor (..),
    ExtensionDescriptor (..),
    AlternativeDescriptions (..),
    AuthenticatorGetInfo (..),
    ProtocolFamily (..),

    -- * Metadata Statement
    MetadataStatement (..),
  )
where

import Crypto.WebAuthn.Internal.Utils (CustomJSON (CustomJSON), EnumJSONEncoding, JSONEncoding)
import qualified Crypto.WebAuthn.Metadata.FidoRegistry as Registry
import qualified Crypto.WebAuthn.Metadata.UAF as UAF
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.List.NonEmpty (NonEmpty)
import Data.Map (Map)
import Data.Text (Text)
import GHC.Generics (Generic)

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#authenticator-attestation-guid-aaguid-typedef)
newtype AAGUID = AAGUID IDL.DOMString
  deriving (Show, Eq)
  deriving newtype (Aeson.FromJSON, Aeson.ToJSON)

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#codeaccuracydescriptor-dictionary)
data CodeAccuracyDescriptor = CodeAccuracyDescriptor
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-codeaccuracydescriptor-base)
    base :: IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-codeaccuracydescriptor-minlength)
    minLength :: IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-codeaccuracydescriptor-maxretries)
    maxRetries :: Maybe IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-codeaccuracydescriptor-blockslowdown)
    blockSlowdown :: Maybe IDL.UnsignedShort
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding CodeAccuracyDescriptor

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biometricaccuracydescriptor-dictionary)
data BiometricAccuracyDescriptor = BiometricAccuracyDescriptor
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-selfattestedfrr)
    selfAttestedFRR :: Maybe IDL.Double,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-selfattestedfar)
    selfAttestedFAR :: Maybe IDL.Double,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-maxtemplates)
    maxTemplates :: Maybe IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-maxretries)
    maxRetries :: Maybe IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-biometricaccuracydescriptor-blockslowdown)
    blockSlowdown :: Maybe IDL.UnsignedShort
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding BiometricAccuracyDescriptor

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary)
data PatternAccuracyDescriptor = PatternAccuracyDescriptor
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-patternaccuracydescriptor-mincomplexity)
    -- FIXME: The spec declares this as an unsigned long, but the blob they
    -- provide has a value in it (34359738368) that doesn't fit into an
    -- unsigned long. See <https://github.com/tweag/webauthn/issues/68>.
    minComplexity :: IDL.UnsignedLongLong,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-patternaccuracydescriptor-maxretries)
    maxRetries :: Maybe IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-patternaccuracydescriptor-blockslowdown)
    blockSlowdown :: Maybe IDL.UnsignedShort
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PatternAccuracyDescriptor

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary)
data VerificationMethodDescriptor = VerificationMethodDescriptor
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-verificationmethoddescriptor-userverificationmethod)
    userVerificationMethod :: Registry.UserVerificationMethod,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-verificationmethoddescriptor-cadesc)
    caDesc :: Maybe CodeAccuracyDescriptor,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-verificationmethoddescriptor-badesc)
    baDesc :: Maybe BiometricAccuracyDescriptor,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-verificationmethoddescriptor-padesc)
    paDesc :: Maybe PatternAccuracyDescriptor
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding VerificationMethodDescriptor

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethodandcombinations-typedef)
newtype VerificationMethodANDCombinations = VerificationMethodANDCombinations (NonEmpty VerificationMethodDescriptor)
  deriving (Show, Eq)
  deriving newtype (Aeson.FromJSON, Aeson.ToJSON)

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#rgbpaletteentry-dictionary)
data RgbPaletteEntry = RgbPaletteEntry
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-rgbpaletteentry-r)
    r :: IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-rgbpaletteentry-g)
    g :: IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-rgbpaletteentry-b)
    b :: IDL.UnsignedShort
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding RgbPaletteEntry

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary)
data DisplayPNGCharacteristicsDescriptor = DisplayPNGCharacteristicsDescriptor
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-width)
    width :: IDL.UnsignedLong,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-height)
    height :: IDL.UnsignedLong,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-bitdepth)
    bitDepth :: IDL.Octet,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-colortype)
    colorType :: IDL.Octet,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-compression)
    compression :: IDL.Octet,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-filter)
    filter :: IDL.Octet,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-interlace)
    interlace :: IDL.Octet,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-displaypngcharacteristicsdescriptor-plte)
    plte :: Maybe (NonEmpty RgbPaletteEntry)
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding DisplayPNGCharacteristicsDescriptor

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#ecdaatrustanchor-dictionary)
data EcdaaTrustAnchor = EcdaaTrustAnchor
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-x)
    litX :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-y)
    litY :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-c)
    c :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-sx)
    sx :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-sy)
    sy :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-ecdaatrustanchor-g1curve)
    litG1Curve :: IDL.DOMString
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding EcdaaTrustAnchor

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#extensiondescriptor-dictionary)
data ExtensionDescriptor = ExtensionDescriptor
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-extensiondescriptor-id)
    id :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-extensiondescriptor-tag)
    tag :: Maybe IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-extensiondescriptor-data)
    litdata :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-extensiondescriptor-fail_if_unknown)
    fail_if_unknown :: IDL.Boolean
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding ExtensionDescriptor

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#alternativedescriptions-dictionary)
-- TODO: Replace Text with
-- <https://hackage.haskell.org/package/aeson-2.0.2.0/docs/Data-Aeson-Key.html#t:Key>
-- when updating aeson. Updating aeson is currently blocked by
-- <https://github.com/fumieval/deriving-aeson/issues/16>.
newtype AlternativeDescriptions = AlternativeDescriptions (Map Text IDL.DOMString)
  deriving (Show, Eq)
  deriving newtype (Aeson.FromJSON, Aeson.ToJSON)

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#authenticatorgetinfo-dictionary)
newtype AuthenticatorGetInfo
  = -- TODO: Replace Text with
    -- <https://hackage.haskell.org/package/aeson-2.0.2.0/docs/Data-Aeson-Key.html#t:Key>
    -- when updating aeson. Updating aeson is currently blocked by
    -- <https://github.com/fumieval/deriving-aeson/issues/16>.
    -- FIXME: The spec wrongfully declares the values to be DOMString's when
    -- they really aren't in the provided blob. See:
    -- <https://github.com/tweag/webauthn/issues/68>
    AuthenticatorGetInfo (Map Text Aeson.Value)
  deriving (Show, Eq)
  deriving newtype (Aeson.FromJSON, Aeson.ToJSON)

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys)
data MetadataStatement = MetadataStatement
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-legalheader)
    legalHeader :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-aaid)
    aaid :: Maybe UAF.AAID,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-aaguid)
    aaguid :: Maybe AAGUID,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationcertificatekeyidentifiers)
    attestationCertificateKeyIdentifiers :: Maybe (NonEmpty UAF.KeyIdentifier),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-description)
    description :: IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-alternativedescriptions)
    alternativeDescriptions :: Maybe AlternativeDescriptions,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorversion)
    authenticatorVersion :: IDL.UnsignedLong,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-protocolfamily)
    protocolFamily :: ProtocolFamily,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-schema)
    schema :: IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-upv)
    upv :: NonEmpty UAF.Version,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticationalgorithms)
    authenticationAlgorithms :: NonEmpty Registry.AuthenticationAlgorithm,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-publickeyalgandencodings)
    publicKeyAlgAndEncodings :: NonEmpty Registry.PublicKeyRepresentationFormat,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationtypes)
    attestationTypes :: NonEmpty Registry.AuthenticatorAttestationType,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-userverificationdetails)
    userVerificationDetails :: NonEmpty VerificationMethodANDCombinations,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-keyprotection)
    keyProtection :: NonEmpty Registry.KeyProtectionType,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-iskeyrestricted)
    isKeyRestricted :: Maybe IDL.Boolean,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-isfreshuserverificationrequired)
    isFreshUserVerificationRequired :: Maybe IDL.Boolean,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-matcherprotection)
    matcherProtection :: NonEmpty Registry.MatcherProtectionType,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-cryptostrength)
    cryptoStrength :: Maybe IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attachmenthint)
    attachmentHint :: NonEmpty Registry.AuthenticatorAttachmentHint,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplay)
    tcDisplay :: [Registry.TransactionConfirmationDisplayType],
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplaycontenttype)
    tcDisplayContentType :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplaypngcharacteristics)
    tcDisplayPNGCharacteristics :: Maybe (NonEmpty DisplayPNGCharacteristicsDescriptor),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationrootcertificates)
    attestationRootCertificates :: [IDL.DOMString],
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-ecdaatrustanchors)
    ecdaaTrustAnchors :: Maybe (NonEmpty EcdaaTrustAnchor),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-icon)
    icon :: Maybe IDL.DOMString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-supportedextensions)
    supportedExtensions :: Maybe (NonEmpty ExtensionDescriptor),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorgetinfo)
    authenticatorGetInfo :: Maybe AuthenticatorGetInfo
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding MetadataStatement

-- | Possible FIDO protocol families for 'protocolFamily'
data ProtocolFamily
  = ProtocolFamilyUAF
  | ProtocolFamilyU2F
  | ProtocolFamilyFIDO2
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via EnumJSONEncoding "ProtocolFamily" ProtocolFamily
