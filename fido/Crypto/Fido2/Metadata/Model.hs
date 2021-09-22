{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Fido2.Metadata.Model
  ( Entry (..),
    AAID (..),
    AAGUID (..),
    KeyIdentifier (..),
    StatusReport (..),
    AuthenticatorStatus (..),
    FIDOProtocol (..),
    Version (..),
    AssertionScheme (..),
    AuthenticationAlgorithms (..),
    PublicKeyRepresentationFormats (..),
    AttestationType (..),
    UserVerificationMethod (..),
    CodeAccuracyDescriptor (..),
    BiometricAccuracyDescriptor (..),
    PatternAccuracyDescriptor (..),
    VerificationMethodDescriptor (..),
    KeyProtection (..),
    MatcherProtection (..),
    AttachmentHint (..),
    TransactionConfirmationDisplay (..),
    MetadataStatement (..),
    ExtensionDescriptor (..),
    RgbPaletteEntry (..),
    DisplayPNGCharacteristicsDescriptor (..),
  )
where

import Crypto.Fido2.EncodingUtils (modifyTypeField)
import Data.Aeson.Types
  ( FromJSON (parseJSON),
    Object,
    Options (constructorTagModifier, fieldLabelModifier, omitNothingFields),
    ToJSON (toJSON),
    camelTo2,
    defaultOptions,
    genericParseJSON,
    genericToJSON,
    withObject,
    (.:),
  )
import Data.Char (toLower, toUpper)
import Data.List.NonEmpty (NonEmpty)
import Data.Map (Map)
import Data.Text (Text)
import Data.Time (Day)
import Data.Word (Word16, Word32, Word64, Word8)
import GHC.Generics (Generic)

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary
data Entry = Entry
  { -- | The AAID of the authenticator, This field MUST be set if the authenticator implements FIDO UAF.
    entryTimeOfLastStatusChange :: Day,
    entryStatusReports :: [StatusReport],
    entryAaid :: Maybe AAID,
    entryAaguid :: Maybe AAGUID,
    entryAttestationCertificateKeyIdentifiers :: Maybe [KeyIdentifier],
    entryMetadataStatement :: MetadataStatement
    -- Fields not used in blob
    -- entryBiometricStatusReports
    -- entryRogueListURL
    -- entryRogueListHash
  }
  deriving (Show, Eq, Generic)

instance FromJSON Entry where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "entry",
          omitNothingFields = True
        }

instance ToJSON Entry where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "entry",
          omitNothingFields = True
        }

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary
data StatusReport = StatusReport
  { statusReportStatus :: AuthenticatorStatus,
    statusReportEffectiveDate :: Maybe Day,
    statusReportAuthenticatorVersion :: Maybe Word32,
    -- , certificate, Seemingly unused
    statusReportUrl :: Maybe Text,
    statusReportCertificationDescriptor :: Maybe Text,
    statusReportCertificateNumber :: Maybe Text,
    statusReportCertificationPolicyVersion :: Maybe Text,
    statusReportCertificationRequirementsVersion :: Maybe Text
  }
  deriving (Show, Eq, Generic)

instance FromJSON StatusReport where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "statusReport",
          omitNothingFields = True
        }

instance ToJSON StatusReport where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "statusReport",
          omitNothingFields = True
        }

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum
data AuthenticatorStatus
  = AuthenticatorStatusNotFidoCertified
  | AuthenticatorStatusFidoCertified
  | AuthenticatorStatusUserVerificationBypass
  | AuthenticatorStatusAttestationKeyCompromise
  | AuthenticatorStatusUserKeyRemoteCompromise
  | AuthenticatorStatusUserKeyPhysicalCompromise
  | AuthenticatorStatusUpdateAvailable
  | AuthenticatorStatusRevoked
  | AuthenticatorStatusSelfAssertionSubmitted
  | AuthenticatorStatusFidoCertifiedL1
  | AuthenticatorStatusFidoCertifiedL1plus
  | AuthenticatorStatusFidoCertifiedL2
  | AuthenticatorStatusFidoCertifiedL2plus
  | AuthenticatorStatusFidoCertifiedL3
  | AuthenticatorStatusFidoCertifiedL3plus
  deriving (Show, Eq, Generic)

instance FromJSON AuthenticatorStatus where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toUpper . camelTo2 '_' . modifyTypeField "AuthenticatorStatus",
          omitNothingFields = True
        }

instance ToJSON AuthenticatorStatus where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = map toUpper . camelTo2 '_' . modifyTypeField "AuthenticatorStatus",
          omitNothingFields = True
        }

-- https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef
newtype AAID = AAID Text
  deriving (Show, Eq)
  deriving newtype (FromJSON, ToJSON)

-- https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#attributes-2
newtype AAGUID = AAGUID Text
  deriving (Show, Eq)
  deriving newtype (FromJSON, ToJSON)

-- Hex string, this value MUST be calculated according to method 1 for computing the keyIdentifier as defined in [RFC5280] section 4.2.1.2. https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
-- TODO: Implement a way to reproduce this value
newtype KeyIdentifier = KeyIdentifier Text
  deriving (Show, Eq)
  deriving newtype (FromJSON, ToJSON)

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#metadata-keys
data MetadataStatement = MetadataStatement
  { metadataStatementSchema :: Word16,
    metadataStatementLegalHeader :: Text,
    metadataStatementAaid :: Maybe AAID,
    metadataStatementAaguid :: Maybe AAGUID,
    metadataStatementAttestationCertificateKeyIdentifiers :: Maybe [KeyIdentifier],
    metadataStatementDescription :: Text,
    metadataStatementAlternativeDescriptions :: Maybe (Map Text Text),
    -- Should be Word16 according to the spec, but there's values higher than 65535 in the blob
    metadataStatementAuthenticatorVersion :: Word32,
    metadataStatementProtocolFamily :: FIDOProtocol,
    metadataStatementUpv :: [Version],
    -- NOTE: This should be required, but the field is never set in the blob
    metadataStatementAssertionScheme :: Maybe AssertionScheme,
    -- NOTE: This should be required, but the field is never set in the blob
    metadataStatementAuthenticationAlgorithm :: Maybe AuthenticationAlgorithms,
    metadataStatementAuthenticationAlgorithms :: [AuthenticationAlgorithms],
    -- NOTE: This should be required, but the field is never set in the blob
    metadataStatementPublicKeyAlgAndEncoding :: Maybe PublicKeyRepresentationFormats,
    metadataStatementPublicKeyAlgAndEncodings :: [PublicKeyRepresentationFormats],
    metadataStatementAttestationTypes :: [AttestationType],
    metadataStatementUserVerificationDetails :: [NonEmpty VerificationMethodDescriptor],
    metadataStatementKeyProtection :: NonEmpty KeyProtection,
    metadataStatementIsKeyRestricted :: Maybe Bool,
    metadataStatementIsFreshUserVerificationRequired :: Maybe Bool,
    metadataStatementMatcherProtection :: NonEmpty MatcherProtection,
    metadataStatementCryptoStrength :: Maybe Word16,
    -- metadataStatementOperatingEnv :: Maybe Text,
    metadataStatementAttachmentHint :: NonEmpty AttachmentHint,
    -- metadataStatementIsSecondFactorOnly :: Bool,
    metadataStatementTcDisplay :: [TransactionConfirmationDisplay],
    metadataStatementTcDisplayContentType :: Maybe Text,
    metadataStatementTcDisplayPNGCharacteristics :: Maybe [DisplayPNGCharacteristicsDescriptor],
    metadataStatementAttestationRootCertificates :: [Text],
    --metadataStatementEcdaaTrustAnchors :: Maybe [EcdaaTrustAnchor],
    metadataStatementIcon :: Text,
    metadataStatementSupportedExtensions :: Maybe [ExtensionDescriptor],
    metadataStatementAuthenticatorGetInfo :: Maybe Object
  }
  deriving (Show, Eq, Generic)

instance FromJSON MetadataStatement where
  parseJSON v = do
    schema :: Word16 <- withObject "MetadataStatement" (.: "schema") v
    if schema /= 3
      then fail $ "MetadataStatement schema version is " <> show schema <> " but we can only parse version 3"
      else
        genericParseJSON
          defaultOptions
            { fieldLabelModifier = modifyTypeField "metadataStatement",
              omitNothingFields = True
            }
          v

instance ToJSON MetadataStatement where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "metadataStatement",
          omitNothingFields = True
        }

data FIDOProtocol
  = UAF
  | U2F
  | FIDO2
  deriving (Show, Eq, Generic)

instance FromJSON FIDOProtocol where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toLower,
          omitNothingFields = True
        }

instance ToJSON FIDOProtocol where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = map toLower,
          omitNothingFields = True
        }

-- https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#version-interface
data Version = Version
  { minor :: Word16,
    major :: Word16
  }
  deriving (Show, Eq, Generic, FromJSON, ToJSON)

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-assertionScheme
data AssertionScheme
  = UAFV1TLV
  | U2FV1BIN
  | FIDOV2
  deriving (Show, Eq, Generic, FromJSON, ToJSON)

-- https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authentication-algorithms
data AuthenticationAlgorithms
  = SECP256R1_ECDSA_SHA256_RAW
  | SECP256R1_ECDSA_SHA256_DER
  | RSASSA_PSS_SHA256_RAW
  | RSASSA_PSS_SHA256_DER
  | SECP256K1_ECDSA_SHA256_RAW
  | SECP256K1_ECDSA_SHA256_DER
  | SM2_SM3_RAW
  | RSA_EMSA_PKCS1_SHA256_RAW
  | RSA_EMSA_PKCS1_SHA256_DER
  | RSASSA_PSS_SHA384_RAW
  | RSASSA_PSS_SHA512_RAW
  | RSASSA_PKCSV15_SHA256_RAW
  | RSASSA_PKCSV15_SHA384_RAW
  | RSASSA_PKCSV15_SHA512_RAW
  | RSASSA_PKCSV15_SHA1_RAW
  | SECP384R1_ECDSA_SHA384_RAW
  | SECP512R1_ECDSA_SHA512_RAW
  | ED25519_EDDSA_SHA512_RAW
  deriving (Show, Eq, Generic)

instance FromJSON AuthenticationAlgorithms where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toLower,
          omitNothingFields = True
        }

instance ToJSON AuthenticationAlgorithms where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = map toLower,
          omitNothingFields = True
        }

data PublicKeyRepresentationFormats
  = ECC_X962_RAW
  | ECC_X962_DER
  | RSA_2048_RAW
  | RSA_2048_DER
  | COSE
  deriving (Show, Eq, Generic)

instance FromJSON PublicKeyRepresentationFormats where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toLower,
          omitNothingFields = True
        }

instance ToJSON PublicKeyRepresentationFormats where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = map toLower,
          omitNothingFields = True
        }

-- https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attestation-types
data AttestationType
  = AttestationTypeBasicFull
  | AttestationTypeBasicSurrogate
  | AttestationTypeEcdaa
  | AttestationTypeAttca
  | AttestationTypeAnonca
  deriving (Show, Eq, Generic)

instance FromJSON AttestationType where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "AttestationType",
          omitNothingFields = True
        }

instance ToJSON AttestationType where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "AttestationType",
          omitNothingFields = True
        }

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#verificationmethoddescriptor-dictionary
data VerificationMethodDescriptor = VerificationMethodDescriptor
  { verificationMethodDescriptorUserVerificationMethod :: UserVerificationMethod,
    verificationMethodDescriptorCaDesc :: Maybe CodeAccuracyDescriptor,
    verificationMethodDescriptorBaDesc :: Maybe BiometricAccuracyDescriptor,
    verificationMethodDescriptorPaDesc :: Maybe PatternAccuracyDescriptor
  }
  deriving (Show, Eq, Generic)

instance FromJSON VerificationMethodDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "verificationMethodDescriptor",
          omitNothingFields = True
        }

instance ToJSON VerificationMethodDescriptor where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "verificationMethodDescriptor",
          omitNothingFields = True
        }

data UserVerificationMethod
  = PRESENCE_INTERNAL
  | FINGERPRINT_INTERNAL
  | PASSCODE_INTERNAL
  | PASSCODE_EXTERNAL
  | VOICEPRINT_INTERNAL
  | FACEPRINT_INTERNAL
  | LOCATION_INTERNAL
  | EYEPRINT_INTERNAL
  | PATTERN_INTERNAL
  | HANDPRINT_INTERNAL
  | NONE
  | ALL
  deriving (Show, Eq, Generic)

instance FromJSON UserVerificationMethod where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toLower,
          omitNothingFields = True
        }

instance ToJSON UserVerificationMethod where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = map toLower,
          omitNothingFields = True
        }

data CodeAccuracyDescriptor = CodeAccuracyDescriptor
  { codeAccuracyDescriptorBase :: Word16,
    codeAccuracyDescriptorMinLength :: Word16,
    codeAccuracyDescriptorMaxRetries :: Maybe Word16,
    codeAccuracyDescriptorBlockSlowdown :: Maybe Word16
  }
  deriving (Show, Eq, Generic)

instance FromJSON CodeAccuracyDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "codeAccuracyDescriptor",
          omitNothingFields = True
        }

instance ToJSON CodeAccuracyDescriptor where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "codeAccuracyDescriptor",
          omitNothingFields = True
        }

data BiometricAccuracyDescriptor = BiometricAccuracyDescriptor
  { biometricAccuracyDescriptorSelfAttestedFAR :: Maybe Double,
    biometricAccuracyDescriptorSelfAttestedFRR :: Maybe Double,
    biometricAccuracyDescriptorSelfAttestedEER :: Maybe Double,
    biometricAccuracyDescriptorSelfAttestedFAAR :: Maybe Double,
    biometricAccuracyDescriptorMaxTemplates :: Maybe Word16,
    biometricAccuracyDescriptorMaxRetries :: Maybe Word16,
    biometricAccuracyDescriptorBlockSlowdown :: Maybe Word16
  }
  deriving (Show, Eq, Generic)

instance FromJSON BiometricAccuracyDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "biometricAccuracyDescriptor",
          omitNothingFields = True
        }

instance ToJSON BiometricAccuracyDescriptor where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "biometricAccuracyDescriptor",
          omitNothingFields = True
        }

data PatternAccuracyDescriptor = PatternAccuracyDescriptor
  { -- Should be Word32, but the blob countains 34359738368, which is bigger than the maximum Word32
    patternAccuracyDescriptorMinComplexity :: Maybe Word64,
    patternAccuracyDescriptorMaxRetries :: Maybe Word16,
    patternAccuracyDescriptorBlockSlowdown :: Maybe Word16
  }
  deriving (Show, Eq, Generic)

instance FromJSON PatternAccuracyDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "patternAccuracyDescriptor",
          omitNothingFields = True
        }

instance ToJSON PatternAccuracyDescriptor where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "patternAccuracyDescriptor",
          omitNothingFields = True
        }

data KeyProtection
  = KeyProtectionSoftware
  | KeyProtectionHardware
  | KeyProtectionTee
  | KeyProtectionSecureElement
  | KeyProtectionRemoteHandle
  deriving (Show, Eq, Generic)

instance FromJSON KeyProtection where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "KeyProtection",
          omitNothingFields = True
        }

instance ToJSON KeyProtection where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "KeyProtection",
          omitNothingFields = True
        }

data MatcherProtection
  = MatcherProtectionSoftware
  | MatcherProtectionTee
  | MatcherProtectionOnChip
  deriving (Show, Eq, Generic)

instance FromJSON MatcherProtection where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "MatcherProtection",
          omitNothingFields = True
        }

instance ToJSON MatcherProtection where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "MatcherProtection",
          omitNothingFields = True
        }

data AttachmentHint
  = AttachmentHintInternal
  | AttachmentHintExternal
  | AttachmentHintWired
  | AttachmentHintWireless
  | AttachmentHintNfc
  | AttachmentHintBluetooth
  | AttachmentHintNetwork
  | AttachmentHintReady
  | AttachmentHintWifiDirect
  deriving (Show, Eq, Generic)

instance FromJSON AttachmentHint where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "AttachmentHint",
          omitNothingFields = True
        }

instance ToJSON AttachmentHint where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "AttachmentHint",
          omitNothingFields = True
        }

data TransactionConfirmationDisplay
  = TransactionConfirmationDisplayAny
  | TransactionConfirmationDisplayPrivilegedSoftware
  | TransactionConfirmationDisplayTee
  | TransactionConfirmationDisplayHardware
  | TransactionConfirmationDisplayRemote
  deriving (Show, Eq, Generic)

instance FromJSON TransactionConfirmationDisplay where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "TransactionConfirmationDisplay",
          omitNothingFields = True
        }

instance ToJSON TransactionConfirmationDisplay where
  toJSON =
    genericToJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "TransactionConfirmationDisplay",
          omitNothingFields = True
        }

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#idl-def-DisplayPNGCharacteristicsDescriptor
data DisplayPNGCharacteristicsDescriptor = DisplayPNGCharacteristicsDescriptor
  { displayPNGCharacteristicsDescriptorWidth :: Word32,
    displayPNGCharacteristicsDescriptorHeight :: Word32,
    displayPNGCharacteristicsDescriptorBitDepth :: Word8,
    displayPNGCharacteristicsDescriptorColorType :: Word8,
    displayPNGCharacteristicsDescriptorCompression :: Word8,
    displayPNGCharacteristicsDescriptorFilter :: Word8,
    displayPNGCharacteristicsDescriptorInterlace :: Word8,
    displayPNGCharacteristicsDescriptorPlte :: Maybe (NonEmpty RgbPaletteEntry)
  }
  deriving (Show, Eq, Generic)

instance FromJSON DisplayPNGCharacteristicsDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "displayPNGCharacteristicsDescriptor",
          omitNothingFields = True
        }

instance ToJSON DisplayPNGCharacteristicsDescriptor where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "displayPNGCharacteristicsDescriptor",
          omitNothingFields = True
        }

data RgbPaletteEntry = RgbPaletteEntry
  { rgbPaletteEntryR :: Word16,
    rgbPaletteEntryG :: Word16,
    rgbPaletteEntryB :: Word16
  }
  deriving (Show, Eq, Generic)

instance FromJSON RgbPaletteEntry where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "rgbPaletteEntry",
          omitNothingFields = True
        }

instance ToJSON RgbPaletteEntry where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "rgbPaletteEntry",
          omitNothingFields = True
        }

data ExtensionDescriptor = ExtensionDescriptor
  { extensionDescriptorId :: Text,
    --, extensionDescriptorTag ::
    extensionDescriptorData :: Maybe Text,
    extensionDescriptorFail_if_unknown :: Bool
  }
  deriving (Show, Eq, Generic)

instance FromJSON ExtensionDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "extensionDescriptor",
          omitNothingFields = True
        }

instance ToJSON ExtensionDescriptor where
  toJSON =
    genericToJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "extensionDescriptor",
          omitNothingFields = True
        }
