module Crypto.Fido2.MDS.Model where

import Control.Lens (preview, _Just)
import Control.Monad.Except (ExceptT, MonadError (throwError), MonadIO (liftIO), runExceptT, withExceptT)
--import qualified Crypto.JOSE.Types as JWT
--import qualified Crypto.JWT as JWT

--import qualified Crypto.JOSE.JWS as JWS
--import qualified Crypto.JOSE.Types as JWS

--import Crypto.JWT (JWTError (JWSError), VerificationKeyStore, JWSHeader, CompactJWS, HasX5c (x5c), param, fromX509Certificate, Error (JWSInvalidSignature), decodeCompact, verifyJWS, defaultValidationSettings)
import Crypto.JOSE.JWK.Store (VerificationKeyStore (getVerificationKeys))
import Data.ASN1.Types (asn1CharacterToString)
import qualified Data.Aeson as Aeson
import Data.Aeson.Types
  ( FromJSON (parseJSON),
    Options (constructorTagModifier, fieldLabelModifier),
    Parser,
    Result (Error, Success),
    ToJSON (toJSON),
    Value,
    camelTo2,
    defaultOptions,
    genericParseJSON,
    parse,
  )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Char (toLower, toUpper)
import qualified Data.HashMap.Strict as HM
import Data.List (stripPrefix)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import Data.Map (Map)
import Data.Maybe (mapMaybe)
import Data.PEM as PEM (PEM (pemContent), pemParseLBS)
import Data.Scientific (Scientific, toBoundedInteger)
import Data.Text (Text)
import Data.Time (Day)
import Data.Word (Word16, Word32, Word64, Word8)
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509
import Debug.Trace (trace)
import GHC.Generics (Generic (Rep))
import Network.HTTP.Client (Request)

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary
data MetadataBlobPayload = MetadataBlobPayload
  { mdsNumber :: Int,
    mdsNextUpdate :: Day,
    mdsLegalHeader :: Text,
    mdsEntries :: [MDSEntry]
  }
  deriving (Show)

-- https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef
newtype AAID = AAID Text
  deriving (Show)
  deriving newtype (FromJSON)

-- https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#attributes-2
newtype AAGUID = AAGUID Text
  deriving (Show)
  deriving newtype (FromJSON)

-- Hex string, this value MUST be calculated according to method 1 for computing the keyIdentifier as defined in [RFC5280] section 4.2.1.2. https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
-- TODO: Implement a way to reproduce this value
newtype KeyIdentifier = KeyIdentifier Text
  deriving (Show)
  deriving newtype (FromJSON)

lowerFirst :: String -> String
lowerFirst [] = []
lowerFirst (x : xs) = toLower x : xs

modifyTypeField :: String -> String -> String
modifyTypeField prefix field = case stripPrefix prefix field of
  Nothing -> error $ "Field " <> field <> " doesn't have prefix " <> prefix
  Just stripped -> lowerFirst stripped

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary
data MDSEntry = MDSEntry
  { -- | The AAID of the authenticator, This field MUST be set if the authenticator implements FIDO UAF.
    entryAaid :: Maybe AAID,
    entryAaguid :: Maybe AAGUID,
    entryAttestationCertificateKeyIdentifiers :: Maybe [KeyIdentifier],
    entryMetadataStatement :: MetadataStatement,
    entryStatusReports :: [StatusReport],
    entryTimeOfLastStatusChange :: Day
    -- Fields not used in blob
    -- entryBiometricStatusReports
    -- entryRogueListURL
    -- entryRogueListHash
  }
  deriving (Show, Generic)

instance FromJSON MDSEntry where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "entry"
        }

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary
data StatusReport = StatusReport
  { status :: AuthenticatorStatus,
    effectiveDate :: Maybe Day,
    authenticatorVersion :: Maybe Word32,
    -- , certificate, Seemingly unused
    url :: Maybe Text,
    certificateDescriptor :: Maybe Text,
    certificateNumber :: Maybe Text,
    certificationPolicyVersion :: Maybe Text,
    certificationRequirementsVersion :: Maybe Text
  }
  deriving (Show, Generic, FromJSON)

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
  deriving (Show, Generic)

instance FromJSON AuthenticatorStatus where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toUpper . camelTo2 '_' . modifyTypeField "AuthenticatorStatus"
        }

data FIDOProtocol
  = UAF
  | U2F
  | FIDO2
  deriving (Show, Generic)

instance FromJSON FIDOProtocol where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toLower
        }

-- https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#version-interface
data Version = Version
  { minor :: Word16,
    major :: Word16
  }
  deriving (Show, Generic, FromJSON)

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-assertionScheme
data AssertionScheme
  = UAFV1TLV
  | U2FV1BIN
  | FIDOV2
  deriving (Show, Generic, FromJSON)

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
  deriving (Show, Generic)

instance FromJSON AuthenticationAlgorithms where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toLower
        }

data PublicKeyRepresentationFormats
  = ECC_X962_RAW
  | ECC_X962_DER
  | RSA_2048_RAW
  | RSA_2048_DER
  | COSE
  deriving (Show, Generic)

instance FromJSON PublicKeyRepresentationFormats where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toLower
        }

-- https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-reg-v1.2-rd-20171128.html#tags-used-in-the-protocol
data AttestationType
  = BASIC_FULL
  | BASIC_SURROGATE
  | ECDAA
  deriving (Show, Generic)

instance FromJSON AttestationType where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toLower
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
  deriving (Show, Generic)

instance FromJSON UserVerificationMethod where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = map toLower
        }

data CodeAccuracyDescriptor = CodeAccuracyDescriptor
  { codeAccuracyDescriptorBase :: Word16,
    codeAccuracyDescriptorMinLength :: Word16,
    codeAccuracyDescriptorMaxRetries :: Maybe Word16,
    codeAccuracyDescriptorBlockSlowdown :: Maybe Word16
  }
  deriving (Show, Generic)

instance FromJSON CodeAccuracyDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "codeAccuracyDescriptor"
        }

data BiometricAccuracyDescriptor = BiometricAccuracyDescriptor
  { biometricAccuracyDescriptorSelfAttestedFAR :: Maybe Word16,
    biometricAccuracyDescriptorSelfAttestedFRR :: Maybe Word16,
    biometricAccuracyDescriptorSelfAttestedEER :: Maybe Word16,
    biometricAccuracyDescriptorSelfAttestedFAAR :: Maybe Word16,
    biometricAccuracyDescriptorMaxTemplates :: Maybe Word16,
    biometricAccuracyDescriptorMaxRetries :: Maybe Word16,
    biometricAccuracyDescriptorBlockSlowdown :: Maybe Word16
  }
  deriving (Show, Generic)

instance FromJSON BiometricAccuracyDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "biometricAccuracyDescriptor"
        }

data PatternAccuracyDescriptor = PatternAccuracyDescriptor
  { -- Should be Word32, but the blob countains 34359738368, which is bigger than the maximum Word32
    patternAccuracyDescriptorMinComplexity :: Maybe Word64,
    patternAccuracyDescriptorMaxRetries :: Maybe Word16,
    patternAccuracyDescriptorBlockSlowdown :: Maybe Word16
  }
  deriving (Show, Generic)

instance FromJSON PatternAccuracyDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "patternAccuracyDescriptor"
        }

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#verificationmethoddescriptor-dictionary
data VerificationMethodDescriptor = VerificationMethodDescriptor
  { verificationMethodDescriptorUserVerificationMethod :: UserVerificationMethod,
    verificationMethodDescriptorCaDesc :: Maybe CodeAccuracyDescriptor,
    verificationMethodDescriptorBaDesc :: Maybe BiometricAccuracyDescriptor,
    verificationMethodDescriptorPaDesc :: Maybe PatternAccuracyDescriptor
  }
  deriving (Show, Generic)

instance FromJSON VerificationMethodDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "verificationMethodDescriptor"
        }

data KeyProtection
  = KeyProtectionSoftware
  | KeyProtectionHardware
  | KeyProtectionTee
  | KeyProtectionSecureElement
  | KeyProtectionRemoteHandle
  deriving (Show, Generic)

instance FromJSON KeyProtection where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "KeyProtection"
        }

data MatcherProtection
  = MatcherProtectionSoftware
  | MatcherProtectionTee
  | MatcherProtectionOnChip
  deriving (Show, Generic)

instance FromJSON MatcherProtection where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "MatcherProtection"
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
  deriving (Show, Generic)

instance FromJSON AttachmentHint where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "AttachmentHint"
        }

data TransactionConfirmationDisplay
  = TransactionConfirmationDisplayAny
  | TransactionConfirmationDisplayPrivilegedSoftware
  | TransactionConfirmationDisplayTee
  | TransactionConfirmationDisplayHardware
  | TransactionConfirmationDisplayRemote
  deriving (Show, Generic)

instance FromJSON TransactionConfirmationDisplay where
  parseJSON =
    genericParseJSON
      defaultOptions
        { constructorTagModifier = camelTo2 '_' . modifyTypeField "TransactionConfirmationDisplay"
        }

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#metadata-keys
data MetadataStatement = MetadataStatement
  { metadataStatementLegalHeader :: Text,
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
    metadataStatementSupportedExtensions :: Maybe [ExtensionDescriptor]
  }
  deriving (Show, Generic)

instance FromJSON MetadataStatement where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "metadataStatement"
        }

data ExtensionDescriptor = ExtensionDescriptor
  { extensionDescriptorId :: Text,
    --, extensionDescriptorTag ::
    extensionDescriptorData :: Maybe Text,
    extensionDescriptorFail_if_unknown :: Bool
  }
  deriving (Show, Generic)

instance FromJSON ExtensionDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "extensionDescriptor"
        }

data RgbPaletteEntry = RgbPaletteEntry
  { rgbPaletteEntryR :: Word16,
    rgbPaletteEntryG :: Word16,
    rgbPaletteEntryB :: Word16
  }
  deriving (Show, Generic)

instance FromJSON RgbPaletteEntry where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "rgbPaletteEntry"
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
  deriving (Show, Generic)

instance FromJSON DisplayPNGCharacteristicsDescriptor where
  parseJSON =
    genericParseJSON
      defaultOptions
        { fieldLabelModifier = modifyTypeField "displayPNGCharacteristicsDescriptor"
        }
