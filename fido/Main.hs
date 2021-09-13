{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}

module Main where

import Control.Lens
import Control.Monad.Except (ExceptT, MonadError (throwError), MonadIO (liftIO), runExceptT, withExceptT)
import qualified Crypto.JOSE.Compact as Compact
import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.JWS as JWS
import qualified Crypto.JOSE.Types as JWT
import qualified Crypto.JWT as JWT
import Data.ASN1.Types (asn1CharacterToString)
import qualified Data.Aeson as Aeson
import Data.Aeson.Types
import Data.Bifunctor (first)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Char (toLower, toUpper)
import Data.Functor.Identity (Identity)
import qualified Data.HashMap.Strict as HM
import Data.List
import Data.List.NonEmpty (NonEmpty ((:|)))
import qualified Data.List.NonEmpty as NE
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe
import Data.PEM as PEM
import Data.Scientific
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding
import qualified Data.Text.Encoding as Text
import Data.Time
import Data.Time.Format.ISO8601
import Data.Word (Word16, Word32, Word64, Word8)
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509
import Debug.Trace
import GHC.Generics
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Network.HTTP.Types.Status (statusCode)

--import qualified Web.JWT as JWT

data MDSSource = Prefetched Text | Fetched Request

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary
data MetadataBlobPayload = MetadataBlobPayload
  { mdsNumber :: Int,
    mdsNextUpdate :: Day,
    mdsLegalHeader :: Text,
    mdsEntries :: [MDSEntry]
  }
  deriving (Show)

data MDSError
  = MDSErrorJWT JWT.JWTError
  | MDSErrorClaimDecoding Text Value String
  | MDSErrorClaimMissing Text
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

-- Stolen from https://hackage.haskell.org/package/either
maybeToRight :: a -> Maybe b -> Either a b
maybeToRight _ (Just x) = Right x
maybeToRight y Nothing = Left y

getClaim :: Text -> HM.HashMap Text Value -> (Value -> Parser a) -> Either MDSError a
getClaim field claims parser = case HM.lookup field claims of
  Nothing -> Left $ MDSErrorClaimMissing field
  Just value -> case parse parser value of
    Error err -> Left $ MDSErrorClaimDecoding field value err
    Success result -> Right result

parseBoundedIntegralFromScientific :: (Bounded a, Integral a) => Scientific -> Parser a
parseBoundedIntegralFromScientific s =
  maybe
    (fail $ "value is either floating or will cause over or underflow " ++ show s)
    pure
    (toBoundedInteger s)

newtype PublicKeyIdentifier = PublicKeyIdentifier BS.ByteString

-- TODO: Make this contain the root certificate
newtype Chain = Chain X509.SignedCertificate

getNames :: X509.Certificate -> (Maybe String, [String])
getNames cert = (commonName >>= asn1CharacterToString, altNames)
  where
    commonName = X509.getDnElement X509.DnCommonName $ X509.certSubjectDN cert
    altNames = maybe [] toAltName $ X509.extensionGet $ X509.certExtensions cert
    toAltName (X509.ExtSubjectAltName names) = catMaybes $ map unAltName names
      where
        unAltName (X509.AltNameDNS s) = Just s
        unAltName _ = Nothing

instance JWT.VerificationKeyStore (ExceptT JWT.JWTError IO) (JWT.JWSHeader ()) LBS.ByteString Chain where
  getVerificationKeys header bytes (Chain rootCert) = do
    -- TODO Handle pattern mismatch, and the spec says to also check x5u
    let Just (NE.toList -> x) = preview (JWT.x5c . _Just . JWT.param) header

    let hooks =
          X509.defaultHooks
            { X509.hookValidateName = \host cert -> trace ("Host is " ++ host ++ ", names are " ++ show (getNames cert)) $ X509.hookValidateName X509.defaultHooks host cert
            }
        store = X509.makeCertificateStore [rootCert]
        cache = X509.exceptionValidationCache []
    -- TODO: Does the SHA256 choice matter here?
    result <- liftIO $ X509.validate X509.HashSHA256 hooks X509.defaultChecks store cache ("mds.fidoalliance.org", "") (X509.CertificateChain x)
    case result of
      [] -> do
        --let pem = PEM.PEM "CERTIFICATE" [] (X509.encodeSignedObject $ head x)
        -- TODO: Verify chain
        res <- JWT.fromX509Certificate (head x)
        return [res]
      --trace ("Got result: " ++ show result) $ trace (Text.unpack $ Text.decodeUtf8 $ LBS.toStrict $ PEM.pemWriteLBS pem) $
      errors ->
        trace (show errors) $ throwError $ JWT.JWSError JWT.JWSInvalidSignature

decodeJWTPayload :: LBS.ByteString -> JWT.SignedCertificate -> ExceptT JWT.JWTError IO LBS.ByteString
decodeJWTPayload bytes rootCert = do
  jws :: JWT.CompactJWS JWT.JWSHeader <- JWT.decodeCompact bytes
  JWS.verifyJWS' (Chain rootCert) jws

--let x = jws ^. JWT.jwsHeader ^. JWT.x5c
--key <- JWT.fromX509Certificate cert

-- TODO: Use Either
decodeMDS :: LBS.ByteString -> X509.SignedCertificate -> ExceptT MDSError IO LBS.ByteString
decodeMDS body cert = do
  --first MDSErrorJWT <$>
  withExceptT MDSErrorJWT $ decodeJWTPayload body cert

--undefined <- JWT.decodeCompact body

--jwt <- maybeToRight MDSErrorJWTDecodingFailed $ JWT.decodeAndVerifySignature undefined body
--let claims = JWT.unregisteredClaims $ JWT.claims jwt
--let claims = undefined
--number <- getClaim "no" claims (withScientific "no" parseBoundedIntegralFromScientific)
--nextUpdate <- getClaim "nextUpdate" claims (withText "nextUpdate" $ iso8601ParseM . Text.unpack)
--legalHeader <- getClaim "legalHeader" claims (withText "legalHeader" pure)
--entries <- getClaim "entries" claims parseJSON
--return
--  MetadataBlobPayload
--    { mdsNumber = number,
--      mdsNextUpdate = nextUpdate,
--      mdsLegalHeader = legalHeader,
--      mdsEntries = entries
--    }

--
-- TODO: Follow this:
-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules
--prefetchedTest :: IO (Either MDSError MetadataBlobPayload)
-- FIXME: The jwt library isn't very compliant and doesn't implement everything we need.
-- Use the jose library instead, and specifically Crypto.JOSE.JWK.fromX509Certificate to generate the JWK needed to verify the signature
main = do
  putStrLn "Reading contents"
  contents <- LBS.readFile "mds.jwt"
  putStrLn "Reading cert"
  certBytes <- LBS.readFile "root-cert.crt"
  let Right [PEM.pemContent -> pem] = PEM.pemParseLBS certBytes
  let Right cert = X509.decodeSignedCertificate pem
  putStrLn $ "Cert decoding successful"
  res <- runExceptT $ decodeMDS contents cert
  case res of
    Left err -> putStrLn $ show err
    Right payload -> do
      putStrLn "Successfully got payload, writing to output.json"
      LBS.writeFile "output.json" payload

newtype EncodingRules a = EncodingRules a

options :: Aeson.Options
options =
  Aeson.defaultOptions
    { Aeson.fieldLabelModifier = \x ->
        if x == "typ"
          then "type"
          else x,
      Aeson.omitNothingFields = True
    }

instance (Aeson.GToJSON Aeson.Zero (Rep a), Generic a) => ToJSON (EncodingRules a) where
  toJSON (EncodingRules a) = Aeson.genericToJSON options a

instance (Aeson.GFromJSON Aeson.Zero (Rep a), Generic a) => FromJSON (EncodingRules a) where
  parseJSON o = EncodingRules <$> Aeson.genericParseJSON options o

--fetchingTest :: IO ()
--fetchingTest = do
--  manager <- newManager tlsManagerSettings
--
--  request <- parseRequest "https://mds.fidoalliance.org/"
--  putStrLn "Making request"
--  response <- httpLbs request manager
--  putStrLn "Done"
--  putStrLn $ "The status code was: " ++ (show $ statusCode $ responseStatus response)
--
--  let body = decodeUtf8 $ LBS.toStrict $ responseBody response
--  decodeMDS body
