{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Fido2.MDS where

import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.List.NonEmpty as NonEmpty
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Scientific
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding
import Data.Time
import Data.Time.Format.ISO8601
import Data.Word (Word16, Word32)
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Network.HTTP.Types.Status (statusCode)
import qualified Web.JWT as JWT

data MDSSource = Prefetched Text | Fetched Request

data MDS = MDS
  { mdsNumber :: Int,
    mdsNextUpdate :: Day,
    mdsLegalHeader :: Text,
    mdsEntries :: Value
  }
  deriving (Show)

data MDSError
  = MDSErrorJWTDecodingFailed
  | MDSErrorClaimMissing Text
  | MDSErrorClaimDecoding Text Value String
  deriving (Show)

-- https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef
newtype AAID = AAID Text

-- https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#attributes-2
newtype AAGUID = AAGUID Text

-- Hex string, this value MUST be calculated according to method 1 for computing the keyIdentifier as defined in [RFC5280] section 4.2.1.2. https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
-- TODO: Implement a way to reproduce this value
newtype KeyIdentifier = KeyIdentifier Text

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary
data MDSEntry = MDSEntry
  { -- | The AAID of the authenticator, This field MUST be set if the authenticator implements FIDO UAF.
    entryAaid :: Maybe AAID,
    entryAaguid :: Maybe AAGUID,
    entryAttestationCertificateKeyIdentifiers :: Maybe [KeyIdentifier], -- TODO: Type
    entryMetadataStatement :: MetadataStatement,
    -- , entryBiometricStatusReports, Seemingly unused?
    entryStatusReports :: [StatusReport],
    entryTimeOfLastStatusChange :: Day,
    entryRogueListURL :: Text, -- TODO: Type
    entryRogueListHash :: Text -- TODO: Type
  }

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary
data StatusReport = StatusReport
  { status :: AuthenticatorStatus,
    effectiveDate :: Day,
    authenticatorVersion :: Word32,
    -- , certificate, Seemingly unused
    url :: Text,
    certificateDescriptor :: Text,
    certificateNumber :: Text,
    certificationPolicyVersion :: Text,
    certificationRequirementsVersion :: Text
  }

-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum
data AuthenticatorStatus
  = NotFidoCertified
  | FidoCertified
  | UserVerificationBypass
  | AttestationKeyCompromise
  | UserKeyRemoteCompromise
  | UserKeyPhysicalCompromise
  | UpdateAvailable
  | Revoked
  | SelfAssertionSubmitted
  | FidoCertifiedL1
  | FidoCertifiedL1plus
  | FidoCertifiedL2
  | FidoCertifiedL2plus
  | FidoCertifiedL3
  | FidoCertifiedL3plus

data FIDOProtocol
  = UAF
  | U2F
  | FIDO2

-- https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#version-interface
data Version = Version
  { minor :: Word16,
    major :: Word16
  }

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#widl-MetadataStatement-assertionScheme
data AssertionScheme
  = UAFV1TLV
  | U2FV1BIN
  | FIDOV2

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#authentication-algorithms
data AuthenticationAlgorithms
  = ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
  | ALG_SIGN_SECP256R1_ECDSA_SHA256_DER
  | ALG_SIGN_RSASSA_PSS_SHA256_RAW
  | ALG_SIGN_RSASSA_PSS_SHA256_DER
  | ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW
  | ALG_SIGN_SECP256K1_ECDSA_SHA256_DER
  | ALG_SIGN_SM2_SM3_RAW
  | ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW
  | ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER

data PublicKeyRepresentationFormats
  = ALG_KEY_ECC_X962_RAW
  | ALG_KEY_ECC_X962_DER
  | ALG_KEY_RSA_2048_RAW
  | ALG_KEY_RSA_2048_DER
  | ALG_KEY_COSE

-- https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-reg-v1.2-rd-20171128.html#tags-used-in-the-protocol
data AttestationType
  = TAG_ATTESTATION_BASIC_FULL
  | TAG_ATTESTATION_BASIC_SURROGATE
  | TAG_ATTESTATION_ECDAA

data VerificationMethodDescriptor = VerificationMethodDescriptor

-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#metadata-keys
data MetadataStatement = MetadataStatement
  { metadataStatementLegalHeader :: Text,
    metadataStatementAaid :: AAID,
    metadataStatementAaguid :: AAGUID,
    metadataStatementAttestationCertificateKeyIdentifiers :: [KeyIdentifier],
    metadataStatementDescription :: Text,
    metadataStatementAlternativeDescriptions :: Map Text Text,
    metadataStatementAuthenticatorVersion :: Word16,
    metadataStatementProtocolFamily :: FIDOProtocol,
    metadataStatementUpv :: [Version],
    metadataStatementAssertionScheme :: AssertionScheme,
    -- NOTE: This should be required, but the field is never set in the blob
    metadataStatementAuthenticationAlgorithm :: Maybe AuthenticationAlgorithms,
    metadataStatementAuthenticationAlgorithms :: [AuthenticationAlgorithms],
    -- NOTE: This should be required, but the field is never set in the blob
    metadataStatementPublicKeyAlgAndEncoding :: Maybe PublicKeyRepresentationFormats,
    metadataStatementPublicKeyAlgAndEncodings :: [PublicKeyRepresentationFormats],
    metadataStatementAttestationTypes :: [AttestationType],
    metadataStatementUserVerificationDetails :: NonEmpty VerificationMethodDescriptor
  }

-- Stolen from https://hackage.haskell.org/package/either
maybeToRight :: a -> Maybe b -> Either a b
maybeToRight _ (Just x) = Right x
maybeToRight y Nothing = Left y

getClaim :: Text -> JWT.ClaimsMap -> (Value -> Parser a) -> Either MDSError a
getClaim field (JWT.ClaimsMap claims) parser = case Map.lookup field claims of
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

-- TODO: Use Either
decodeMDS :: Text -> Either MDSError MDS
decodeMDS body = do
  jwt <- maybeToRight MDSErrorJWTDecodingFailed $ JWT.decode body
  let claims = JWT.unregisteredClaims $ JWT.claims jwt
  number <- getClaim "no" claims (withScientific "no" parseBoundedIntegralFromScientific)
  nextUpdate <- getClaim "nextUpdate" claims (withText "nextUpdate" $ iso8601ParseM . Text.unpack)
  legalHeader <- getClaim "legalHeader" claims (withText "legalHeader" pure)
  entries <- getClaim "entries" claims pure
  return
    MDS
      { mdsNumber = number,
        mdsNextUpdate = nextUpdate,
        mdsLegalHeader = legalHeader,
        mdsEntries = entries
      }

prefetchedTest :: IO (Either MDSError MDS)
prefetchedTest = do
  contents <- BS.readFile "mds.jwt"
  let body = decodeUtf8 contents
  return $ decodeMDS body

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
