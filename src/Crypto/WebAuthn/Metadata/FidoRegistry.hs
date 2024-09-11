{-# LANGUAGE DataKinds #-}

-- | Stability: experimental
-- [Fido Registry of Predefined Values](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authenticator-attestation-types)
-- FIDO Alliance Proposed Standard 17 December 2019
module Crypto.WebAuthn.Metadata.FidoRegistry
  ( UserVerificationMethod (..),
    KeyProtectionType (..),
    MatcherProtectionType (..),
    AuthenticatorAttachmentHint (..),
    TransactionConfirmationDisplayType (..),
    AuthenticationAlgorithm (..),
    PublicKeyRepresentationFormat (..),
    AuthenticatorAttestationType (..),
  )
where

import Crypto.WebAuthn.Internal.Utils (enumJSONEncodingOptions)
import qualified Data.Aeson as Aeson
import GHC.Generics (Generic)

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods)
data UserVerificationMethod
  = USER_VERIFY_PRESENCE_INTERNAL
  | USER_VERIFY_FINGERPRINT_INTERNAL
  | USER_VERIFY_PASSCODE_INTERNAL
  | USER_VERIFY_VOICEPRINT_INTERNAL
  | USER_VERIFY_FACEPRINT_INTERNAL
  | USER_VERIFY_LOCATION_INTERNAL
  | USER_VERIFY_EYEPRINT_INTERNAL
  | USER_VERIFY_PATTERN_INTERNAL
  | USER_VERIFY_HANDPRINT_INTERNAL
  | USER_VERIFY_PASSCODE_EXTERNAL
  | USER_VERIFY_PATTERN_EXTERNAL
  | USER_VERIFY_NONE
  | USER_VERIFY_ALL
  deriving (Show, Eq, Generic)

instance Aeson.FromJSON UserVerificationMethod where
  parseJSON = Aeson.genericParseJSON $ enumJSONEncodingOptions "USER_VERIFY_"

instance Aeson.ToJSON UserVerificationMethod where
  toJSON = Aeson.genericToJSON $ enumJSONEncodingOptions "USER_VERIFY_"

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types)
data KeyProtectionType
  = KEY_PROTECTION_SOFTWARE
  | KEY_PROTECTION_HARDWARE
  | KEY_PROTECTION_TEE
  | KEY_PROTECTION_SECURE_ELEMENT
  | KEY_PROTECTION_REMOTE_HANDLE
  deriving (Show, Eq, Generic)

instance Aeson.FromJSON KeyProtectionType where
  parseJSON = Aeson.genericParseJSON $ enumJSONEncodingOptions "KEY_PROTECTION_"

instance Aeson.ToJSON KeyProtectionType where
  toJSON = Aeson.genericToJSON $ enumJSONEncodingOptions "KEY_PROTECTION_"

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#matcher-protection-types)
data MatcherProtectionType
  = MATCHER_PROTECTION_SOFTWARE
  | MATCHER_PROTECTION_TEE
  | MATCHER_PROTECTION_ON_CHIP
  deriving (Show, Eq, Generic)

instance Aeson.FromJSON MatcherProtectionType where
  parseJSON = Aeson.genericParseJSON $ enumJSONEncodingOptions "MATCHER_PROTECTION_"

instance Aeson.ToJSON MatcherProtectionType where
  toJSON = Aeson.genericToJSON $ enumJSONEncodingOptions "MATCHER_PROTECTION_"

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authenticator-attachment-hints)
data AuthenticatorAttachmentHint
  = ATTACHMENT_HINT_INTERNAL
  | ATTACHMENT_HINT_EXTERNAL
  | ATTACHMENT_HINT_WIRED
  | ATTACHMENT_HINT_WIRELESS
  | ATTACHMENT_HINT_NFC
  | ATTACHMENT_HINT_BLUETOOTH
  | ATTACHMENT_HINT_NETWORK
  | ATTACHMENT_HINT_READY
  | ATTACHMENT_HINT_WIFI_DIRECT
  deriving (Show, Eq, Generic)

instance Aeson.FromJSON AuthenticatorAttachmentHint where
  parseJSON = Aeson.genericParseJSON $ enumJSONEncodingOptions "ATTACHMENT_HINT_"

instance Aeson.ToJSON AuthenticatorAttachmentHint where
  toJSON = Aeson.genericToJSON $ enumJSONEncodingOptions "ATTACHMENT_HINT_"

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#transaction-confirmation-display-types)
data TransactionConfirmationDisplayType
  = TRANSACTION_CONFIRMATION_DISPLAY_ANY
  | TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE
  | TRANSACTION_CONFIRMATION_DISPLAY_TEE
  | TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE
  | TRANSACTION_CONFIRMATION_DISPLAY_REMOTE
  deriving (Show, Eq, Generic)

instance Aeson.FromJSON TransactionConfirmationDisplayType where
  parseJSON = Aeson.genericParseJSON $ enumJSONEncodingOptions "TRANSACTION_CONFIRMATION_DISPLAY_"

instance Aeson.ToJSON TransactionConfirmationDisplayType where
  toJSON = Aeson.genericToJSON $ enumJSONEncodingOptions "TRANSACTION_CONFIRMATION_DISPLAY_"

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authentication-algorithms)
data AuthenticationAlgorithm
  = ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW
  | ALG_SIGN_SECP256R1_ECDSA_SHA256_DER
  | ALG_SIGN_RSASSA_PSS_SHA256_RAW
  | ALG_SIGN_RSASSA_PSS_SHA256_DER
  | ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW
  | ALG_SIGN_SECP256K1_ECDSA_SHA256_DER
  | ALG_SIGN_SM2_SM3_RAW
  | ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW
  | ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER
  | ALG_SIGN_RSASSA_PSS_SHA384_RAW
  | ALG_SIGN_RSASSA_PSS_SHA512_RAW
  | ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW
  | ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW
  | ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW
  | ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW
  | ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW
  | ALG_SIGN_SECP512R1_ECDSA_SHA512_RAW
  | ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW
  | ALG_SIGN_ED25519_EDDSA_SHA512_RAW
  deriving (Show, Eq, Generic)

instance Aeson.FromJSON AuthenticationAlgorithm where
  parseJSON = Aeson.genericParseJSON $ enumJSONEncodingOptions "ALG_SIGN_"

instance Aeson.ToJSON AuthenticationAlgorithm where
  toJSON = Aeson.genericToJSON $ enumJSONEncodingOptions "ALG_SIGN_"

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#public-key-representation-formats)
data PublicKeyRepresentationFormat
  = ALG_KEY_ECC_X962_RAW
  | ALG_KEY_ECC_X962_DER
  | ALG_KEY_RSA_2048_RAW
  | ALG_KEY_RSA_2048_DER
  | ALG_KEY_COSE
  deriving (Show, Eq, Generic)

instance Aeson.FromJSON PublicKeyRepresentationFormat where
  parseJSON = Aeson.genericParseJSON $ enumJSONEncodingOptions "ALG_KEY_"

instance Aeson.ToJSON PublicKeyRepresentationFormat where
  toJSON = Aeson.genericToJSON $ enumJSONEncodingOptions "ALG_KEY_"

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authenticator-attestation-types)
data AuthenticatorAttestationType
  = ATTESTATION_BASIC_FULL
  | ATTESTATION_BASIC_SURROGATE
  | ATTESTATION_ECDAA
  | ATTESTATION_ATTCA
  deriving (Show, Eq, Generic)

instance Aeson.FromJSON AuthenticatorAttestationType where
  parseJSON = Aeson.genericParseJSON $ enumJSONEncodingOptions "ATTESTATION_"

instance Aeson.ToJSON AuthenticatorAttestationType where
  toJSON = Aeson.genericToJSON $ enumJSONEncodingOptions "ATTESTATION_"
