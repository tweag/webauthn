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

import Crypto.WebAuthn.Internal.Utils (EnumJSONEncoding)
import qualified Data.Aeson as Aeson
import Deriving.Aeson (CustomJSON (CustomJSON))
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
  deriving (Aeson.FromJSON, Aeson.ToJSON) via EnumJSONEncoding "USER_VERIFY_" UserVerificationMethod

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types)
data KeyProtectionType
  = KEY_PROTECTION_SOFTWARE
  | KEY_PROTECTION_HARDWARE
  | KEY_PROTECTION_TEE
  | KEY_PROTECTION_SECURE_ELEMENT
  | KEY_PROTECTION_REMOTE_HANDLE
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via EnumJSONEncoding "KEY_PROTECTION_" KeyProtectionType

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#matcher-protection-types)
data MatcherProtectionType
  = MATCHER_PROTECTION_SOFTWARE
  | MATCHER_PROTECTION_TEE
  | MATCHER_PROTECTION_ON_CHIP
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via EnumJSONEncoding "MATCHER_PROTECTION_" MatcherProtectionType

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
  deriving (Aeson.FromJSON, Aeson.ToJSON) via EnumJSONEncoding "ATTACHMENT_HINT_" AuthenticatorAttachmentHint

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#transaction-confirmation-display-types)
data TransactionConfirmationDisplayType
  = TRANSACTION_CONFIRMATION_DISPLAY_ANY
  | TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE
  | TRANSACTION_CONFIRMATION_DISPLAY_TEE
  | TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE
  | TRANSACTION_CONFIRMATION_DISPLAY_REMOTE
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via EnumJSONEncoding "TRANSACTION_CONFIRMATION_DISPLAY_" TransactionConfirmationDisplayType

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
  | ALG_SIGN_ED25519_EDDSA_SHA512_RAW
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via EnumJSONEncoding "ALG_SIGN_" AuthenticationAlgorithm

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#public-key-representation-formats)
data PublicKeyRepresentationFormat
  = ALG_KEY_ECC_X962_RAW
  | ALG_KEY_ECC_X962_DER
  | ALG_KEY_RSA_2048_RAW
  | ALG_KEY_RSA_2048_DER
  | ALG_KEY_COSE
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via EnumJSONEncoding "ALG_KEY_" PublicKeyRepresentationFormat

-- | [(spec)](https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authenticator-attestation-types)
data AuthenticatorAttestationType
  = ATTESTATION_BASIC_FULL
  | ATTESTATION_BASIC_SURROGATE
  | ATTESTATION_ECDAA
  | ATTESTATION_ATTCA
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via EnumJSONEncoding "ATTESTATION_" AuthenticatorAttestationType
