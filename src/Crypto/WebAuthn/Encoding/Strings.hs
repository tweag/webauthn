-- | Stability: experimental
-- This module provides functions for encoding and decoding WebAuthn enum types
-- between their Haskell types defined in "Crypto.WebAuthn.Model.Types" and
-- their string forms.
module Crypto.WebAuthn.Encoding.Strings
  ( encodeCredentialType,
    decodeCredentialType,
    encodeUserVerificationRequirement,
    decodeUserVerificationRequirement,
    encodeAuthenticatorAttachment,
    decodeAuthenticatorAttachment,
    encodeResidentKeyRequirement,
    decodeResidentKeyRequirement,
    encodeAttestationConveyancePreference,
    decodeAttestationConveyancePreference,
    encodeAuthenticatorTransport,
    decodeAuthenticatorTransport,
    encodePublicKeyCredentialHint,
    decodePublicKeyCredentialHint,
  )
where

import qualified Crypto.WebAuthn.Model.Types as T
import Data.Text (Text)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype)
-- Encodes a 'T.CredentialType' to a string.
encodeCredentialType :: T.CredentialType -> Text
encodeCredentialType T.CredentialTypePublicKey = "public-key"

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype)
-- Decodes a string into a 'T.CredentialType', returning 'Left' when the string
-- isn't known to be an enum value.
decodeCredentialType :: Text -> Either Text T.CredentialType
decodeCredentialType "public-key" = pure T.CredentialTypePublicKey
decodeCredentialType str = Left $ "Unknown PublicKeyCredentialType string: " <> str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement)
-- Encodes a 'T.UserVerificationRequirement' to a string.
encodeUserVerificationRequirement :: T.UserVerificationRequirement -> Text
encodeUserVerificationRequirement T.UserVerificationRequirementRequired = "required"
encodeUserVerificationRequirement T.UserVerificationRequirementPreferred = "preferred"
encodeUserVerificationRequirement T.UserVerificationRequirementDiscouraged = "discouraged"

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement)
-- Decodes a string into a 'T.UserVerificationRequirement', returning 'Left' when
-- the string isn't known to be an enum value.
decodeUserVerificationRequirement :: Text -> Either Text T.UserVerificationRequirement
decodeUserVerificationRequirement "discouraged" = pure T.UserVerificationRequirementDiscouraged
decodeUserVerificationRequirement "preferred" = pure T.UserVerificationRequirementPreferred
decodeUserVerificationRequirement "required" = pure T.UserVerificationRequirementRequired
decodeUserVerificationRequirement str = Left $ "Unknown UserVerificationRequirement string: " <> str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment)
-- Encodes a 'T.AuthenticatorAttachment' to a string.
encodeAuthenticatorAttachment :: T.AuthenticatorAttachment -> Text
encodeAuthenticatorAttachment T.AuthenticatorAttachmentPlatform = "platform"
encodeAuthenticatorAttachment T.AuthenticatorAttachmentCrossPlatform = "cross-platform"

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment)
-- Decodes a string into a 'T.AuthenticatorAttachment', returning 'Left' when
-- the string isn't known to be an enum value.
decodeAuthenticatorAttachment :: Text -> Either Text T.AuthenticatorAttachment
decodeAuthenticatorAttachment "platform" = pure T.AuthenticatorAttachmentPlatform
decodeAuthenticatorAttachment "cross-platform" = pure T.AuthenticatorAttachmentCrossPlatform
decodeAuthenticatorAttachment str = Left $ "Unknown AuthenticatorAttachment string: " <> str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement)
-- Encodes a 'T.ResidentKeyRequirement' to a string.
encodeResidentKeyRequirement :: T.ResidentKeyRequirement -> Text
encodeResidentKeyRequirement T.ResidentKeyRequirementDiscouraged = "discouraged"
encodeResidentKeyRequirement T.ResidentKeyRequirementPreferred = "preferred"
encodeResidentKeyRequirement T.ResidentKeyRequirementRequired = "required"

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement)
-- Decodes a string into a 'T.ResidentKeyRequirement', returning 'Left' when
-- the string isn't known to be an enum value.
decodeResidentKeyRequirement :: Text -> Either Text T.ResidentKeyRequirement
decodeResidentKeyRequirement "discouraged" = pure T.ResidentKeyRequirementDiscouraged
decodeResidentKeyRequirement "preferred" = pure T.ResidentKeyRequirementPreferred
decodeResidentKeyRequirement "required" = pure T.ResidentKeyRequirementRequired
decodeResidentKeyRequirement str = Left $ "Unknown ResidentKeyRequirement string: " <> str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-attestation-convey)
-- Encodes a 'T.AttestationConveyancePreference' to a string.
encodeAttestationConveyancePreference :: T.AttestationConveyancePreference -> Text
encodeAttestationConveyancePreference T.AttestationConveyancePreferenceNone = "none"
encodeAttestationConveyancePreference T.AttestationConveyancePreferenceIndirect = "indirect"
encodeAttestationConveyancePreference T.AttestationConveyancePreferenceDirect = "direct"
encodeAttestationConveyancePreference T.AttestationConveyancePreferenceEnterprise = "enterprise"

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-attestation-convey)
-- Decodes a string into a 'T.AttestationConveyancePreference', returning 'Left' when
-- the string isn't known to be an enum value.
decodeAttestationConveyancePreference :: Text -> Either Text T.AttestationConveyancePreference
decodeAttestationConveyancePreference "none" = pure T.AttestationConveyancePreferenceNone
decodeAttestationConveyancePreference "indirect" = pure T.AttestationConveyancePreferenceIndirect
decodeAttestationConveyancePreference "direct" = pure T.AttestationConveyancePreferenceDirect
decodeAttestationConveyancePreference "enterprise" = pure T.AttestationConveyancePreferenceEnterprise
decodeAttestationConveyancePreference str = Left $ "Unknown AttestationConveyancePreference string: " <> str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport)
-- Encodes a 'T.AuthenticatorTransport' to a string.
encodeAuthenticatorTransport :: T.AuthenticatorTransport -> Text
encodeAuthenticatorTransport T.AuthenticatorTransportUSB = "usb"
encodeAuthenticatorTransport T.AuthenticatorTransportNFC = "nfc"
encodeAuthenticatorTransport T.AuthenticatorTransportBLE = "ble"
encodeAuthenticatorTransport T.AuthenticatorTransportInternal = "internal"
encodeAuthenticatorTransport (T.AuthenticatorTransportUnknown str) = str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport)
-- Decodes a string into a 'T.AuthenticatorTransport', returning
-- 'T.AuthenticatorTransportUnknown' when the string isn't known to be an enum
-- value. This is required so that relying parties can still store unknown
-- values, see
-- [transports](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-transports-slot)
-- and the clarification to that section
-- [here](https://github.com/w3c/webauthn/pull/1654)
decodeAuthenticatorTransport :: Text -> T.AuthenticatorTransport
decodeAuthenticatorTransport "usb" = T.AuthenticatorTransportUSB
decodeAuthenticatorTransport "nfc" = T.AuthenticatorTransportNFC
decodeAuthenticatorTransport "ble" = T.AuthenticatorTransportBLE
decodeAuthenticatorTransport "internal" = T.AuthenticatorTransportInternal
-- <https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-transports-slot>
-- mentions:
--
-- > The values SHOULD be members of AuthenticatorTransport but Relying Parties
-- > MUST ignore unknown values.
--
-- This is a small bug in the standard however, see
-- https://github.com/w3c/webauthn/pull/1654 which changes it to
--
-- > The values SHOULD be members of AuthenticatorTransport but Relying
-- > Parties SHOULD accept and store unknown values.
decodeAuthenticatorTransport str = T.AuthenticatorTransportUnknown str

-- | [(spec)](https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint)
-- Encodes a 'T.PublicKeyCredentialHint' to a string.
encodePublicKeyCredentialHint :: T.PublicKeyCredentialHint -> Text
encodePublicKeyCredentialHint T.PublicKeyCredentialHintSecurityKey = "security-key"
encodePublicKeyCredentialHint T.PublicKeyCredentialHintClientDevice = "client-device"
encodePublicKeyCredentialHint T.PublicKeyCredentialHintHybrid = "hybrid"
encodePublicKeyCredentialHint (T.PublicKeyCredentialHintUnknown str) = str

-- | [(spec)](https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint)
-- Decodes a string into a 'T.PublicKeyCredentialHint', returning
-- 'T.PublicKeyCredentialHintUnknown' when the string isn't a known enum value.
-- This is required for forward compatibility when new hint values are added
-- to the specification.
decodePublicKeyCredentialHint :: Text -> T.PublicKeyCredentialHint
decodePublicKeyCredentialHint "security-key" = T.PublicKeyCredentialHintSecurityKey
decodePublicKeyCredentialHint "client-device" = T.PublicKeyCredentialHintClientDevice
decodePublicKeyCredentialHint "hybrid" = T.PublicKeyCredentialHintHybrid
decodePublicKeyCredentialHint str = T.PublicKeyCredentialHintUnknown str
