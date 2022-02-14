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
  )
where

import qualified Crypto.WebAuthn.Model.Types as T
import Data.Text (Text)

encodeCredentialType :: T.CredentialType -> Text
encodeCredentialType T.CredentialTypePublicKey = "public-key"

decodeCredentialType :: Text -> Either Text T.CredentialType
decodeCredentialType "public-key" = pure T.CredentialTypePublicKey
decodeCredentialType str = Left $ "Unknown PublicKeyCredentialType string: " <> str

encodeUserVerificationRequirement :: T.UserVerificationRequirement -> Text
encodeUserVerificationRequirement T.UserVerificationRequirementRequired = "required"
encodeUserVerificationRequirement T.UserVerificationRequirementPreferred = "preferred"
encodeUserVerificationRequirement T.UserVerificationRequirementDiscouraged = "discouraged"

decodeUserVerificationRequirement :: Text -> Either Text T.UserVerificationRequirement
decodeUserVerificationRequirement "discouraged" = pure T.UserVerificationRequirementDiscouraged
decodeUserVerificationRequirement "preferred" = pure T.UserVerificationRequirementPreferred
decodeUserVerificationRequirement "required" = pure T.UserVerificationRequirementRequired
decodeUserVerificationRequirement key = Left $ "Unknown UserVerificationRequirement string: " <> key

encodeAuthenticatorAttachment :: T.AuthenticatorAttachment -> Text
encodeAuthenticatorAttachment T.AuthenticatorAttachmentPlatform = "platform"
encodeAuthenticatorAttachment T.AuthenticatorAttachmentCrossPlatform = "cross-platform"

decodeAuthenticatorAttachment :: Text -> Either Text T.AuthenticatorAttachment
decodeAuthenticatorAttachment "platform" = pure T.AuthenticatorAttachmentPlatform
decodeAuthenticatorAttachment "cross-platform" = pure T.AuthenticatorAttachmentCrossPlatform
decodeAuthenticatorAttachment key = Left $ "Unknown AuthenticatorAttachment string: " <> key

encodeResidentKeyRequirement :: T.ResidentKeyRequirement -> Text
encodeResidentKeyRequirement T.ResidentKeyRequirementDiscouraged = "discouraged"
encodeResidentKeyRequirement T.ResidentKeyRequirementPreferred = "preferred"
encodeResidentKeyRequirement T.ResidentKeyRequirementRequired = "required"

decodeResidentKeyRequirement :: Text -> Either Text T.ResidentKeyRequirement
decodeResidentKeyRequirement "discouraged" = pure T.ResidentKeyRequirementDiscouraged
decodeResidentKeyRequirement "preferred" = pure T.ResidentKeyRequirementPreferred
decodeResidentKeyRequirement "required" = pure T.ResidentKeyRequirementRequired
decodeResidentKeyRequirement key = Left $ "Unknown ResidentKeyRequirement string: " <> key

encodeAttestationConveyancePreference :: T.AttestationConveyancePreference -> Text
encodeAttestationConveyancePreference T.AttestationConveyancePreferenceNone = "none"
encodeAttestationConveyancePreference T.AttestationConveyancePreferenceIndirect = "indirect"
encodeAttestationConveyancePreference T.AttestationConveyancePreferenceDirect = "direct"
encodeAttestationConveyancePreference T.AttestationConveyancePreferenceEnterprise = "enterprise"

decodeAttestationConveyancePreference :: Text -> Either Text T.AttestationConveyancePreference
decodeAttestationConveyancePreference "none" = pure T.AttestationConveyancePreferenceNone
decodeAttestationConveyancePreference "indirect" = pure T.AttestationConveyancePreferenceIndirect
decodeAttestationConveyancePreference "direct" = pure T.AttestationConveyancePreferenceDirect
decodeAttestationConveyancePreference "enterprise" = pure T.AttestationConveyancePreferenceEnterprise
decodeAttestationConveyancePreference key = Left $ "Unknown AttestationConveyancePreference string: " <> key

encodeAuthenticatorTransport :: T.AuthenticatorTransport -> Text
encodeAuthenticatorTransport T.AuthenticatorTransportUSB = "usb"
encodeAuthenticatorTransport T.AuthenticatorTransportNFC = "nfc"
encodeAuthenticatorTransport T.AuthenticatorTransportBLE = "ble"
encodeAuthenticatorTransport T.AuthenticatorTransportInternal = "internal"
encodeAuthenticatorTransport (T.AuthenticatorTransportUnknown str) = str

decodeAuthenticatorTransport :: Text -> T.AuthenticatorTransport
decodeAuthenticatorTransport "usb" = T.AuthenticatorTransportUSB
decodeAuthenticatorTransport "nfc" = T.AuthenticatorTransportNFC
decodeAuthenticatorTransport "ble" = T.AuthenticatorTransportBLE
decodeAuthenticatorTransport "internal" = T.AuthenticatorTransportInternal
decodeAuthenticatorTransport str = T.AuthenticatorTransportUnknown str
