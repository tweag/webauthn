{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Client.Conversion
  ( Convert (..),
    Encode (..),
  )
where

import qualified Crypto.Fido2.Client.Haskell as HS
import qualified Crypto.Fido2.Client.JavaScript as JS
import Data.Coerce (Coercible, coerce)

-- | @'Convert' hs@ indicates that the Haskell-specific type @hs@ has a more
-- general JavaScript-specific type associated with it, which can be accessed with 'JS'.
class Convert hs where
  type JS hs :: *

instance Convert hs => Convert (Maybe hs) where
  type JS (Maybe hs) = Maybe (JS hs)

instance Convert a => Convert [a] where
  type JS [a] = [JS a]

instance Convert HS.RpId where
  type JS HS.RpId = JS.DOMString

instance Convert HS.RelyingPartyName where
  type JS HS.RelyingPartyName = JS.DOMString

instance Convert HS.PublicKeyCredentialRpEntity where
  type JS HS.PublicKeyCredentialRpEntity = JS.PublicKeyCredentialRpEntity

instance Convert HS.UserHandle where
  type JS HS.UserHandle = JS.BufferSource

instance Convert HS.UserAccountDisplayName where
  type JS HS.UserAccountDisplayName = JS.DOMString

instance Convert HS.UserAccountName where
  type JS HS.UserAccountName = JS.DOMString

instance Convert HS.PublicKeyCredentialUserEntity where
  type JS HS.PublicKeyCredentialUserEntity = JS.PublicKeyCredentialUserEntity

instance Convert HS.Challenge where
  type JS HS.Challenge = JS.BufferSource

instance Convert HS.PublicKeyCredentialType where
  type JS HS.PublicKeyCredentialType = JS.DOMString

instance Convert HS.COSEAlgorithmIdentifier where
  type JS HS.COSEAlgorithmIdentifier = JS.COSEAlgorithmIdentifier

instance Convert HS.PublicKeyCredentialParameters where
  type JS HS.PublicKeyCredentialParameters = JS.PublicKeyCredentialParameters

instance Convert HS.Timeout where
  type JS HS.Timeout = JS.UnsignedLong

instance Convert HS.CredentialId where
  type JS HS.CredentialId = JS.BufferSource

instance Convert HS.AuthenticatorTransport where
  type JS HS.AuthenticatorTransport = JS.DOMString

instance Convert HS.PublicKeyCredentialDescriptor where
  type JS HS.PublicKeyCredentialDescriptor = JS.PublicKeyCredentialDescriptor

instance Convert HS.AuthenticatorAttachment where
  type JS HS.AuthenticatorAttachment = JS.DOMString

instance Convert HS.ResidentKeyRequirement where
  type JS HS.ResidentKeyRequirement = Maybe JS.DOMString

instance Convert HS.UserVerificationRequirement where
  type JS HS.UserVerificationRequirement = Maybe JS.DOMString

instance Convert HS.AuthenticatorSelectionCriteria where
  type JS HS.AuthenticatorSelectionCriteria = JS.AuthenticatorSelectionCriteria

instance Convert HS.AttestationConveyancePreference where
  type JS HS.AttestationConveyancePreference = Maybe JS.DOMString

instance Convert HS.AuthenticationExtensionsClientInputs where
  type JS HS.AuthenticationExtensionsClientInputs = JS.AuthenticationExtensionsClientInputs

instance Convert HS.PublicKeyCredentialCreationOptions where
  type JS HS.PublicKeyCredentialCreationOptions = JS.PublicKeyCredentialCreationOptions

instance Convert HS.PublicKeyCredentialRequestOptions where
  type JS HS.PublicKeyCredentialRequestOptions = JS.PublicKeyCredentialRequestOptions

-- | @'Encode' hs@ indicates that the Haskell-specific type @hs@ can be
-- encoded to the more generic JavaScript type @'JS' hs@ with the 'encode' function.
class Encode hs where
  encode :: hs -> JS hs
  default encode :: Coercible hs (JS hs) => hs -> JS hs
  encode = coerce

instance Encode HS.RpId

instance Encode HS.RelyingPartyName

instance Encode HS.UserHandle

instance Encode HS.UserAccountDisplayName

instance Encode HS.UserAccountName

instance Encode HS.Challenge

instance Encode HS.Timeout

instance Encode HS.CredentialId

instance Encode hs => Encode (Maybe hs) where
  encode Nothing = Nothing
  encode (Just hs) = Just $ encode hs

instance Encode a => Encode [a] where
  encode = fmap encode

instance Encode HS.PublicKeyCredentialRpEntity where
  encode HS.PublicKeyCredentialRpEntity {..} =
    JS.PublicKeyCredentialRpEntity
      { id = encode id,
        name = encode name
      }

instance Encode HS.PublicKeyCredentialUserEntity where
  encode HS.PublicKeyCredentialUserEntity {..} =
    JS.PublicKeyCredentialUserEntity
      { id = encode id,
        displayName = encode displayName,
        name = encode name
      }

instance Encode HS.PublicKeyCredentialParameters where
  encode HS.PublicKeyCredentialParameters {..} =
    JS.PublicKeyCredentialParameters
      { typ = encode typ,
        alg = encode alg
      }

instance Encode HS.PublicKeyCredentialDescriptor where
  encode HS.PublicKeyCredentialDescriptor {..} =
    JS.PublicKeyCredentialDescriptor
      { typ = encode typ,
        id = encode id,
        transports = encode transports
      }

instance Encode HS.AuthenticatorSelectionCriteria where
  encode HS.AuthenticatorSelectionCriteria {..} =
    JS.AuthenticatorSelectionCriteria
      { authenticatorAttachment = encode authenticatorAttachment,
        residentKey = encode residentKey,
        -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
        -- Relying Parties SHOULD set it to true if, and only if, residentKey is set to required.
        requireResidentKey = Just (residentKey == HS.ResidentKeyRequirementRequired),
        userVerification = encode userVerification
      }

instance Encode HS.PublicKeyCredentialCreationOptions where
  encode HS.PublicKeyCredentialCreationOptions {..} =
    JS.PublicKeyCredentialCreationOptions
      { rp = encode rp,
        user = encode user,
        challenge = encode challenge,
        pubKeyCredParams = encode pubKeyCredParams,
        timeout = encode timeout,
        excludeCredentials = Just $ encode excludeCredentials,
        authenticatorSelection = encode authenticatorSelection,
        attestation = encode attestation,
        extensions = encode extensions
      }

instance Encode HS.PublicKeyCredentialRequestOptions where
  encode HS.PublicKeyCredentialRequestOptions {..} =
    JS.PublicKeyCredentialRequestOptions
      { challenge = encode challenge,
        timeout = encode timeout,
        rpId = encode rpId,
        allowCredentials = Just $ encode allowCredentials,
        userVerification = encode userVerification,
        extensions = Just $ encode extensions
      }

instance Encode HS.AuthenticationExtensionsClientInputs where
  encode HS.AuthenticationExtensionsClientInputs {} =
    JS.AuthenticationExtensionsClientInputs {}

-- | <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
instance Encode HS.COSEAlgorithmIdentifier where
  encode HS.ES512 = -36
  encode HS.ES384 = -35
  encode HS.EdDSA = -8
  encode HS.ES256 = -7

-- | <https://www.w3.org/TR/webauthn-2/#enum-credentialType>
instance Encode HS.PublicKeyCredentialType where
  encode HS.PublicKey = "public-key"

-- | <https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport>
instance Encode HS.AuthenticatorTransport where
  encode HS.USB = "usb"
  encode HS.NFC = "nfc"
  encode HS.BLE = "ble"
  encode HS.Internal = "internal"

-- | <https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment>
instance Encode HS.AuthenticatorAttachment where
  encode HS.Platform = "platform"
  encode HS.CrossPlatform = "cross-platform"

-- | <https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement>
instance Encode HS.ResidentKeyRequirement where
  encode HS.ResidentKeyRequirementDiscouraged = Just "discouraged"
  encode HS.ResidentKeyRequirementPreferred = Just "preferred"
  encode HS.ResidentKeyRequirementRequired = Just "required"

-- | <https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement>
instance Encode HS.UserVerificationRequirement where
  encode HS.UserVerificationRequirementRequired = Just "required"
  encode HS.UserVerificationRequirementPreferred = Just "preferred"
  encode HS.UserVerificationRequirementDiscouraged = Just "discouraged"

-- | <https://www.w3.org/TR/webauthn-2/#enum-attestation-convey>
instance Encode HS.AttestationConveyancePreference where
  encode HS.AttestationConveyancePreferenceNone = Just "none"
  encode HS.AttestationConveyancePreferenceIndirect = Just "indirect"
  encode HS.AttestationConveyancePreferenceDirect = Just "direct"
  encode HS.AttestationConveyancePreferenceEnterprise = Just "enterprise"
