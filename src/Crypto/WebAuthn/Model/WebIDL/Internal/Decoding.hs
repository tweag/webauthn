{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RecordWildCards #-}

-- | Stability: internal
-- This module handles the decoding of structures returned by the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- and [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- methods while [Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- and [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion) respectively.
--
-- Note: The spec often mentions that _client platforms_ must ignore unknown
-- values, but since we implement only relying party code, we don't need to
-- concern ourselves with that.
module Crypto.WebAuthn.Model.WebIDL.Internal.Decoding
  ( Decode (..),
    DecodeCreated (..),
  )
where

import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import qualified Crypto.WebAuthn.Model.Defaults as D
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Crypto.WebAuthn.Model.WebIDL.Internal.Binary.Decoding as B
import Crypto.WebAuthn.Model.WebIDL.Internal.Convert (Convert (IDL))
import qualified Crypto.WebAuthn.Model.WebIDL.Types as IDL
import qualified Crypto.WebAuthn.WebIDL as IDL
import Data.Coerce (Coercible, coerce)
import Data.Singletons (SingI)
import Data.Text (Text)

-- | @'Decode' a@ indicates that the Haskell-specific type @a@ can be
-- decoded from the more generic JavaScript type @'IDL' a@ with the 'decode' function.
class Convert a => Decode a where
  decode :: IDL a -> Either Text a
  default decode :: Coercible (IDL a) a => IDL a -> Either Text a
  decode = pure . coerce

-- | Like 'Decode', but with a 'decodeCreated' function that also takes a
-- 'M.SupportedAttestationStatementFormats' in order to allow decoding to depend
-- on the supported attestation formats.
class Convert a => DecodeCreated a where
  decodeCreated :: M.SupportedAttestationStatementFormats -> IDL a -> Either Text a

decodeWithDefault :: Decode a => a -> Maybe (IDL a) -> Either Text a
decodeWithDefault def Nothing = pure def
decodeWithDefault _ (Just value) = decode value

instance (Traversable f, Decode a) => Decode (f a) where
  decode = traverse decode

instance Decode M.CredentialId

instance Decode M.AssertionSignature

instance Decode M.UserHandle

instance Decode M.AuthenticationExtensionsClientOutputs where
  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.
  decode _ = pure M.AuthenticationExtensionsClientOutputs {}

instance SingI c => Decode (M.CollectedClientData (c :: K.CeremonyKind) 'True) where
  decode (IDL.URLEncodedBase64 bytes) = B.decodeCollectedClientData bytes

instance Decode (M.AuthenticatorData 'K.Authentication 'True) where
  decode (IDL.URLEncodedBase64 bytes) = B.decodeAuthenticatorData bytes

instance Decode (M.AuthenticatorResponse 'K.Authentication 'True) where
  decode IDL.AuthenticatorAssertionResponse {..} = do
    araClientData <- decode clientDataJSON
    araAuthenticatorData <- decode authenticatorData
    araSignature <- decode signature
    araUserHandle <- decode userHandle
    pure $ M.AuthenticatorResponseAuthentication {..}

instance Decode (M.Credential 'K.Authentication 'True) where
  decode IDL.PublicKeyCredential {..} = do
    cIdentifier <- decode rawId
    cResponse <- decode response
    cClientExtensionResults <- decode clientExtensionResults
    pure $ M.Credential {..}

instance Decode M.RpId

instance Decode M.RelyingPartyName

instance Decode M.CredentialRpEntity where
  decode IDL.PublicKeyCredentialRpEntity {..} = do
    creId <- decode id
    creName <- decode name
    pure $ M.CredentialRpEntity {..}

instance Decode M.UserAccountDisplayName

instance Decode M.UserAccountName

instance Decode M.CredentialUserEntity where
  decode IDL.PublicKeyCredentialUserEntity {..} = do
    cueId <- decode id
    cueDisplayName <- decode displayName
    cueName <- decode name
    pure $ M.CredentialUserEntity {..}

instance Decode M.Challenge

instance Decode Cose.CoseSignAlg where
  -- The specification does not inspect the algorithm until
  -- assertion/attestation. We implement the check here to go to a Haskell
  -- type. Erring on the side of caution by failing to parse if an unsupported
  -- alg was encountered.
  decode = Cose.toCoseSignAlg

instance Decode M.Timeout

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-transport)
instance Decode M.AuthenticatorTransport where
  decode "usb" = pure M.AuthenticatorTransportUSB
  decode "nfc" = pure M.AuthenticatorTransportNFC
  decode "ble" = pure M.AuthenticatorTransportBLE
  decode "internal" = pure M.AuthenticatorTransportInternal
  -- FIXME: <https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-transports-slot>
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
  --
  -- This code currently thrown an error which is wrong
  decode str = Left $ "Unknown AuthenticatorTransport string: " <> str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-descriptor)
instance Decode M.CredentialDescriptor where
  decode IDL.PublicKeyCredentialDescriptor {..} = do
    cdTyp <- decode littype
    cdId <- decode id
    cdTransports <- decode transports
    pure M.CredentialDescriptor {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement)
instance Decode M.UserVerificationRequirement where
  decode "discouraged" = pure M.UserVerificationRequirementDiscouraged
  decode "preferred" = pure M.UserVerificationRequirementPreferred
  decode "required" = pure M.UserVerificationRequirementRequired
  decode str = Left $ "Unknown UserVerificationRequirement string: " <> str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-attachment)
instance Decode M.AuthenticatorAttachment where
  decode "platform" = pure M.AuthenticatorAttachmentPlatform
  decode "cross-platform" = pure M.AuthenticatorAttachmentCrossPlatform
  decode str = Left $ "Unknown AuthenticatorAttachment string: " <> str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
instance Decode M.ResidentKeyRequirement where
  decode "discouraged" = pure M.ResidentKeyRequirementDiscouraged
  decode "preferred" = pure M.ResidentKeyRequirementPreferred
  decode "required" = pure M.ResidentKeyRequirementRequired
  decode str = Left $ "Unknown ResidentKeyRequirement string: " <> str

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection)
instance Decode M.AuthenticatorSelectionCriteria where
  decode IDL.AuthenticatorSelectionCriteria {..} = do
    ascAuthenticatorAttachment <- decode authenticatorAttachment
    ascResidentKey <- decodeWithDefault (D.ascResidentKeyDefault requireResidentKey) residentKey
    ascUserVerification <- decodeWithDefault D.ascUserVerificationDefault userVerification
    pure $ M.AuthenticatorSelectionCriteria {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-attestationconveyancepreference)
instance Decode M.AttestationConveyancePreference where
  decode "none" = Right M.AttestationConveyancePreferenceNone
  decode "indirect" = Right M.AttestationConveyancePreferenceIndirect
  decode "direct" = Right M.AttestationConveyancePreferenceDirect
  decode "enterprise" = Right M.AttestationConveyancePreferenceEnterprise
  decode str = Left $ "Unknown AttestationConveyancePreference string: " <> str

instance Decode M.CredentialType where
  decode "public-key" = pure M.CredentialTypePublicKey
  decode str = Left $ "Unknown PublicKeyCredentialType string: " <> str

-- [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialparameters)
instance Decode M.CredentialParameters where
  decode IDL.PublicKeyCredentialParameters {..} = do
    cpTyp <- decode littype
    cpAlg <- decode alg
    pure M.CredentialParameters {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
instance Decode (M.CredentialOptions 'K.Registration) where
  decode IDL.PublicKeyCredentialCreationOptions {..} = do
    corRp <- decode rp
    corUser <- decode user
    corChallenge <- decode challenge
    corPubKeyCredParams <- decode pubKeyCredParams
    corTimeout <- decode timeout
    corExcludeCredentials <- decodeWithDefault D.corExcludeCredentialsDefault excludeCredentials
    corAuthenticatorSelection <- decode authenticatorSelection
    corAttestation <- decodeWithDefault D.corAttestationDefault attestation
    let corExtensions = M.AuthenticationExtensionsClientInputs {} <$ extensions
    pure $ M.CredentialOptionsRegistration {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
instance Decode (M.CredentialOptions 'K.Authentication) where
  decode IDL.PublicKeyCredentialRequestOptions {..} = do
    coaChallenge <- decode challenge
    coaTimeout <- decode timeout
    coaRpId <- decode rpId
    coaAllowCredentials <- decodeWithDefault D.coaAllowCredentialsDefault allowCredentials
    coaUserVerification <- decodeWithDefault D.coaUserVerificationDefault userVerification
    let coaExtensions = M.AuthenticationExtensionsClientInputs {} <$ extensions
    pure $ M.CredentialOptionsAuthentication {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
instance DecodeCreated (M.AttestationObject 'True) where
  decodeCreated supportedFormats (IDL.URLEncodedBase64 bytes) =
    B.decodeAttestationObject supportedFormats bytes

instance DecodeCreated (M.AuthenticatorResponse 'K.Registration 'True) where
  decodeCreated supportedFormats IDL.AuthenticatorAttestationResponse {..} = do
    arrClientData <- decode clientDataJSON
    arrAttestationObject <- decodeCreated supportedFormats attestationObject
    arrTransports <- decodeWithDefault [] transports
    pure $ M.AuthenticatorResponseRegistration {..}

instance DecodeCreated (M.Credential 'K.Registration 'True) where
  decodeCreated supportedFormats IDL.PublicKeyCredential {..} = do
    cIdentifier <- decode rawId
    cResponse <- decodeCreated supportedFormats response
    cClientExtensionResults <- decode clientExtensionResults
    pure $ M.Credential {..}
