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
module Crypto.WebAuthn.Model.WebIDL.Internal.Decoding
  ( Decode (..),
    DecodeCreated (..),
  )
where

import qualified Crypto.WebAuthn.Cose.Algorithm as Cose
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Crypto.WebAuthn.Model.WebIDL.Internal.Binary.Decoding as B
import Crypto.WebAuthn.Model.WebIDL.Internal.Convert (Convert (IDL))
import qualified Crypto.WebAuthn.Model.WebIDL.Types as IDL
import qualified Crypto.WebAuthn.WebIDL as IDL
import Data.Coerce (Coercible, coerce)
import Data.Maybe (catMaybes, mapMaybe)
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
  decodeCreated :: M.WebAuthnRegistries -> IDL a -> Either Text a

instance Decode a => Decode (Maybe a) where
  decode Nothing = pure Nothing
  decode (Just a) = Just <$> decode a

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
instance Decode [M.AuthenticatorTransport] where
  decode = pure . mapMaybe decodeTransport
    where
      decodeTransport "usb" = Just M.AuthenticatorTransportUSB
      decodeTransport "nfc" = Just M.AuthenticatorTransportNFC
      decodeTransport "ble" = Just M.AuthenticatorTransportBLE
      decodeTransport "internal" = Just M.AuthenticatorTransportInternal
      decodeTransport _ = Nothing

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-descriptor)
-- [The type] member contains the type of the public key credential the caller
-- is referring to. The value SHOULD be a member of
-- PublicKeyCredentialType but client platforms MUST ignore any
-- PublicKeyCredentialDescriptor with an unknown type.
instance Decode [M.CredentialDescriptor] where
  decode Nothing = pure []
  decode (Just xs) = catMaybes <$> traverse decodeDescriptor xs
    where
      decodeDescriptor :: IDL.PublicKeyCredentialDescriptor -> Either Text (Maybe M.CredentialDescriptor)
      decodeDescriptor IDL.PublicKeyCredentialDescriptor {littype = "public-key", ..} = do
        let cdTyp = M.CredentialTypePublicKey
        cdId <- decode id
        cdTransports <- decode transports
        pure . Just $ M.CredentialDescriptor {..}
      decodeDescriptor _ = pure Nothing

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement)
-- The value SHOULD be a member of UserVerificationRequirement but client
-- platforms MUST ignore unknown values, treating an unknown value as if the
-- member does not exist. The default is "preferred".
instance Decode M.UserVerificationRequirement where
  decode (Just "discouraged") = Right M.UserVerificationRequirementDiscouraged
  decode (Just "preferred") = Right M.UserVerificationRequirementPreferred
  decode (Just "required") = Right M.UserVerificationRequirementRequired
  decode _ = Right M.UserVerificationRequirementPreferred

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection)
instance Decode M.AuthenticatorSelectionCriteria where
  decode IDL.AuthenticatorSelectionCriteria {..} = do
    let ascAuthenticatorAttachment = decodeAttachment =<< authenticatorAttachment
        ascResidentKey = decodeResidentKey residentKey
    ascUserVerification <- decode userVerification
    pure $ M.AuthenticatorSelectionCriteria {..}
    where
      -- Any unknown values must be ignored, treating them as if the member does not exist
      decodeAttachment "platform" = Just M.AuthenticatorAttachmentPlatform
      decodeAttachment "cross-platform" = Just M.AuthenticatorAttachmentCrossPlatform
      decodeAttachment _ = Nothing

      -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
      -- The value SHOULD be a member of ResidentKeyRequirement but client platforms
      -- MUST ignore unknown values, treating an unknown value as if the member does not
      -- exist. If no value is given then the effective value is required if
      -- requireResidentKey is true or discouraged if it is false or absent.
      decodeResidentKey :: Maybe IDL.DOMString -> M.ResidentKeyRequirement
      decodeResidentKey (Just "discouraged") = M.ResidentKeyRequirementDiscouraged
      decodeResidentKey (Just "preferred") = M.ResidentKeyRequirementPreferred
      decodeResidentKey (Just "required") = M.ResidentKeyRequirementRequired
      decodeResidentKey _ = case requireResidentKey of
        Just True -> M.ResidentKeyRequirementRequired
        _ -> M.ResidentKeyRequirementDiscouraged

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-attestationconveyancepreference)
-- Its values SHOULD be members of AttestationConveyancePreference. Client
-- platforms MUST ignore unknown values, treating an unknown value as if the
-- member does not exist. Its default value is "none".
instance Decode M.AttestationConveyancePreference where
  decode (Just "none") = Right M.AttestationConveyancePreferenceNone
  decode (Just "indirect") = Right M.AttestationConveyancePreferenceIndirect
  decode (Just "direct") = Right M.AttestationConveyancePreferenceDirect
  decode (Just "enterprise") = Right M.AttestationConveyancePreferenceEnterprise
  decode _ = Right M.AttestationConveyancePreferenceNone

-- [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialparameters)
-- [The type] member specifies the type of credential to be created. The value SHOULD
-- be a member of PublicKeyCredentialType but client platforms MUST ignore
-- unknown values, ignoring any PublicKeyCredentialParameters with an unknown
-- type.
instance Decode [M.CredentialParameters] where
  decode xs = catMaybes <$> traverse decodeParam xs
    where
      decodeParam :: IDL.PublicKeyCredentialParameters -> Either Text (Maybe M.CredentialParameters)
      decodeParam IDL.PublicKeyCredentialParameters {littype = "public-key", ..} = do
        let cpTyp = M.CredentialTypePublicKey
        cpAlg <- decode alg
        pure . Just $ M.CredentialParameters {..}
      decodeParam _ = pure Nothing

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
instance Decode (M.CredentialOptions 'K.Registration) where
  decode IDL.PublicKeyCredentialCreationOptions {..} = do
    corRp <- decode rp
    corUser <- decode user
    corChallenge <- decode challenge
    corPubKeyCredParams <- decode pubKeyCredParams
    corTimeout <- decode timeout
    corExcludeCredentials <- decode excludeCredentials
    corAuthenticatorSelection <- decode authenticatorSelection
    corAttestation <- decode attestation
    let corExtensions = M.AuthenticationExtensionsClientInputs {} <$ extensions
    pure $ M.CredentialOptionsRegistration {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
instance Decode (M.CredentialOptions 'K.Authentication) where
  decode IDL.PublicKeyCredentialRequestOptions {..} = do
    coaChallenge <- decode challenge
    coaTimeout <- decode timeout
    coaRpId <- decode rpId
    coaAllowCredentials <- decode allowCredentials
    coaUserVerification <- decode userVerification
    let coaExtensions = M.AuthenticationExtensionsClientInputs {} <$ extensions
    pure $ M.CredentialOptionsAuthentication {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
instance DecodeCreated (M.AttestationObject 'True) where
  decodeCreated registries (IDL.URLEncodedBase64 bytes) =
    B.decodeAttestationObject (M.warAttestationStatementFormats registries) bytes

instance DecodeCreated (M.AuthenticatorResponse 'K.Registration 'True) where
  decodeCreated supportedFormats IDL.AuthenticatorAttestationResponse {..} = do
    arrClientData <- decode clientDataJSON
    arrAttestationObject <- decodeCreated supportedFormats attestationObject
    arrTransports <- case transports of
      Nothing -> pure []
      Just t -> decode t
    pure $ M.AuthenticatorResponseRegistration {..}

instance DecodeCreated (M.Credential 'K.Registration 'True) where
  decodeCreated supportedFormats IDL.PublicKeyCredential {..} = do
    cIdentifier <- decode rawId
    cResponse <- decodeCreated supportedFormats response
    cClientExtensionResults <- decode clientExtensionResults
    pure $ M.Credential {..}
