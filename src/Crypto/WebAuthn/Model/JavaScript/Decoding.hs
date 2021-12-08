{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | This module handles the decoding of structures returned by the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- and [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- methods while [Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- and [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion) respectively.
module Crypto.WebAuthn.Model.JavaScript.Decoding
  ( -- * Decoding PublicKeyCredential results
    decodeCreatedPublicKeyCredential,
    decodeRequestedPublicKeyCredential,
    decodePublicKeyCredentialCreationOptions,
    decodePublicKeyCredentialRequestOptions,
  )
where

import Crypto.WebAuthn.Model
  ( SupportedAttestationStatementFormats,
  )
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Model.Binary.Decoding as MD
import qualified Crypto.WebAuthn.Model.JavaScript as JS
import Crypto.WebAuthn.Model.JavaScript.Types (Convert (JS))
import Crypto.WebAuthn.Model.WebauthnType (SingI)
import qualified Crypto.WebAuthn.PublicKey as PublicKey
import qualified Crypto.WebAuthn.WebIDL as IDL
import Data.Bifunctor (first)
import Data.Coerce (Coercible, coerce)
import Data.Maybe (catMaybes, mapMaybe)

-- | @'Decode' a@ indicates that the Haskell-specific type @a@ can be
-- decoded from the more generic JavaScript type @'JS' a@ with the 'decode' function.
class Convert a => Decode a where
  decode :: JS a -> Either MD.DecodingError a
  default decode :: Coercible (JS a) a => JS a -> Either MD.DecodingError a
  decode = pure . coerce

-- | Like 'Decode', but with a 'decodeCreated' function that also takes a
-- 'SupportedAttestationStatementFormats' in order to allow decoding to depend
-- on the supported attestation formats. This function also throws a
-- 'CreatedDecodingError' instead of a 'DecodingError.
class Convert a => DecodeCreated a where
  decodeCreated :: SupportedAttestationStatementFormats -> JS a -> Either MD.CreatedDecodingError a

instance Decode a => Decode (Maybe a) where
  decode Nothing = pure Nothing
  decode (Just a) = Just <$> decode a

instance Decode M.CredentialId

instance Decode M.AssertionSignature

instance Decode M.UserHandle

instance Decode M.AuthenticationExtensionsClientOutputs where
  -- TODO: Implement extension support
  decode _ = pure M.AuthenticationExtensionsClientOutputs {}

instance SingI t => Decode (M.CollectedClientData t 'True) where
  decode (IDL.URLEncodedBase64 bytes) = MD.decodeCollectedClientData bytes

instance Decode (M.AuthenticatorData 'M.Get 'True) where
  decode (IDL.URLEncodedBase64 bytes) = MD.decodeAuthenticatorData bytes

instance Decode (M.AuthenticatorResponse 'M.Get 'True) where
  decode JS.AuthenticatorAssertionResponse {..} = do
    argClientData <- decode clientDataJSON
    argAuthenticatorData <- decode authenticatorData
    argSignature <- decode signature
    argUserHandle <- decode userHandle
    pure $ M.AuthenticatorAssertionResponse {..}

instance Decode (M.PublicKeyCredential 'M.Get 'True) where
  decode JS.PublicKeyCredential {..} = do
    pkcIdentifier <- decode rawId
    pkcResponse <- decode response
    pkcClientExtensionResults <- decode clientExtensionResults
    pure $ M.PublicKeyCredential {..}

instance Decode M.RpId

instance Decode M.RelyingPartyName

instance Decode M.PublicKeyCredentialRpEntity where
  decode JS.PublicKeyCredentialRpEntity {..} = do
    pkcreId <- decode id
    pkcreName <- decode name
    pure $ M.PublicKeyCredentialRpEntity {..}

instance Decode M.UserAccountDisplayName

instance Decode M.UserAccountName

instance Decode M.PublicKeyCredentialUserEntity where
  decode JS.PublicKeyCredentialUserEntity {..} = do
    pkcueId <- decode id
    pkcueDisplayName <- decode displayName
    pkcueName <- decode name
    pure $ M.PublicKeyCredentialUserEntity {..}

instance Decode M.Challenge

instance Decode PublicKey.COSEAlgorithmIdentifier where
  -- The specification does not inspect the algorithm until
  -- assertion/attestation. We implement the check here to go to a Haskell
  -- type. Erring on the side of caution by failing to parse if an unsupported
  -- alg was encountered.
  decode n = maybe (Left $ MD.DecodingErrorUnexpectedAlgorithmIdentifier n) Right $ PublicKey.toAlg n

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
instance Decode [M.PublicKeyCredentialDescriptor] where
  decode Nothing = pure []
  decode (Just xs) = catMaybes <$> traverse decodeDescriptor xs
    where
      decodeDescriptor :: JS.PublicKeyCredentialDescriptor -> Either MD.DecodingError (Maybe M.PublicKeyCredentialDescriptor)
      decodeDescriptor JS.PublicKeyCredentialDescriptor {littype = "public-key", id, transports} = do
        let pkcdTyp = M.PublicKeyCredentialTypePublicKey
        pkcdId <- decode id
        pkcdTransports <- decode transports
        pure . Just $ M.PublicKeyCredentialDescriptor {..}
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
  decode JS.AuthenticatorSelectionCriteria {..} = do
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
instance Decode [M.PublicKeyCredentialParameters] where
  decode xs = catMaybes <$> traverse decodeParam xs
    where
      decodeParam :: JS.PublicKeyCredentialParameters -> Either MD.DecodingError (Maybe M.PublicKeyCredentialParameters)
      decodeParam JS.PublicKeyCredentialParameters {littype = "public-key", alg} = do
        let pkcpTyp = M.PublicKeyCredentialTypePublicKey
        pkcpAlg <- decode alg
        pure . Just $ M.PublicKeyCredentialParameters {..}
      decodeParam _ = pure Nothing

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
instance Decode (M.PublicKeyCredentialOptions 'M.Create) where
  decode JS.PublicKeyCredentialCreationOptions {..} = do
    pkcocRp <- decode rp
    pkcocUser <- decode user
    pkcocChallenge <- decode challenge
    pkcocPubKeyCredParams <- decode pubKeyCredParams
    pkcocTimeout <- decode timeout
    pkcocExcludeCredentials <- decode excludeCredentials
    pkcocAuthenticatorSelection <- decode authenticatorSelection
    pkcocAttestation <- decode attestation
    let pkcocExtensions = M.AuthenticationExtensionsClientInputs {} <$ extensions
    pure $ M.PublicKeyCredentialCreationOptions {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
instance Decode (M.PublicKeyCredentialOptions 'M.Get) where
  decode JS.PublicKeyCredentialRequestOptions {..} = do
    pkcogChallenge <- decode challenge
    pkcogTimeout <- decode timeout
    pkcogRpId <- decode rpId
    pkcogAllowCredentials <- decode allowCredentials
    pkcogUserVerification <- decode userVerification
    let pkcogExtensions = M.AuthenticationExtensionsClientInputs {} <$ extensions
    pure $ M.PublicKeyCredentialRequestOptions {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
instance DecodeCreated (M.AttestationObject 'True) where
  decodeCreated supportedFormats (IDL.URLEncodedBase64 bytes) =
    MD.decodeAttestationObject supportedFormats bytes

instance DecodeCreated (M.AuthenticatorResponse 'M.Create 'True) where
  decodeCreated asfMap JS.AuthenticatorAttestationResponse {..} = do
    arcClientData <- first MD.CreatedDecodingErrorCommon $ decode clientDataJSON
    arcAttestationObject <- decodeCreated asfMap attestationObject
    pure $ M.AuthenticatorAttestationResponse {..}

instance DecodeCreated (M.PublicKeyCredential 'M.Create 'True) where
  decodeCreated asfMap JS.PublicKeyCredential {..} = do
    pkcIdentifier <- first MD.CreatedDecodingErrorCommon $ decode rawId
    pkcResponse <- decodeCreated asfMap response
    pkcClientExtensionResults <- first MD.CreatedDecodingErrorCommon $ decode clientExtensionResults
    pure $ M.PublicKeyCredential {..}

-- | Decodes a 'JS.CreatedPublicKeyCredential' result, corresponding to the
-- [`PublicKeyCredential` interface](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- as returned by the [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- method while [Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
decodeCreatedPublicKeyCredential ::
  SupportedAttestationStatementFormats ->
  JS.CreatedPublicKeyCredential ->
  Either MD.CreatedDecodingError (M.PublicKeyCredential 'M.Create 'True)
decodeCreatedPublicKeyCredential = decodeCreated

-- | Decodes a 'JS.RequestedPublicKeyCredential' result, corresponding to the
-- [`PublicKeyCredential` interface](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- as returned by the [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- method while [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
decodeRequestedPublicKeyCredential ::
  JS.RequestedPublicKeyCredential ->
  Either MD.DecodingError (M.PublicKeyCredential 'M.Get 'True)
decodeRequestedPublicKeyCredential = decode

decodePublicKeyCredentialCreationOptions ::
  JS.PublicKeyCredentialCreationOptions ->
  Either MD.DecodingError (M.PublicKeyCredentialOptions 'M.Create)
decodePublicKeyCredentialCreationOptions = decode

decodePublicKeyCredentialRequestOptions ::
  JS.PublicKeyCredentialRequestOptions ->
  Either MD.DecodingError (M.PublicKeyCredentialOptions 'M.Get)
decodePublicKeyCredentialRequestOptions = decode
