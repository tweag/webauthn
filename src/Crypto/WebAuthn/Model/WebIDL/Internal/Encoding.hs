{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

-- | Stability: internal
-- This module handles the encoding of structures passed to the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- and [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- methods while [Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- and [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion) respectively.
module Crypto.WebAuthn.Model.WebIDL.Internal.Encoding
  ( Encode (..),
  )
where

import qualified Crypto.WebAuthn.Cose.Algorithm as Cose
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Crypto.WebAuthn.Model.WebIDL.Internal.Binary.Encoding as B
import Crypto.WebAuthn.Model.WebIDL.Internal.Convert (Convert (IDL))
import qualified Crypto.WebAuthn.Model.WebIDL.Types as IDL
import qualified Crypto.WebAuthn.WebIDL as IDL
import Data.Coerce (Coercible, coerce)
import qualified Data.Map as Map
import Data.Singletons (SingI)

-- | @'Encode' hs@ indicates that the Haskell-specific type @hs@ can be
-- encoded to the more generic JavaScript type @'IDL' hs@ with the 'encode' function.
class Convert a => Encode a where
  encode :: a -> IDL a
  default encode :: Coercible a (IDL a) => a -> IDL a
  encode = coerce

instance Encode hs => Encode (Maybe hs) where
  encode Nothing = Nothing
  encode (Just hs) = Just $ encode hs

instance Encode M.RpId

instance Encode M.RelyingPartyName

instance Encode M.UserHandle

instance Encode M.UserAccountDisplayName

instance Encode M.UserAccountName

instance Encode M.Challenge

instance Encode M.Timeout

instance Encode M.CredentialId

instance Encode M.AuthenticationExtensionsClientInputs where
  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.
  encode M.AuthenticationExtensionsClientInputs {} = Map.empty

-- | <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
instance Encode Cose.CoseSignAlg where
  encode = Cose.fromCoseSignAlg

-- | <https://www.w3.org/TR/webauthn-2/#enum-credentialType>
instance Encode M.CredentialType where
  encode M.CredentialTypePublicKey = "public-key"

-- | <https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport>
instance Encode [M.AuthenticatorTransport] where
  encode = map encodeTransport
    where
      encodeTransport M.AuthenticatorTransportUSB = "usb"
      encodeTransport M.AuthenticatorTransportNFC = "nfc"
      encodeTransport M.AuthenticatorTransportBLE = "ble"
      encodeTransport M.AuthenticatorTransportInternal = "internal"

-- | <https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment>
instance Encode M.AuthenticatorAttachment where
  encode M.AuthenticatorAttachmentPlatform = "platform"
  encode M.AuthenticatorAttachmentCrossPlatform = "cross-platform"

-- | <https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement>
instance Encode M.ResidentKeyRequirement where
  encode M.ResidentKeyRequirementDiscouraged = Just "discouraged"
  encode M.ResidentKeyRequirementPreferred = Just "preferred"
  encode M.ResidentKeyRequirementRequired = Just "required"

-- | <https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement>
instance Encode M.UserVerificationRequirement where
  encode M.UserVerificationRequirementRequired = Just "required"
  encode M.UserVerificationRequirementPreferred = Just "preferred"
  encode M.UserVerificationRequirementDiscouraged = Just "discouraged"

-- | <https://www.w3.org/TR/webauthn-2/#enum-attestation-convey>
instance Encode M.AttestationConveyancePreference where
  encode M.AttestationConveyancePreferenceNone = Just "none"
  encode M.AttestationConveyancePreferenceIndirect = Just "indirect"
  encode M.AttestationConveyancePreferenceDirect = Just "direct"
  encode M.AttestationConveyancePreferenceEnterprise = Just "enterprise"

instance Encode M.CredentialRpEntity where
  encode M.CredentialRpEntity {..} =
    IDL.PublicKeyCredentialRpEntity
      { id = encode creId,
        name = encode creName
      }

instance Encode M.CredentialUserEntity where
  encode M.CredentialUserEntity {..} =
    IDL.PublicKeyCredentialUserEntity
      { id = encode cueId,
        displayName = encode cueDisplayName,
        name = encode cueName
      }

instance Encode [M.CredentialParameters] where
  encode = map encodeParameters
    where
      encodeParameters M.CredentialParameters {..} =
        IDL.PublicKeyCredentialParameters
          { littype = encode cpTyp,
            alg = encode cpAlg
          }

instance Encode M.CredentialDescriptor where
  encode M.CredentialDescriptor {..} =
    IDL.PublicKeyCredentialDescriptor
      { littype = encode cdTyp,
        id = encode cdId,
        transports = encode cdTransports
      }

instance Encode M.AuthenticatorSelectionCriteria where
  encode M.AuthenticatorSelectionCriteria {..} =
    IDL.AuthenticatorSelectionCriteria
      { authenticatorAttachment = encode ascAuthenticatorAttachment,
        residentKey = encode ascResidentKey,
        -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
        -- Relying Parties SHOULD set it to true if, and only if, residentKey is set to required.
        requireResidentKey = Just (ascResidentKey == M.ResidentKeyRequirementRequired),
        userVerification = encode ascUserVerification
      }

instance Encode [M.CredentialDescriptor] where
  encode = Just . map encode

instance Encode (M.CredentialOptions 'K.Registration) where
  encode M.CredentialOptionsRegistration {..} =
    IDL.PublicKeyCredentialCreationOptions
      { rp = encode corRp,
        user = encode corUser,
        challenge = encode corChallenge,
        pubKeyCredParams = encode corPubKeyCredParams,
        timeout = encode corTimeout,
        excludeCredentials = encode corExcludeCredentials,
        authenticatorSelection = encode corAuthenticatorSelection,
        attestation = encode corAttestation,
        extensions = encode corExtensions
      }

instance Encode (M.CredentialOptions 'K.Authentication) where
  encode M.CredentialOptionsAuthentication {..} =
    IDL.PublicKeyCredentialRequestOptions
      { challenge = encode coaChallenge,
        timeout = encode coaTimeout,
        rpId = encode coaRpId,
        allowCredentials = encode coaAllowCredentials,
        userVerification = encode coaUserVerification,
        extensions = encode coaExtensions
      }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- Encodes the PublicKeyCredential for attestation, this instance is mostly used in the tests where we emulate the
-- of the client.
instance Encode (M.Credential 'K.Registration 'True) where
  encode M.Credential {..} =
    IDL.PublicKeyCredential
      { rawId = encode cIdentifier,
        response = encode cResponse,
        -- TODO: Extensions are not implemented by this library, see the TODO in the
        -- module documentation of `Crypto.WebAuthn.Model` for more information.
        clientExtensionResults = Map.empty
      }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
instance SingI c => Encode (M.CollectedClientData c 'True) where
  encode ccd = IDL.URLEncodedBase64 $ B.encodeCollectedClientData ccd

instance Encode (M.AuthenticatorResponse 'K.Authentication 'True) where
  encode M.AuthenticatorResponseAuthentication {..} =
    IDL.AuthenticatorAssertionResponse
      { clientDataJSON = encode araClientData,
        authenticatorData = IDL.URLEncodedBase64 $ M.unRaw $ M.adRawData araAuthenticatorData,
        signature = IDL.URLEncodedBase64 $ M.unAssertionSignature araSignature,
        userHandle = IDL.URLEncodedBase64 . M.unUserHandle <$> araUserHandle
      }

instance Encode (M.Credential 'K.Authentication 'True) where
  encode M.Credential {..} =
    IDL.PublicKeyCredential
      { rawId = encode cIdentifier,
        response = encode cResponse,
        -- TODO: Extensions are not implemented by this library, see the TODO in the
        -- module documentation of `Crypto.WebAuthn.Model` for more information.
        clientExtensionResults = Map.empty
      }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorresponse)
instance Encode (M.AuthenticatorResponse 'K.Registration 'True) where
  encode M.AuthenticatorResponseRegistration {..} =
    IDL.AuthenticatorAttestationResponse
      { clientDataJSON = encode arrClientData,
        attestationObject = encode arrAttestationObject
      }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject)
instance Encode (M.AttestationObject 'True) where
  encode ao = IDL.URLEncodedBase64 $ B.encodeAttestationObject ao
