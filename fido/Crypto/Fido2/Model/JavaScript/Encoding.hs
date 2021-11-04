{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

-- | This module handles the encoding of structures passed to the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- and [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- methods while [Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- and [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion) respectively.
module Crypto.Fido2.Model.JavaScript.Encoding
  ( encodePublicKeyCredentialCreationOptions,
    encodePublicKeyCredentialRequestOptions,
    encodeCreatedPublicKeyCredential,
  )
where

import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Write as CBOR
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import Crypto.Fido2.Model.JavaScript.Types (Convert (JS))
import qualified Crypto.Fido2.Model.JavaScript.Types as JS
import qualified Crypto.Fido2.PublicKey as PublicKey
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Base64.URL as Base64
import Data.ByteString.Lazy (toStrict)
import Data.Coerce (Coercible, coerce)
import qualified Data.Map as Map
import qualified Data.Text.Encoding as Text

-- | @'Encode' hs@ indicates that the Haskell-specific type @hs@ can be
-- encoded to the more generic JavaScript type @'JS' hs@ with the 'encode' function.
class Convert a => Encode a where
  encode :: a -> JS a
  default encode :: Coercible a (JS a) => a -> JS a
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
  -- TODO: Implement extension support
  encode M.AuthenticationExtensionsClientInputs {} = Map.empty

-- | <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
instance Encode PublicKey.COSEAlgorithmIdentifier where
  encode PublicKey.COSEAlgorithmIdentifierES512 = -36
  encode PublicKey.COSEAlgorithmIdentifierES384 = -35
  encode PublicKey.COSEAlgorithmIdentifierEdDSA = -8
  encode PublicKey.COSEAlgorithmIdentifierES256 = -7

-- | <https://www.w3.org/TR/webauthn-2/#enum-credentialType>
instance Encode M.PublicKeyCredentialType where
  encode M.PublicKeyCredentialTypePublicKey = "public-key"

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

instance Encode M.PublicKeyCredentialRpEntity where
  encode M.PublicKeyCredentialRpEntity {..} =
    JS.PublicKeyCredentialRpEntity
      { id = encode pkcreId,
        name = encode pkcreName
      }

instance Encode M.PublicKeyCredentialUserEntity where
  encode M.PublicKeyCredentialUserEntity {..} =
    JS.PublicKeyCredentialUserEntity
      { id = encode pkcueId,
        displayName = encode pkcueDisplayName,
        name = encode pkcueName
      }

instance Encode [M.PublicKeyCredentialParameters] where
  encode = map encodeParameters
    where
      encodeParameters M.PublicKeyCredentialParameters {..} =
        JS.PublicKeyCredentialParameters
          { typ = encode pkcpTyp,
            alg = encode pkcpAlg
          }

instance Encode M.PublicKeyCredentialDescriptor where
  encode M.PublicKeyCredentialDescriptor {..} =
    JS.PublicKeyCredentialDescriptor
      { typ = encode pkcdTyp,
        id = encode pkcdId,
        transports = encode pkcdTransports
      }

instance Encode M.AuthenticatorSelectionCriteria where
  encode M.AuthenticatorSelectionCriteria {..} =
    JS.AuthenticatorSelectionCriteria
      { authenticatorAttachment = encode ascAuthenticatorAttachment,
        residentKey = encode ascResidentKey,
        -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
        -- Relying Parties SHOULD set it to true if, and only if, residentKey is set to required.
        requireResidentKey = Just (ascResidentKey == M.ResidentKeyRequirementRequired),
        userVerification = encode ascUserVerification
      }

instance Encode [M.PublicKeyCredentialDescriptor] where
  encode = Just . map encode

instance Encode (M.PublicKeyCredentialOptions 'M.Create) where
  encode M.PublicKeyCredentialCreationOptions {..} =
    JS.PublicKeyCredentialCreationOptions
      { rp = encode pkcocRp,
        user = encode pkcocUser,
        challenge = encode pkcocChallenge,
        pubKeyCredParams = encode pkcocPubKeyCredParams,
        timeout = encode pkcocTimeout,
        excludeCredentials = encode pkcocExcludeCredentials,
        authenticatorSelection = encode pkcocAuthenticatorSelection,
        attestation = encode pkcocAttestation,
        extensions = encode pkcocExtensions
      }

instance Encode (M.PublicKeyCredentialOptions 'M.Get) where
  encode M.PublicKeyCredentialRequestOptions {..} =
    JS.PublicKeyCredentialRequestOptions
      { challenge = encode pkcogChallenge,
        timeout = encode pkcogTimeout,
        rpId = encode pkcogRpId,
        allowCredentials = encode pkcogAllowCredentials,
        userVerification = encode pkcogUserVerification,
        extensions = encode pkcogExtensions
      }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- Encodes the PublicKeyCredential for attestation, this instance is mostly used in the tests where we emulate the
-- of the client.
instance Encode (M.PublicKeyCredential 'M.Create) where
  encode M.PublicKeyCredential {..} =
    JS.PublicKeyCredential
      { rawId = encode pkcIdentifier,
        response = encode pkcResponse,
        -- TODO: Extensions aren't currently supported
        clientExtensionResults = Just Map.empty
      }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorresponse)
instance Encode (M.AuthenticatorResponse 'M.Create) where
  encode M.AuthenticatorAttestationResponse {..} =
    JS.AuthenticatorAttestationResponse
      { clientDataJSON = encode arcClientData,
        attestationObject = encode arcAttestationObject
      }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
-- TODO: Consider if we should encode a general `CollectedClientData t`
instance Encode (M.CollectedClientData 'M.Create) where
  encode M.CollectedClientData {..} =
    JS.URLEncodedBase64 . Base64.encode . toStrict $
      Aeson.encode
        JS.ClientDataJSON
          { typ = "webauthn.create",
            challenge = Text.decodeUtf8 $ M.unChallenge ccdChallenge,
            origin = M.unOrigin ccdOrigin,
            crossOrigin = ccdCrossOrigin
          }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject)
instance Encode M.AttestationObject where
  encode M.AttestationObject {..} =
    JS.URLEncodedBase64 . Base64.encode . CBOR.toStrictByteString $ CBOR.encodeTerm term
    where
      term :: CBOR.Term
      term =
        CBOR.TMap
          [ (CBOR.TString "authData", CBOR.TBytes $ M.adRawData aoAuthData),
            (CBOR.TString "fmt", CBOR.TString $ M.asfIdentifier aoFmt),
            (CBOR.TString "attStmt", M.asfEncode aoFmt aoAttStmt)
          ]

-- | Encodes a 'JS.PublicKeyCredentialCreationOptions', corresponding to the
-- [`PublicKeyCredentialCreationOptions` dictionary](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
-- to be passed to the [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- method while [Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
encodePublicKeyCredentialCreationOptions ::
  M.PublicKeyCredentialOptions 'M.Create ->
  JS.PublicKeyCredentialCreationOptions
encodePublicKeyCredentialCreationOptions = encode

-- | Encodes a 'JS.PublicKeyCredentialRequestOptions', corresponding to the
-- [`PublicKeyCredentialRequestOptions` dictionary](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
-- to be passed to the [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- method while [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
encodePublicKeyCredentialRequestOptions ::
  M.PublicKeyCredentialOptions 'M.Get ->
  JS.PublicKeyCredentialRequestOptions
encodePublicKeyCredentialRequestOptions = encode

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- Encodes the PublicKeyCredential for attestation, this function is mostly used in the tests where we emulate the
-- of the client.
encodeCreatedPublicKeyCredential :: M.PublicKeyCredential 'M.Create -> JS.CreatedPublicKeyCredential
encodeCreatedPublicKeyCredential = encode
