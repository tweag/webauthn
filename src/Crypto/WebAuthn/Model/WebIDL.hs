{-# LANGUAGE DataKinds #-}

-- | Stability: experimental
-- This module contains functions and types for encoding 'T.CredentialOptions'
-- and decoding 'T.Credential's, based on intermediate types that implement the 'ToJSON' and 'FromJSON' types respectively, matching the serialization used by [webauthn-json](https://github.com/github/webauthn-json).
module Crypto.WebAuthn.Model.WebIDL
  ( -- * Registration
    encodeCredentialOptionsRegistration,
    IDLCredentialOptionsRegistration,
    IDLCredentialRegistration,
    decodeCredentialRegistration,

    -- * Authentication
    encodeCredentialOptionsAuthentication,
    IDLCredentialOptionsAuthentication,
    IDLCredentialAuthentication,
    decodeCredentialAuthentication,
  )
where

import Control.Monad.Except (runExcept)
import Control.Monad.Reader (runReaderT)
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as T
import Crypto.WebAuthn.Model.WebIDL.Internal.Decoding (Decode (decode), DecodeCreated (decodeCreated))
import Crypto.WebAuthn.Model.WebIDL.Internal.Encoding (Encode (encode))
import qualified Crypto.WebAuthn.Model.WebIDL.Types as IDL
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)

-- | Encodes a @'T.CredentialOptions' 'K.Registration'@, which is needed for the
-- [registration ceremony](https://www.w3.org/TR/webauthn-2/#registration). The
-- resulting type from this function can be encoded using 'Data.Aeson.toJSON',
-- sent as a response, received by the Relying Party script, passed directly as the [@publicKey@](https://www.w3.org/TR/webauthn-2/#dom-credentialcreationoptions-publickey)
-- field in the argument to [webauthn-json](https://github.com/github/webauthn-json)'s [@create()@](https://github.com/github/webauthn-json#api) (or equivalent) function. The result of that function can then be decoded using 'decodeCredentialRegistration'.
encodeCredentialOptionsRegistration ::
  T.CredentialOptions 'K.Registration ->
  IDLCredentialOptionsRegistration
encodeCredentialOptionsRegistration = IDLCredentialOptionsRegistration <$> encode

-- | The intermediate type returned by 'encodeCredentialOptionsRegistration',
-- equivalent to the [@PublicKeyCredentialCreationOptions@](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions) dictionary
newtype IDLCredentialOptionsRegistration = IDLCredentialOptionsRegistration
  { _unIDLCredentialOptionsRegistration :: IDL.PublicKeyCredentialCreationOptions
  }
  deriving newtype (Show, Eq, ToJSON)

-- | The intermediate type as an input to 'decodeCredentialRegistration',
-- equivalent to the [PublicKeyCredential](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- interface with the response being an
-- [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse).
newtype IDLCredentialRegistration = IDLCredentialRegistration
  { _unIDLCredentialRegistration :: IDL.PublicKeyCredential IDL.AuthenticatorAttestationResponse
  }
  deriving newtype (Show, Eq, FromJSON, ToJSON)

-- | Decodes the intermediate 'IDLCredentialRegistration' type which can be
-- parsed with 'Data.Aeson.fromJSON' from the result of
-- [webauthn-json](https://github.com/github/webauthn-json)'s
-- [@create()@](https://github.com/github/webauthn-json#api) (or equivalent)
-- function, to a @'T.Credential' 'K.Registration'@. This is the continuation
-- of 'encodeCredentialOptionsRegistration'.
decodeCredentialRegistration ::
  -- | The [attestation statement formats](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats)
  -- that should be supported. The value of 'Crypto.WebAuthn.allSupportedFormats'
  -- can be passed here, but additional or custom formats may also be used if needed
  T.WebAuthnRegistries ->
  IDLCredentialRegistration ->
  Either Text (T.Credential 'K.Registration 'True)
decodeCredentialRegistration registries (IDLCredentialRegistration value) = runExcept $ runReaderT (decodeCreated value) registries

-- | Encodes a @'T.CredentialOptions' 'K.Authentication'@, which is needed for the
-- [authentication ceremony](https://www.w3.org/TR/webauthn-2/#authentication). The
-- resulting type from this function can be encoded using 'Data.Aeson.toJSON',
-- sent as a response, received by the Relying Party script, parsed as JSON,
-- and passed directly as the [@publicKey@](https://www.w3.org/TR/webauthn-2/#dom-credentialrequestoptions-publickey)
-- field in the argument to the [@navigator.credentials.get()@](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- function.
encodeCredentialOptionsAuthentication ::
  T.CredentialOptions 'K.Authentication ->
  IDLCredentialOptionsAuthentication
encodeCredentialOptionsAuthentication = IDLCredentialOptionsAuthentication <$> encode

-- | The intermediate type returned by 'encodeCredentialOptionsAuthentication',
-- equivalent to the [@PublicKeyCredentialRequestOptions@](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions) dictionary
newtype IDLCredentialOptionsAuthentication = IDLCredentialOptionsAuthentication
  { _unIDLCredentialOptionsAuthentication :: IDL.PublicKeyCredentialRequestOptions
  }
  deriving newtype (Show, Eq, ToJSON)

-- | The intermediate type as an input to 'decodeCredentialAuthentication',
-- equivalent to the [PublicKeyCredential](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- interface with the response being an
-- [AuthenticatorAssertionResponse](https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse).
newtype IDLCredentialAuthentication = IDLCredentialAuthentication
  { _unIDLCredentialAuthentication :: IDL.PublicKeyCredential IDL.AuthenticatorAssertionResponse
  }
  deriving newtype (Show, Eq, FromJSON, ToJSON)

-- | Decodes a 'IDL.RequestedPublicKeyCredential' result, corresponding to the
-- [@PublicKeyCredential@ interface](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- as returned by the [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- method while [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
--
-- | Decodes the intermediate 'IDLCredentialAuthentication' type which can be
-- parsed with 'Data.Aeson.fromJSON' from the result of
-- [webauthn-json](https://github.com/github/webauthn-json)'s
-- [@get()@](https://github.com/github/webauthn-json#api) (or equivalent)
-- function, to a @'T.Credential' 'K.Authentication' True@. This is the continuation
-- of 'encodeCredentialOptionsAuthentication'
decodeCredentialAuthentication ::
  IDLCredentialAuthentication ->
  Either Text (T.Credential 'K.Authentication 'True)
decodeCredentialAuthentication (IDLCredentialAuthentication value) = runExcept $ decode value
