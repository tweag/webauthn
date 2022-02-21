{-# LANGUAGE DataKinds #-}

-- | Stability: experimental
-- This module contains functions and types for encoding 'T.CredentialOptions'
-- and decoding 'T.Credential's, based on intermediate types that implement the
-- 'ToJSON' and 'FromJSON' types respectively, matching the serialization used
-- by [webauthn-json](https://github.com/github/webauthn-json).
module Crypto.WebAuthn.Encoding.WebAuthnJson
  ( -- * Registration
    wjEncodeCredentialOptionsRegistration,
    WJCredentialOptionsRegistration,
    WJCredentialRegistration,
    wjDecodeCredentialRegistration',
    wjDecodeCredentialRegistration,

    -- * Authentication
    wjEncodeCredentialOptionsAuthentication,
    WJCredentialOptionsAuthentication,
    WJCredentialAuthentication,
    wjDecodeCredentialAuthentication,
  )
where

import Control.Monad.Except (runExceptT)
import Control.Monad.Identity (runIdentity)
import Control.Monad.Reader (runReaderT)
import Crypto.WebAuthn.AttestationStatementFormat (allSupportedFormats)
import qualified Crypto.WebAuthn.Encoding.Internal.WebAuthnJson as WJ
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as T
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)

-- | Encodes a @'T.CredentialOptions' 'K.Registration'@, which is needed for the
-- [registration ceremony](https://www.w3.org/TR/webauthn-2/#registration). The
-- resulting type from this function can be encoded using 'Data.Aeson.toJSON',
-- sent as a response, received by the Relying Party script, passed directly as the [@publicKey@](https://www.w3.org/TR/webauthn-2/#dom-credentialcreationoptions-publickey)
-- field in the argument to [webauthn-json](https://github.com/github/webauthn-json)'s [@create()@](https://github.com/github/webauthn-json#api) (or equivalent) function. The result of that function can then be decoded using 'wjDecodeCredentialRegistration'.
wjEncodeCredentialOptionsRegistration ::
  T.CredentialOptions 'K.Registration ->
  WJCredentialOptionsRegistration
wjEncodeCredentialOptionsRegistration = WJCredentialOptionsRegistration <$> WJ.encode

-- | The intermediate type returned by 'wjEncodeCredentialOptionsRegistration',
-- equivalent to the [@PublicKeyCredentialCreationOptions@](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions) dictionary
newtype WJCredentialOptionsRegistration = WJCredentialOptionsRegistration
  { _unWJCredentialOptionsRegistration :: WJ.PublicKeyCredentialCreationOptions
  }
  deriving newtype (Show, Eq, ToJSON)

-- | The intermediate type as an input to 'wjDecodeCredentialRegistration',
-- equivalent to the [PublicKeyCredential](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- interface with the response being an
-- [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse).
newtype WJCredentialRegistration = WJCredentialRegistration
  { unWJCredentialRegistration :: WJ.PublicKeyCredential WJ.AuthenticatorAttestationResponse
  }
  deriving newtype (Show, Eq, FromJSON, ToJSON)

-- | Decodes the intermediate 'WJCredentialRegistration' type which can be
-- parsed with 'Data.Aeson.fromJSON' from the result of
-- [webauthn-json](https://github.com/github/webauthn-json)'s
-- [@create()@](https://github.com/github/webauthn-json#api) (or equivalent)
-- function, to a @'T.Credential' 'K.Registration'@. This is the continuation
-- of 'wjEncodeCredentialOptionsRegistration'.
wjDecodeCredentialRegistration' ::
  -- | The [attestation statement formats](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats)
  -- that should be supported. The value of 'Crypto.WebAuthn.allSupportedFormats'
  -- can be passed here, but additional or custom formats may also be used if needed
  T.SupportedAttestationStatementFormats ->
  WJCredentialRegistration ->
  Either Text (T.Credential 'K.Registration 'True)
wjDecodeCredentialRegistration' supportedFormats =
  runIdentity . (`runReaderT` supportedFormats) . runExceptT . WJ.decode . unWJCredentialRegistration

-- | A version of 'wjDecodeCredentialRegistration'' with 'allSupportedFormats' passed as the supported formats
wjDecodeCredentialRegistration ::
  WJCredentialRegistration ->
  Either Text (T.Credential 'K.Registration 'True)
wjDecodeCredentialRegistration = wjDecodeCredentialRegistration' allSupportedFormats

-- | Encodes a @'T.CredentialOptions' 'K.Authentication'@, which is needed for the
-- [authentication ceremony](https://www.w3.org/TR/webauthn-2/#authentication). The
-- resulting type from this function can be encoded using 'Data.Aeson.toJSON',
-- sent as a response, received by the Relying Party script, parsed as JSON,
-- and passed directly as the [@publicKey@](https://www.w3.org/TR/webauthn-2/#dom-credentialrequestoptions-publickey)
-- field in the argument to the [@navigator.credentials.get()@](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- function.
wjEncodeCredentialOptionsAuthentication ::
  T.CredentialOptions 'K.Authentication ->
  WJCredentialOptionsAuthentication
wjEncodeCredentialOptionsAuthentication = WJCredentialOptionsAuthentication <$> WJ.encode

-- | The intermediate type returned by 'wjEncodeCredentialOptionsAuthentication',
-- equivalent to the [@PublicKeyCredentialRequestOptions@](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions) dictionary
newtype WJCredentialOptionsAuthentication = WJCredentialOptionsAuthentication
  { _unWJCredentialOptionsAuthentication :: WJ.PublicKeyCredentialRequestOptions
  }
  deriving newtype (Show, Eq, ToJSON)

-- | The intermediate type as an input to 'wjDecodeCredentialAuthentication',
-- equivalent to the [PublicKeyCredential](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- interface with the response being an
-- [AuthenticatorAssertionResponse](https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse).
newtype WJCredentialAuthentication = WJCredentialAuthentication
  { unWJCredentialAuthentication :: WJ.PublicKeyCredential WJ.AuthenticatorAssertionResponse
  }
  deriving newtype (Show, Eq, FromJSON, ToJSON)

-- | Decodes a 'WJ.RequestedPublicKeyCredential' result, corresponding to the
-- [@PublicKeyCredential@ interface](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- as returned by the [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- method while [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
--
-- | Decodes the intermediate 'WJCredentialAuthentication' type which can be
-- parsed with 'Data.Aeson.fromJSON' from the result of
-- [webauthn-json](https://github.com/github/webauthn-json)'s
-- [@get()@](https://github.com/github/webauthn-json#api) (or equivalent)
-- function, to a @'T.Credential' 'K.Authentication' True@. This is the continuation
-- of 'wjEncodeCredentialOptionsAuthentication'
wjDecodeCredentialAuthentication ::
  WJCredentialAuthentication ->
  Either Text (T.Credential 'K.Authentication 'True)
wjDecodeCredentialAuthentication =
  runIdentity . runExceptT . WJ.decode . unWJCredentialAuthentication
