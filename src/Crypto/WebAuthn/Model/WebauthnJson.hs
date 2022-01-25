{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module Crypto.WebAuthn.Model.WebauthnJson where

import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as T
import Data.Aeson.Schema (Object, schema)

-- Note: PublicKeyCredentialWithClientExtensionResults and AuthenticationExtensionsClientOutputs from <https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L10-L19> don't seem to be needed

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L23-L27) and [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-descriptor)
type PublicKeyCredentialDescriptor =
  [schema|{
    type: Text,
    id: Text,
    transports: Maybe List Text,
  }|]

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L29-L33)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-inputs).
-- For the specific extensions:
--
-- * [@appid@](https://www.w3.org/TR/webauthn-2/#sctn-appid-extension)
-- * [@appidExclude@](https://www.w3.org/TR/webauthn-2/#sctn-appid-exclude-extension)
-- * [@credProps@](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-credential-properties-extension)
type AuthenticationExtensionsClientInputs =
  [schema|{
    appid: Maybe Text,
    appidExclude: Maybe Text,
    credProps: Maybe Bool,
  }|]

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L35-L39)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-outputs).
--
-- For the specific extensions:
--
-- * [@appid@](https://www.w3.org/TR/webauthn-2/#sctn-appid-extension)
-- * [@appidExclude@](https://www.w3.org/TR/webauthn-2/#sctn-appid-exclude-extension)
-- * [@credProps@](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-credential-properties-extension)
type AuthenticationExtensionsClientOutputs =
  [schema|{
    appid: Maybe Bool,
    appidExclude: Maybe Bool,
    credProps: Maybe {
      rk: Bool,
    },
  }|]

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L43-L46)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialuserentity)
type PublicKeyCredentialUserEntity =
  [schema|{
    name: Text,
    id: Text,
    displayName: Text,
  }|]

-- Note: ResidentKeyRequirement from <https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L48> is just eqivalent to Text for json

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L50-L53)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection)
type AuthenticatorSelectionCriteria =
  [schema|{
    authenticatorAttachment: Text,
    residentKey: Text,
    requireResidentKey: Bool,
    userVerification: Text,
  }|]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params)
type PublicKeyCredentialRpEntity =
  [schema|{
    name: Text,
    id: Maybe Text,
  }|]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-params)
type PublicKeyCredentialParameters =
  [schema|{
    type: Text,
    alg: Int,
  }|]

$(return [])

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L55-L67)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
type PublicKeyCredentialCreationOptions =
  [schema|{
    rp: #PublicKeyCredentialRpEntity,
    user: #PublicKeyCredentialUserEntity,

    challenge: Text,
    pubKeyCredParams: List #PublicKeyCredentialParameters,

    timeout: Maybe Int,
    excludeCredentials: Maybe List #PublicKeyCredentialDescriptor,
    authenticatorSelection: Maybe #AuthenticatorSelectionCriteria,
    attestation: Maybe Text,
    extensions: Maybe #AuthenticationExtensionsClientOutputs,
  }|]

-- Note: CredentialCreationOptionsJSON from <https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L69-L72>
-- shouldn't be needed

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L76-L80)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse)
type AuthenticatorAttestationResponse =
  [schema|{
    clientDataJSON: Text,
    attestationObject: Text,
    transports: List Text,
  }|]

-- Compile above types before reifying
$(return [])

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L82-L88)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
type PublicKeyCredentialWithAttestation =
  [schema|{
    id: Text,
    type: Text,
    rawId: Text,
    response: #AuthenticatorAttestationResponse,
    clientExtensionResults: #AuthenticationExtensionsClientOutputs,
  }|]

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L92-L99)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
type PublicKeyCredentialRequestOptions =
  [schema|{
    challenge: Text,
    timeout: Maybe Int,
    rpId: Maybe Text,
    allowCredentials: Maybe #PublicKeyCredentialDescriptor,
    userVerification: Maybe Text,
    extensions: Maybe #AuthenticationExtensionsClientInputs,
  }|]

-- Note: CredentialRequestOptionsJSON from <https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L101-L105>
-- shouldn't be needed

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L109-L114)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorassertionresponse)
type AuthenticatorAssertionResponse =
  [schema|{
    clientDataJSON: Text,
    authenticatorData: Text,
    signature: Text,
    userHandle: Try Text,
  }|]

-- Compile above types before reifying
$(return [])

-- | [(spec)](https://github.com/github/webauthn-json/blob/v0.6.5/src/webauthn-json/basic/json.ts#L116-L122)
-- and [(spec)](https://www.w3.org/TR/webauthn-2/#publickeycredential)
type PublicKeyCredentialWithAssertion =
  [schema|{
    type: Text,
    id: Text,
    rawId: Text,
    response: #AuthenticatorAssertionResponse,
    clientExtensionResults: #AuthenticationExtensionsClientOutputs,
  }|]

encodeCredentialOptionsRegistration ::
  T.CredentialOptions 'K.Registration ->
  Object PublicKeyCredentialCreationOptions
encodeCredentialOptionsRegistration = undefined
