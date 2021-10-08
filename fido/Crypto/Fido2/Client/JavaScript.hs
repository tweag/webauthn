{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}

-- |
-- This module models direct representations of JavaScript objects interacting with the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- and [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) methods, as used by [Webauthn2](https://www.w3.org/TR/webauthn-2).
-- Note that these types don't encode the semantics of their values. E.g. if the JavaScript object has a @DOMString@
-- field, but only values @"foo"@ and @"bar"@ are possible, the type is still encoded as a generic 'DOMString'.
-- This allows us to match the specification very closely, deferring decoding of these values to another module.
-- This module also implements 'Aeson.FromJSON' and 'Aeson.ToJSON' instances of its types, which are compatible with
-- [webauthn-json](https://github.com/github/webauthn-json)'s JSON schema.
--
-- The defined types are
--
-- - 'PublicKeyCredentialCreationOptions' and all its subtypes. Passed as the
--   [publicKey](https://www.w3.org/TR/webauthn-2/#dom-credentialcreationoptions-publickey) field to the
--   [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) method
--   in step 2 of [§ 7.1 Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- - 'PublicKeyCredentialRequestOptions' and all its subtypes. Passed as the
--   [publicKey](https://www.w3.org/TR/webauthn-2/#dom-credentialrequestoptions-publickey) field to the
--   [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) method
--   in step 2 of [§ 7.2 Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
-- - @'PublicKeyCredential' response@ and all its subtypes. Responses of the
--   [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) (in which case @response ~ 'AuthenticatorAttestationResponse'@) and
--   [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) (in which case @response ~ 'AuthenticatorAssertionResponse'@ methods.
module Crypto.Fido2.Client.JavaScript
  ( -- * Top-level types
    PublicKeyCredentialCreationOptions (..),
    PublicKeyCredentialRequestOptions (..),
    PublicKeyCredential (..),
    AuthenticatorAttestationResponse (..),
    AuthenticatorAssertionResponse (..),

    -- * Nested types
    PublicKeyCredentialRpEntity (..),
    PublicKeyCredentialUserEntity (..),
    PublicKeyCredentialParameters (..),
    COSEAlgorithmIdentifier,
    PublicKeyCredentialDescriptor (..),
    AuthenticatorSelectionCriteria (..),
    AuthenticationExtensionsClientInputs (..),
    AuthenticationExtensionsClientOutputs (..),

    -- * JavaScript-builtin types
    DOMString,
    UnsignedLong,
    BufferSource (..),
    ArrayBuffer,
  )
where

import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as Base64
import Data.Int (Int32)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Word (Word32)
import Deriving.Aeson
  ( CustomJSON (CustomJSON),
    FieldLabelModifier,
    OmitNothingFields,
    Rename,
  )
import GHC.Generics (Generic)

-- TODO: It's probably not okay for both DOMString and USVString to be the
-- same type, figure out how they need to differ

-- | [(spec)](https://heycam.github.io/webidl/#idl-DOMString)
type DOMString = Text

-- | [(spec)](https://heycam.github.io/webidl/#idl-USVString)
type USVString = Text

-- | [(spec)](https://heycam.github.io/webidl/#idl-unsigned-long)
type UnsignedLong = Word32

-- | [(spec)](https://heycam.github.io/webidl/#BufferSource)
newtype BufferSource = -- | base64url encoded buffersource as done by https://github.com/github/webauthn-json
  URLEncodedBase64 {unUrlEncodedBase64 :: BS.ByteString}
  deriving (Show, Eq)

instance Aeson.FromJSON BufferSource where
  parseJSON = Aeson.withText "base64url" $ \t ->
    either fail (pure . URLEncodedBase64) (Base64.decode $ Text.encodeUtf8 t)

instance Aeson.ToJSON BufferSource where
  toJSON (URLEncodedBase64 bs) = Aeson.String . Text.decodeUtf8 . Base64.encodeUnpadded $ bs

type ArrayBuffer = BufferSource

type JSONEncoding = CustomJSON '[OmitNothingFields, FieldLabelModifier (Rename "typ" "type")]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
data PublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-rp)
    rp :: PublicKeyCredentialRpEntity,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user)
    user :: PublicKeyCredentialUserEntity,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-challenge)
    challenge :: BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-pubkeycredparams)
    pubKeyCredParams :: [PublicKeyCredentialParameters],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
    timeout :: Maybe UnsignedLong,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials)
    excludeCredentials :: Maybe [PublicKeyCredentialDescriptor],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection)
    authenticatorSelection :: Maybe AuthenticatorSelectionCriteria,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-attestation)
    attestation :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-extensions)
    extensions :: Maybe AuthenticationExtensionsClientInputs
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialCreationOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params)
data PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id)
    id :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    name :: DOMString
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialRpEntity

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-user-credential-params)
data PublicKeyCredentialUserEntity = PublicKeyCredentialUserEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id)
    id :: BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
    displayName :: DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    name :: DOMString
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialUserEntity

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-params)
data PublicKeyCredentialParameters = PublicKeyCredentialParameters
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-type)
    typ :: DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-alg)
    alg :: COSEAlgorithmIdentifier
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialParameters

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier)
type COSEAlgorithmIdentifier = Int32

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor)
data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-type)
    typ :: DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-id)
    id :: BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports)
    transports :: Maybe [DOMString]
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialDescriptor

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria)
data AuthenticatorSelectionCriteria = AuthenticatorSelectionCriteria
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-authenticatorattachment)
    authenticatorAttachment :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
    residentKey :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
    requireResidentKey :: Maybe Bool,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification)
    userVerification :: Maybe DOMString
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding AuthenticatorSelectionCriteria

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-inputs)
-- TODO: Implement a way to specify extensions, or implement them here directly
data AuthenticationExtensionsClientInputs = AuthenticationExtensionsClientInputs
  {
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding AuthenticationExtensionsClientInputs

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
data PublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge)
    challenge :: BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-timeout)
    timeout :: Maybe UnsignedLong,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-rpid)
    rpId :: Maybe USVString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials)
    allowCredentials :: Maybe [PublicKeyCredentialDescriptor],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-userverification)
    userVerification :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-extensions)
    extensions :: Maybe AuthenticationExtensionsClientInputs
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialRequestOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
data PublicKeyCredential response = PublicKeyCredential
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-identifier-slot)
    rawId :: ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-response)
    response :: response,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-getclientextensionresults)
    clientExtensionResults :: AuthenticationExtensionsClientOutputs
  }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-outputs)
-- TODO: Implement a way to specify extensions, or implement them here directly
data AuthenticationExtensionsClientOutputs = AuthenticationExtensionsClientOutputs
  {
  }
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse)
data AuthenticatorAttestationResponse = AuthenticatorAttestationResponse
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
    clientDataJSON :: ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject)
    attestationObject :: ArrayBuffer
  }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorassertionresponse)
data AuthenticatorAssertionResponse = AuthenticatorAssertionResponse
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
    clientDataJSON :: ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata)
    authenticatorData :: ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-signature)
    signature :: ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-userhandle)
    userHandle :: Maybe ArrayBuffer
  }
