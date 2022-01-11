{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE StandaloneDeriving #-}

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
module Crypto.WebAuthn.Model.WebIDL.Types
  ( -- * Top-level types
    PublicKeyCredentialCreationOptions (..),
    PublicKeyCredentialRequestOptions (..),
    CreatedPublicKeyCredential,
    RequestedPublicKeyCredential,

    -- * Nested types
    PublicKeyCredential (..),
    AuthenticatorAttestationResponse (..),
    AuthenticatorAssertionResponse (..),
    PublicKeyCredentialRpEntity (..),
    PublicKeyCredentialUserEntity (..),
    PublicKeyCredentialParameters (..),
    COSEAlgorithmIdentifier,
    PublicKeyCredentialDescriptor (..),
    AuthenticatorSelectionCriteria (..),
  )
where

import Crypto.WebAuthn.Internal.Utils (CustomJSON (CustomJSON), JSONEncoding)
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.Map (Map)
import Data.Text (Text)
import GHC.Generics (Generic)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
data PublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-rp)
    rp :: PublicKeyCredentialRpEntity,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user)
    user :: PublicKeyCredentialUserEntity,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-challenge)
    challenge :: IDL.BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-pubkeycredparams)
    pubKeyCredParams :: [PublicKeyCredentialParameters],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
    timeout :: Maybe IDL.UnsignedLong,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials)
    excludeCredentials :: Maybe [PublicKeyCredentialDescriptor],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection)
    authenticatorSelection :: Maybe AuthenticatorSelectionCriteria,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-attestation)
    attestation :: Maybe IDL.DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-extensions)
    extensions :: Maybe (Map Text Aeson.Value)
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialCreationOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params)
data PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id)
    id :: Maybe IDL.DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    name :: IDL.DOMString
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialRpEntity

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-user-credential-params)
data PublicKeyCredentialUserEntity = PublicKeyCredentialUserEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id)
    id :: IDL.BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
    displayName :: IDL.DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    name :: IDL.DOMString
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialUserEntity

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-params)
data PublicKeyCredentialParameters = PublicKeyCredentialParameters
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-type)
    littype :: IDL.DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-alg)
    alg :: COSEAlgorithmIdentifier
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialParameters

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier)
type COSEAlgorithmIdentifier = IDL.Long

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor)
data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-type)
    littype :: IDL.DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-id)
    id :: IDL.BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports)
    transports :: Maybe [IDL.DOMString]
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialDescriptor

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria)
data AuthenticatorSelectionCriteria = AuthenticatorSelectionCriteria
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-authenticatorattachment)
    authenticatorAttachment :: Maybe IDL.DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
    residentKey :: Maybe IDL.DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
    requireResidentKey :: Maybe IDL.Boolean,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification)
    userVerification :: Maybe IDL.DOMString
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding AuthenticatorSelectionCriteria

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
data PublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge)
    challenge :: IDL.BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-timeout)
    timeout :: Maybe IDL.UnsignedLong,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-rpid)
    rpId :: Maybe IDL.USVString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials)
    allowCredentials :: Maybe [PublicKeyCredentialDescriptor],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-userverification)
    userVerification :: Maybe IDL.DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-extensions)
    extensions :: Maybe (Map Text Aeson.Value)
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialRequestOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
data PublicKeyCredential response = PublicKeyCredential
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-identifier-slot)
    rawId :: IDL.ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-response)
    response :: response,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-getclientextensionresults)
    clientExtensionResults :: Map Text Aeson.Value
  }
  deriving (Eq, Show, Generic)

deriving via
  JSONEncoding (PublicKeyCredential response)
  instance
    Aeson.FromJSON response =>
    Aeson.FromJSON (PublicKeyCredential response)

deriving via
  JSONEncoding (PublicKeyCredential response)
  instance
    Aeson.ToJSON response =>
    Aeson.ToJSON (PublicKeyCredential response)

type CreatedPublicKeyCredential = PublicKeyCredential AuthenticatorAttestationResponse

type RequestedPublicKeyCredential = PublicKeyCredential AuthenticatorAssertionResponse

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse)
data AuthenticatorAttestationResponse = AuthenticatorAttestationResponse
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
    clientDataJSON :: IDL.ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject)
    attestationObject :: IDL.ArrayBuffer
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding AuthenticatorAttestationResponse

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorassertionresponse)
data AuthenticatorAssertionResponse = AuthenticatorAssertionResponse
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
    clientDataJSON :: IDL.ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata)
    authenticatorData :: IDL.ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-signature)
    signature :: IDL.ArrayBuffer,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-userhandle)
    userHandle :: Maybe IDL.ArrayBuffer
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding AuthenticatorAssertionResponse
