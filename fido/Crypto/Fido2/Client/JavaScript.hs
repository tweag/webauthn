{-# LANGUAGE DataKinds #-}

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
    -- PublicKeyCredential (..),
    -- AuthenticatorAttestationResponse (..),
    -- AuthenticatorAssertionResponse (..),

    -- * Nested types
    PublicKeyCredentialRpEntity (..),
    PublicKeyCredentialUserEntity (..),
    PublicKeyCredentialParameters (..),
    COSEAlgorithmIdentifier,
    PublicKeyCredentialDescriptor (..),
    AuthenticatorSelectionCriteria (..),
    AuthenticationExtensionsClientInputs (..),

    -- * JavaScript-builtin types
    DOMString,
    UnsignedLong,
    BufferSource (..),
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

type JSONEncoding = CustomJSON '[OmitNothingFields, FieldLabelModifier (Rename "typ" "type")]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
data PublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-rp)
    -- This member contains data about the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- responsible for the request.
    rp :: PublicKeyCredentialRpEntity,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user)
    -- This member contains data about the user account for which the
    -- [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) is requesting attestation.
    user :: PublicKeyCredentialUserEntity,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-challenge)
    -- This member contains a challenge intended to be used for generating the newly created
    -- credential’s attestation object. See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
    -- security consideration.
    challenge :: BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-pubkeycredparams)
    -- This member contains information about the desired properties of the credential to be created.
    -- The sequence is ordered from most preferred to least preferred.
    -- The [client](https://www.w3.org/TR/webauthn-2/#client) makes a best-effort
    -- to create the most preferred credential that it can.
    pubKeyCredParams :: [PublicKeyCredentialParameters],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
    -- This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    -- This is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
    timeout :: Maybe UnsignedLong,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials)
    -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- that wish to limit the creation of multiple credentials for the same account on a single authenticator.
    -- The [client](https://www.w3.org/TR/webauthn-2/#client) is requested to return an error if the new credential
    -- would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
    excludeCredentials :: Maybe [PublicKeyCredentialDescriptor],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection)
    -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- that wish to select the appropriate authenticators to participate in the [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) operation.
    authenticatorSelection :: Maybe AuthenticatorSelectionCriteria,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-attestation)
    -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- that wish to express their preference for [attestation conveyance](https://www.w3.org/TR/webauthn-2/#attestation-conveyance).
    attestation :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-extensions)
    -- This member contains additional parameters requesting additional processing by the client and authenticator.
    -- For example, the caller may request that only authenticators with certain capabilities be used to create the credential,
    -- or that particular information be returned in the [attestation object](https://www.w3.org/TR/webauthn-2/#attestation-object).
    -- Some extensions are defined in [§ 9 WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#sctn-extensions);
    -- consult the IANA "WebAuthn Extension Identifiers" registry [IANA-WebAuthn-Registries](https://www.w3.org/TR/webauthn-2/#biblio-iana-webauthn-registries)
    -- established by [RFC8809](https://www.w3.org/TR/webauthn-2/#biblio-rfc8809) for an up-to-date
    -- list of registered [WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#webauthn-extensions).
    extensions :: Maybe AuthenticationExtensionsClientInputs
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialCreationOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params)
-- The 'PublicKeyCredentialRpEntity' dictionary is used to supply additional
-- [Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) attributes when creating a new credential.
data PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id)
    -- A unique identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- entity, which sets the [RP ID](https://www.w3.org/TR/webauthn-2/#rp-id).
    id :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability)
    -- identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
    -- intended only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
    name :: DOMString
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialRpEntity

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-user-credential-params)
-- The 'PublicKeyCredentialUserEntity' dictionary is used to supply additional
-- user account attributes when creating a new credential.
data PublicKeyCredentialUserEntity = PublicKeyCredentialUserEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id)
    -- The [user handle](https://www.w3.org/TR/webauthn-2/#user-handle) of the user account entity.
    -- A [user handle](https://www.w3.org/TR/webauthn-2/#user-handle) is an opaque
    -- byte sequence with a maximum size of 64 bytes, and is not meant to be displayed to the user.
    id :: BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) name for the user account,
    -- intended only for display. For example, "Alex Müller" or "田中倫".
    displayName :: DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) identifier for a user account.
    -- It is intended only for display, i.e., aiding the user in determining the difference between user
    -- accounts with similar displayNames. For example, "alexm", "alex.mueller@example.com" or "+14255551234".
    name :: DOMString
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialUserEntity

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-params)
-- This dictionary is used to supply additional parameters when creating a new credential.
data PublicKeyCredentialParameters = PublicKeyCredentialParameters
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-type)
    -- This member specifies the type of credential to be created.
    typ :: DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-alg)
    -- This member specifies the cryptographic signature algorithm with which the newly
    -- generated credential will be used, and thus also the type of asymmetric
    -- key pair to be generated, e.g., RSA or Elliptic Curve.
    alg :: COSEAlgorithmIdentifier
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialParameters

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier)
-- A 'COSEAlgorithmIdentifier''s value is a number identifying a cryptographic algorithm.
type COSEAlgorithmIdentifier = Int32

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor)
-- This dictionary contains the attributes that are specified by a caller when referring to a
-- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) as an input parameter to the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) or
-- [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) methods.
-- It mirrors the fields of the 'PublicKeyCredential' object returned by the latter methods.
data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-type)
    -- This member contains the type of the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    typ :: DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-id)
    -- This member contains the [credential ID](https://www.w3.org/TR/webauthn-2/#credential-id) of the
    -- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    id :: BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports)
    -- This OPTIONAL member contains a hint as to how the [client](https://www.w3.org/TR/webauthn-2/#client)
    -- might communicate with the [managing authenticator](https://www.w3.org/TR/webauthn-2/#public-key-credential-source-managing-authenticator)
    -- of the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    transports :: Maybe [DOMString]
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialDescriptor

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria)
-- [WebAuthn Relying Parties](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)
-- may use the 'AuthenticatorSelectionCriteria' dictionary to specify their
-- requirements regarding authenticator attributes.
data AuthenticatorSelectionCriteria = AuthenticatorSelectionCriteria
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-authenticatorattachment)
    -- If this member is present, eligible authenticators are filtered to
    -- only authenticators attached with the specified [§ 5.4.5 Authenticator
    -- Attachment Enumeration (enum AuthenticatorAttachment)](https://www.w3.org/TR/webauthn-2/#enum-attachment).
    authenticatorAttachment :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
    -- Specifies the extent to which the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- desires to create a [client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential).
    -- For historical reasons the naming retains the deprecated “resident” terminology.
    residentKey :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
    -- This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical reasons,
    -- its naming retains the deprecated “resident” terminology for [discoverable credentials](https://www.w3.org/TR/webauthn-2/#discoverable-credential).
    requireResidentKey :: Maybe Bool,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification)
    -- This member describes the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s
    -- requirements regarding [user verification](https://www.w3.org/TR/webauthn-2/#user-verification)
    -- for the [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
    -- operation. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    userVerification :: Maybe DOMString
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding AuthenticatorSelectionCriteria

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-inputs)
-- This is a dictionary containing the [client extension input](https://www.w3.org/TR/webauthn-2/#client-extension-input)
-- values for zero or more [WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#webauthn-extensions).
-- TODO: Implement a way to specify extensions, or implement them here directly
data AuthenticationExtensionsClientInputs = AuthenticationExtensionsClientInputs
  {
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding AuthenticationExtensionsClientInputs

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
-- The 'PublicKeyCredentialRequestOptions' dictionary supplies `[get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)`
-- with the data it needs to generate an assertion.
data PublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge)
    -- This member represents a challenge that the selected [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) signs,
    -- along with other data, when producing an [authentication assertion](https://www.w3.org/TR/webauthn-2/#authentication-assertion).
    -- See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges) security consideration.
    challenge :: BufferSource,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-timeout)
    -- This OPTIONAL member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    -- The value is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
    timeout :: Maybe UnsignedLong,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-rpid)
    -- This OPTIONAL member specifies the [relying party identifier](https://www.w3.org/TR/webauthn-2/#relying-party-identifier) claimed by the caller.
    -- If omitted, its value will be the `[CredentialsContainer](https://w3c.github.io/webappsec-credential-management/#credentialscontainer)`
    -- object’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object)'s
    -- [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin)'s
    -- [effective domain](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain).
    rpId :: Maybe USVString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials)
    -- This OPTIONAL member contains a list of 'PublicKeyCredentialDescriptor'
    -- objects representing [public key credentials](https://www.w3.org/TR/webauthn-2/#public-key-credential) acceptable to the caller,
    -- in descending order of the caller’s preference (the first item in the list is the most preferred credential, and so on down the list).
    allowCredentials :: Maybe [PublicKeyCredentialDescriptor],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-userverification)
    -- This OPTIONAL member describes the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s requirements regarding
    -- [user verification](https://www.w3.org/TR/webauthn-2/#user-verification) for the
    -- `[get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)` operation.
    userVerification :: Maybe DOMString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-extensions)
    -- This OPTIONAL member contains additional parameters requesting additional processing by the client and authenticator.
    -- For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
    extensions :: Maybe AuthenticationExtensionsClientInputs
  }
  deriving (Eq, Show, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding PublicKeyCredentialRequestOptions
