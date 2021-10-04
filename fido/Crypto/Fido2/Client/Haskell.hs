-- |
-- This module contains the same top-level definitions as 'Crypto.Fido2.Client.JavaScript', but with the types containing a more Haskell-friendly structure
module Crypto.Fido2.Client.Haskell
  ( -- * Top-level types
    PublicKeyCredentialCreationOptions (..),

    -- * Nested types
    RpId (..),
    RelyingPartyName (..),
    PublicKeyCredentialRpEntity (..),
    PublicKeyCredentialUserEntity (..),
    UserHandle (..),
    UserAccountDisplayName (..),
    UserAccountName (..),
    Challenge (..),
    PublicKeyCredentialType (..),
    COSEAlgorithmIdentifier (..),
    PublicKeyCredentialParameters (..),
    PublicKeyCredentialDescriptor (..),
    Timeout (..),
    CredentialId (..),
    AuthenticatorTransport (..),
    AuthenticatorAttachment (..),
    ResidentKeyRequirement (..),
    UserVerificationRequirement (..),
    AuthenticatorSelectionCriteria (..),
    AttestationConveyancePreference (..),
    AuthenticationExtensionsClientInputs (..),
  )
where

import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word32)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#rp-id)
-- A [valid domain string](https://url.spec.whatwg.org/#valid-domain-string)
-- identifying the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)
-- on whose behalf a given [registration](https://www.w3.org/TR/webauthn-2/#registration)
-- or [authentication ceremony](https://www.w3.org/TR/webauthn-2/#authentication) is being performed.
-- A [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential)
-- can only be used for [authentication](https://www.w3.org/TR/webauthn-2/#authentication)
-- with the same entity (as identified by 'RpId') it was registered with.
--
-- By default, the 'RpId' for a WebAuthn operation is set to the caller’s
-- [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin)'s
-- [effective domain](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain).
-- This default MAY be overridden by the caller, as long as the caller-specified 'RpId' value
-- [is a registrable domain suffix of or is equal to](https://html.spec.whatwg.org/multipage/origin.html#is-a-registrable-domain-suffix-of-or-is-equal-to)
-- the caller’s [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin)'s [effective domain](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain).
newtype RpId = RpId {unRpId :: Text}
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
-- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability)
-- identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
-- intended only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
--
-- - [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266](https://www.w3.org/TR/webauthn-2/#biblio-rfc8266) for the Nickname Profile of the PRECIS FreeformClass [RFC8264](https://www.w3.org/TR/webauthn-2/#biblio-rfc8264), when setting 'RelyingPartyName''s value, or displaying the value to the user.
-- - This string MAY contain language and direction metadata. [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD consider providing this information. See [§ 6.4.2 Language and Direction Encoding](https://www.w3.org/TR/webauthn-2/#sctn-strings-langdir) about how this metadata is encoded.
newtype RelyingPartyName = RelyingPartyName {unRelyingPartyName :: Text}
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params)
-- The 'PublicKeyCredentialRpEntity' dictionary is used to supply additional
-- [Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) attributes when creating a new credential.
data PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id)
    -- A unique identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- entity, which sets the 'RpId'.
    id :: Maybe RpId,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability)
    -- identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
    -- intended only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
    name :: RelyingPartyName
  }
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#user-handle)
-- The user handle is specified by a [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
-- as the value of 'id', and used to [map](https://www.w3.org/TR/webauthn-2/#authenticator-credentials-map) a specific [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) to a specific user account with the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party). Authenticators in turn [map](https://www.w3.org/TR/webauthn-2/#authenticator-credentials-map) [RP IDs](https://www.w3.org/TR/webauthn-2/#rp-id) and user handle pairs to [public key credential sources](https://www.w3.org/TR/webauthn-2/#public-key-credential-source).
-- A user handle is an opaque [byte sequence](https://infra.spec.whatwg.org/#byte-sequence) with a maximum size of 64 bytes, and is not meant to be displayed to the user.
newtype UserHandle = UserHandle {unUserHandle :: BS.ByteString}
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
-- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) name for the user account,
-- intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD
-- let the user choose this, and SHOULD NOT restrict the choice more than necessary.
--
-- - [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD perform enforcement, as prescribed in Section 2.3 of [RFC8266](https://www.w3.org/TR/webauthn-2/#biblio-rfc8266) for the Nickname Profile of the PRECIS FreeformClass [RFC8264](https://www.w3.org/TR/webauthn-2/#biblio-rfc8264), when setting 'displayName''s value, or displaying the value to the user.
-- - This string MAY contain language and direction metadata. [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD consider providing this information. See [§ 6.4.2 Language and Direction Encoding](https://www.w3.org/TR/webauthn-2/#sctn-strings-langdir) about how this metadata is encoded.
newtype UserAccountDisplayName = UserAccountDisplayName {unUserAccountDisplayName :: Text}
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
-- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) identifier for a user account.
-- It is intended only for display, i.e., aiding the user in determining the difference between user accounts with
-- similar 'displayNames'. For example, "alexm", "alex.mueller@example.com" or "+14255551234".
--
-- - The [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) MAY let the user choose this value.
--   The [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD perform enforcement,
--   as prescribed in Section 3.4.3 of [RFC8265](https://www.w3.org/TR/webauthn-2/#biblio-rfc8265)
--   for the UsernameCasePreserved Profile of the PRECIS IdentifierClass
--   [RFC8264](https://www.w3.org/TR/webauthn-2/#biblio-rfc8264), when setting 'UserAccountName''s value,
--   or displaying the value to the user.
-- - This string MAY contain language and direction metadata.
--   [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD consider providing this information.
--   See [§ 6.4.2 Language and Direction Encoding](https://www.w3.org/TR/webauthn-2/#sctn-strings-langdir)
--   about how this metadata is encoded.
newtype UserAccountName = UserAccountName {unUserAccountName :: Text}
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-user-credential-params)
-- The 'PublicKeyCredentialUserEntity' dictionary is used to supply additional
-- user account attributes when creating a new credential.
data PublicKeyCredentialUserEntity = PublicKeyCredentialUserEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id)
    -- The 'UserHandle' of the user account entity.
    -- To ensure secure operation, authentication and authorization decisions MUST
    -- be made on the basis of this 'id' member, not the 'displayName' nor 'name' members.
    -- See Section 6.1 of [RFC8266](https://www.w3.org/TR/webauthn-2/#biblio-rfc8266).
    -- The 'UserHandle' MUST NOT contain personally identifying information about the user, such as a username
    -- or e-mail address; see [§ 14.6.1 User Handle Contents](https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy)
    -- for details. The user handle MUST NOT be empty, though it MAY be null.
    -- FIXME: We don't allow encoding it as null here, because it doesn't seem to be an allowed value in the client, see <https://www.w3.org/TR/webauthn-2/#sctn-createCredential>
    id :: UserHandle,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) name for the user account,
    -- intended only for display. For example, "Alex Müller" or "田中倫".
    displayName :: UserAccountDisplayName,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) identifier for a user account.
    -- It is intended only for display, i.e., aiding the user in determining the difference between user
    -- accounts with similar displayNames. For example, "alexm", "alex.mueller@example.com" or "+14255551234".
    name :: UserAccountName
  }
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
-- This member contains a challenge intended to be used for generating the newly
-- created credential’s attestation object. See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
-- security consideration.
newtype Challenge = Challenge {unChallenge :: BS.ByteString}
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype)
-- This enumeration defines the valid credential types. It is an extension point;
-- values can be added to it in the future, as more credential types are defined.
-- The values of this enumeration are used for versioning the Authentication Assertion
-- and attestation structures according to the type of the authenticator.
data PublicKeyCredentialType = PublicKey
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier)
-- A 'COSEAlgorithmIdentifier''s value is a number identifying a cryptographic algorithm.
-- The algorithm identifiers SHOULD be values registered in the IANA COSE Algorithms
-- registry [IANA-COSE-ALGS-REG](https://www.w3.org/TR/webauthn-2/#biblio-iana-cose-algs-reg),
-- for instance, -7 for "ES256" and -257 for "RS256".
data COSEAlgorithmIdentifier
  = ES256
  | ES384
  | ES512
  | EdDSA
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-params)
-- This dictionary is used to supply additional parameters when creating a new credential.
data PublicKeyCredentialParameters = PublicKeyCredentialParameters
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-type)
    -- This member specifies the type of credential to be created.
    typ :: PublicKeyCredentialType,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-alg)
    -- This member specifies the cryptographic signature algorithm with which the newly
    -- generated credential will be used, and thus also the type of asymmetric
    -- key pair to be generated, e.g., RSA or Elliptic Curve.
    alg :: COSEAlgorithmIdentifier
  }
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#credential-id)
-- A probabilistically-unique [byte sequence](https://infra.spec.whatwg.org/#byte-sequence)
-- identifying a [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential-source)
-- source and its [authentication assertions](https://www.w3.org/TR/webauthn-2/#authentication-assertion).
newtype CredentialId = CredentialId {unCredentialId :: BS.ByteString}
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-transport)
-- [Authenticators](https://www.w3.org/TR/webauthn-2/#authenticator) may implement various [transports](https://www.w3.org/TR/webauthn-2/#enum-transport) for communicating with [clients](https://www.w3.org/TR/webauthn-2/#client). This enumeration defines hints as to how clients might communicate with a particular authenticator in order to obtain an assertion for a specific credential. Note that these hints represent the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)'s best belief as to how an authenticator may be reached. A [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) will typically learn of the supported transports for a [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) via [getTransports()](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-gettransports).
data AuthenticatorTransport
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatortransport-usb)
    -- Indicates the respective [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) can be contacted over removable USB.
    USB
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatortransport-nfc)
    -- Indicates the respective [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) can be contacted over Near Field Communication (NFC).
    NFC
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatortransport-ble)
    -- Indicates the respective [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
    BLE
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatortransport-internal)
    -- Indicates the respective [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) is contacted using a [client device](https://www.w3.org/TR/webauthn-2/#client-device)-specific transport, i.e., it is a [platform authenticator](https://www.w3.org/TR/webauthn-2/#platform-authenticators). These authenticators are not removable from the [client device](https://www.w3.org/TR/webauthn-2/#client-device).
    Internal
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor)
-- This dictionary contains the attributes that are specified by a caller when referring to a
-- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) as an input parameter to the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) or
-- [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) methods.
-- It mirrors the fields of the 'PublicKeyCredential' object returned by the latter methods.
data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-type)
    -- This member contains the type of the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    typ :: PublicKeyCredentialType,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-id)
    -- This member contains the [credential ID](https://www.w3.org/TR/webauthn-2/#credential-id) of the
    -- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    id :: CredentialId,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports)
    -- This OPTIONAL member contains a hint as to how the [client](https://www.w3.org/TR/webauthn-2/#client)
    -- might communicate with the [managing authenticator](https://www.w3.org/TR/webauthn-2/#public-key-credential-source-managing-authenticator)
    -- of the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    -- The values SHOULD be members of 'AuthenticatorTransport' but [client platforms](https://www.w3.org/TR/webauthn-2/#client-platform) MUST ignore unknown values.
    transports :: Maybe [AuthenticatorTransport]
  }
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment)
-- This enumeration’s values describe [authenticators](https://www.w3.org/TR/webauthn-2/#authenticator)' [attachment modalities](https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality). [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) use this to express a preferred [authenticator attachment modality](https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality) when calling [@navigator.credentials.create()@](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) to [create a credential](https://www.w3.org/TR/webauthn-2/#sctn-createCredential).
data AuthenticatorAttachment
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattachment-platform)
    -- This value indicates [platform attachment](https://www.w3.org/TR/webauthn-2/#platform-attachment).
    Platform
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattachment-cross-platform)
    -- This value indicates [cross-platform attachment](https://www.w3.org/TR/webauthn-2/#cross-platform-attachment).
    CrossPlatform
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-residentkeyrequirement)
-- This enumeration’s values describe the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s
-- requirements for [client-side discoverable credentials](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential)
-- (formerly known as [resident credentials](https://www.w3.org/TR/webauthn-2/#resident-credential)
-- or [resident keys](https://www.w3.org/TR/webauthn-2/#resident-key)):
data ResidentKeyRequirement
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-discouraged)
    -- This value indicates the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- prefers creating a [server-side credential](https://www.w3.org/TR/webauthn-2/#server-side-credential),
    -- but will accept a [client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential).
    ResidentKeyRequirementDiscouraged
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-preferred)
    -- This value indicates the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- strongly prefers [creating a client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential),
    -- but will accept a [server-side credential](https://www.w3.org/TR/webauthn-2/#server-side-credential).
    -- For example, user agents SHOULD guide the user through setting up [user verification](https://www.w3.org/TR/webauthn-2/#user-verification)
    -- if needed to create a [client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential)
    -- in this case. This takes precedence over the setting of 'userVerification'.
    ResidentKeyRequirementPreferred
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-required)
    -- This value indicates the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- requires a [client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential),
    -- and is prepared to receive an error if a
    -- [client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential) cannot be created.
    ResidentKeyRequirementRequired
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement)
-- A [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) may
-- require [user verification](https://www.w3.org/TR/webauthn-2/#user-verification) for some
-- of its operations but not for others, and may use this type to express its needs.
data UserVerificationRequirement
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-userverificationrequirement-required)
    -- This value indicates that the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- requires [user verification](https://www.w3.org/TR/webauthn-2/#user-verification) for the
    -- operation and will fail the operation if the response does not have the
    -- [UV](https://www.w3.org/TR/webauthn-2/#uv) [flag](https://www.w3.org/TR/webauthn-2/#flags) set.
    UserVerificationRequirementRequired
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-userverificationrequirement-preferred)
    -- This value indicates that the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- prefers [user verification](https://www.w3.org/TR/webauthn-2/#user-verification) for the
    -- operation if possible, but will not fail the operation if the response does not have the
    -- [UV](https://www.w3.org/TR/webauthn-2/#uv) [flag](https://www.w3.org/TR/webauthn-2/#flags) set.
    UserVerificationRequirementPreferred
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-userverificationrequirement-discouraged)
    -- This value indicates that the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- does not want [user verification](https://www.w3.org/TR/webauthn-2/#user-verification) employed
    -- during the operation (e.g., in the interest of minimizing disruption to the user interaction flow).
    UserVerificationRequirementDiscouraged
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria)
-- [WebAuthn Relying Parties](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)
-- may use the 'AuthenticatorSelectionCriteria' dictionary to specify their
-- requirements regarding authenticator attributes.
data AuthenticatorSelectionCriteria = AuthenticatorSelectionCriteria
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-authenticatorattachment)
    -- If this member is present, eligible authenticators are filtered to
    -- only authenticators attached with the specified [§ 5.4.5 Authenticator
    -- Attachment Enumeration (enum AuthenticatorAttachment)](https://www.w3.org/TR/webauthn-2/#enum-attachment).
    authenticatorAttachment :: Maybe AuthenticatorAttachment,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
    -- Specifies the extent to which the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- desires to create a [client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential).
    -- For historical reasons the naming retains the deprecated “resident” terminology.
    residentKey :: ResidentKeyRequirement,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification)
    -- This member describes the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s
    -- requirements regarding [user verification](https://www.w3.org/TR/webauthn-2/#user-verification)
    -- for the [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
    -- operation. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    -- The value SHOULD be a member of 'UserVerificationRequirement' but
    -- [client platforms](https://www.w3.org/TR/webauthn-2/#client-platform) MUST ignore unknown values,
    -- treating an unknown value as if the [member does not exist](https://infra.spec.whatwg.org/#map-exists).
    userVerification :: UserVerificationRequirement
  }
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-attestation-convey)
-- [WebAuthn Relying Parties](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) may use
-- [AttestationConveyancePreference](https://www.w3.org/TR/webauthn-2/#enumdef-attestationconveyancepreference)
-- to specify their preference regarding
-- [attestation conveyance](https://www.w3.org/TR/webauthn-2/#attestation-conveyance) during credential generation.
data AttestationConveyancePreference
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-attestationconveyancepreference-none)
    -- This value indicates that the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- is not interested in [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
    -- [attestation](https://www.w3.org/TR/webauthn-2/#attestation). For example, in order to
    -- potentially avoid having to obtain [user consent](https://www.w3.org/TR/webauthn-2/#user-consent)
    -- to relay identifying information to the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
    -- or to save a roundtrip to an [Attestation CA](https://www.w3.org/TR/webauthn-2/#attestation-ca)
    -- or [Anonymization CA](https://www.w3.org/TR/webauthn-2/#anonymization-ca). This is the default value.
    AttestationConveyancePreferenceNone
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-attestationconveyancepreference-indirect)
    -- This value indicates that the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- prefers an [attestation](https://www.w3.org/TR/webauthn-2/#attestation) conveyance yielding
    -- verifiable [attestation statements](https://www.w3.org/TR/webauthn-2/#attestation-statement),
    -- but allows the client to decide how to obtain such
    -- [attestation statements](https://www.w3.org/TR/webauthn-2/#attestation-statement).
    -- The client MAY replace the authenticator-generated [attestation statements](https://www.w3.org/TR/webauthn-2/#attestation-statement)
    -- with [attestation statements](https://www.w3.org/TR/webauthn-2/#attestation-statement)
    -- generated by an [Anonymization CA](https://www.w3.org/TR/webauthn-2/#anonymization-ca),
    -- in order to protect the user’s privacy, or to assist [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- with attestation verification in a heterogeneous ecosystem.
    --
    -- Note: There is no guarantee that the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- will obtain a verifiable [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement)
    -- in this case. For example, in the case that the authenticator employs
    -- [self attestation](https://www.w3.org/TR/webauthn-2/#self-attestation).
    AttestationConveyancePreferenceIndirect
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-attestationconveyancepreference-direct)
    -- This value indicates that the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- wants to receive the [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement)
    -- as generated by the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator).
    AttestationConveyancePreferenceDirect
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-attestationconveyancepreference-enterprise)
    -- This value indicates that the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- wants to receive an [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement)
    -- that may include uniquely identifying information. This is intended for controlled deployments
    -- within an enterprise where the organization wishes to tie registrations to specific authenticators.
    -- User agents MUST NOT provide such an attestation unless the user agent or authenticator configuration
    -- permits it for the requested 'RpId'.
    --
    -- If permitted, the user agent SHOULD signal to the authenticator
    -- (at [invocation time](https://www.w3.org/TR/webauthn-2/#CreateCred-InvokeAuthnrMakeCred))
    -- that enterprise attestation is requested, and convey the resulting [AAGUID](https://www.w3.org/TR/webauthn-2/#aaguid)
    -- and [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement), unaltered,
    -- to the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party).
    AttestationConveyancePreferenceEnterprise
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-inputs)
-- This is a dictionary containing the [client extension input](https://www.w3.org/TR/webauthn-2/#client-extension-input)
-- values for zero or more [WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#webauthn-extensions).
-- TODO: Implement a way to specify extensions, or implement them here directly
data AuthenticationExtensionsClientInputs = AuthenticationExtensionsClientInputs
  {
  }
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
-- This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
-- This is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
newtype Timeout = Timeout {unTimeout :: Word32}
  deriving (Eq, Show)

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
    challenge :: Challenge,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-pubkeycredparams)
    -- This member contains information about the desired properties of the credential to be created.
    -- The sequence is ordered from most preferred to least preferred.
    -- The [client](https://www.w3.org/TR/webauthn-2/#client) makes a best-effort
    -- to create the most preferred credential that it can.
    pubKeyCredParams :: [PublicKeyCredentialParameters],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
    -- This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    -- This is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
    timeout :: Maybe Timeout,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials)
    -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- that wish to limit the creation of multiple credentials for the same account on a single authenticator.
    -- The [client](https://www.w3.org/TR/webauthn-2/#client) is requested to return an error if the new credential
    -- would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
    excludeCredentials :: [PublicKeyCredentialDescriptor],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection)
    -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- that wish to select the appropriate authenticators to participate in the [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) operation.
    authenticatorSelection :: Maybe AuthenticatorSelectionCriteria,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-attestation)
    -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- that wish to express their preference for [attestation conveyance](https://www.w3.org/TR/webauthn-2/#attestation-conveyance).
    attestation :: AttestationConveyancePreference,
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
  deriving (Eq, Show)
