{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Stability: experimental
--
-- This module contains Haskell-friendly types for structures used in WebAuthn
-- that are used throughout this library. These types are modelled according to
-- the following conventions:
--
-- * If a structure has the same semantics for both the
--   [registration](https://www.w3.org/TR/webauthn-2/#registration) and
--   [authentication](https://www.w3.org/TR/webauthn-2/#authentication) WebAuthn
--   [ceremonies](https://www.w3.org/TR/webauthn-2/#ceremony), then its type is
--   parametrized by a @c@ parameter of kind 'CeremonyKind'. If such types have
--   differing fields,
--   [GADTs](https://ghc.gitlab.haskell.org/ghc/doc/users_guide/exts/gadt.html)
--   are used to distinguish between them, where the constructor name is the
--   type name with a @...Registration@ or @...Authentication@ suffix
-- * If the raw bytes are needed for verification purposes of a structure, then
--   its type is parametrized by a @raw@ parameter of kind 'Bool'. Only if @raw
--   ~ 'True'@, the raw bytes of the necessary structures has to be present in
--   the type. The type 'RawField' is used as a helper type for this.
-- * In order to avoid duplicate record fields, all fields are prefixed with
--   the initials of the constructor name.
-- * Every type should have a 'ToJSON' instance for pretty-printing purposes.
--   This JSON encoding doesn't correspond to any encoding used for
--   sending\/receiving these structures, it's only used for pretty-printing,
--   which is why it doesn't need to be standardized. For encoding these
--   structures from\/to JSON for sending/receiving, see the
--   'Crypto.WebAuthn.Model.WebIDL' module
-- #defaultFields#
-- * Fields of the WebAuthn standard that are optional (for writing) but have
--   defaults (making them non-optional for reading) are encoded as
--   non-optional fields, while the defaults are exposed in the
--   'Crypto.WebAuthn.Model.Defaults' module. The alternative of making these
--   fields optional would allow RP not having to specify them, which seems
--   like a less safer option, since the defaults might not be what is really
--   needed, and they might change. The root cause why this decision had to be
--   made is that such assymetrical reading/writing fields don't map nicely to
--   Haskell's records.
--
-- #extensions#
-- TODO:
-- [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-extensions) This library
-- does not currently implement most extensions. In order to fully comply with
-- level 2 of the webauthn spec extensions are required. At least, we wish the
-- library to offer a typeclass implementable by relying parties to allow
-- extensions in a scheme similar to the attestation statement formats.
-- Ideally, we would implement all 8 extensions tracked by
-- [IANA](https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-extension-ids).
module Crypto.WebAuthn.Model.Types
  ( -- * Enumerations
    CredentialType (..),
    AuthenticatorTransport (..),
    AuthenticatorAttachment (..),
    ResidentKeyRequirement (..),
    UserVerificationRequirement (..),
    AttestationConveyancePreference (..),
    PublicKeyCredentialHint (..),
    AttestationChain (..),
    AttestationKind (..),
    AttestationType (..),
    VerifiableAttestationType (..),

    -- * Newtypes
    RpId (..),
    RelyingPartyName (..),
    UserHandle (..),
    generateUserHandle,
    UserAccountDisplayName (..),
    UserAccountName (..),
    CredentialId (..),
    generateCredentialId,
    Challenge (..),
    generateChallenge,
    Timeout (..),
    AssertionSignature (..),
    RpIdHash (..),
    ClientDataHash (..),
    Origin (..),
    SignatureCounter (..),
    PublicKeyBytes (..),

    -- * Extensions (unimplemented, see module documentation)
    AuthenticationExtensionsClientInputs (..),
    CredentialPropertiesOutput (..),
    AuthenticationExtensionsClientOutputs (..),
    AuthenticatorExtensionOutputs (..),

    -- * Dictionaries
    CredentialRpEntity (..),
    CredentialUserEntity (..),
    CredentialParameters (..),
    CredentialDescriptor (..),
    AuthenticatorSelectionCriteria (..),
    AuthenticatorDataFlags (..),
    CollectedClientData (..),
    AttestedCredentialData (..),
    AuthenticatorData (..),
    AttestationObject (..),
    AuthenticatorResponse (..),

    -- * Attestation Statement Formats
    SomeAttestationType (..),
    AttestationStatementFormat (..),
    SomeAttestationStatementFormat (..),
    SupportedAttestationStatementFormats,
    singletonAttestationStatementFormat,
    lookupAttestationStatementFormat,

    -- * Raw fields
    RawField (..),

    -- * Top-level types
    CredentialOptions (..),
    Credential (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Crypto.Hash (Digest)
import Crypto.Hash.Algorithms (SHA256)
import Crypto.Random (MonadRandom, getRandomBytes)
import qualified Crypto.WebAuthn.Cose.PublicKeyWithSignAlg as Cose
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import Crypto.WebAuthn.Internal.ToJSONOrphans (PrettyHexByteString (PrettyHexByteString))
import Crypto.WebAuthn.Model.Identifier (AAGUID)
import Crypto.WebAuthn.Model.Kinds
  ( AttestationKind (Unverifiable, Verifiable),
    CeremonyKind (Authentication, Registration),
    ProtocolKind (Fido2, FidoU2F),
  )
import Data.Aeson (ToJSON, Value (Null, String), object, (.=))
import Data.Aeson.Types (toJSON)
import qualified Data.ByteString as BS
import Data.HashMap.Strict (HashMap, (!?))
import qualified Data.HashMap.Strict as HashMap
import qualified Data.Hourglass as HG
import Data.Kind (Type)
import Data.List.NonEmpty (NonEmpty)
import Data.Singletons (SingI, sing)
import Data.String (IsString)
import Data.Text (Text)
import Data.Validation (Validation)
import Data.Word (Word32)
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import GHC.Generics (Generic)
import Type.Reflection (Typeable, eqTypeRep, typeOf, type (:~~:) (HRefl))

-- | A model field parametrized by whether it's empty ('False') or contains raw bytes ('True')
data RawField (raw :: Bool) where
  NoRaw :: RawField 'False
  WithRaw :: {unRaw :: BS.ByteString} -> RawField 'True

deriving instance Eq (RawField raw)

deriving instance Show (RawField raw)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON (RawField raw) where
  toJSON NoRaw = "<none>"
  toJSON (WithRaw bytes) = toJSON $ PrettyHexByteString bytes

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype)
-- This enumeration defines the valid credential types. It is an extension point;
-- values can be added to it in the future, as more credential types are defined.
-- The values of this enumeration are used for versioning the Authentication Assertion
-- and attestation structures according to the type of the authenticator.
--
-- To decode\/encode this type from\/to its standard string, use
-- 'Crypto.WebAuthn.Encoding.Strings.decodeCredentialType'/'Crypto.WebAuthn.Encoding.Strings.encodeCredentialType'.
data CredentialType = CredentialTypePublicKey
  deriving (Eq, Show, Bounded, Enum, Ord, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON CredentialType where
  toJSON CredentialTypePublicKey = "CredentialTypePublicKey"

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-transport)
-- [Authenticators](https://www.w3.org/TR/webauthn-2/#authenticator) may implement
-- various [transports](https://www.w3.org/TR/webauthn-2/#enum-transport) for communicating
-- with [clients](https://www.w3.org/TR/webauthn-2/#client). This enumeration defines
-- hints as to how clients might communicate with a particular authenticator in order
-- to obtain an assertion for a specific credential. Note that these hints represent
-- the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)'s
-- best belief as to how an authenticator may be reached. A [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
-- will typically learn of the supported transports for a [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential)
-- via [getTransports()](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-gettransports).
--
-- To decode\/encode this type from\/to its standard string, use
-- 'Crypto.WebAuthn.Encoding.Strings.decodeAuthenticatorTransport'/'Crypto.WebAuthn.Encoding.Strings.encodeAuthenticatorTransport'.
data AuthenticatorTransport
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatortransport-usb)
    -- Indicates the respective [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
    -- can be contacted over removable USB.
    AuthenticatorTransportUSB
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatortransport-nfc)
    -- Indicates the respective [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
    -- can be contacted over Near Field Communication (NFC).
    AuthenticatorTransportNFC
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatortransport-ble)
    -- Indicates the respective [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
    -- can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
    AuthenticatorTransportBLE
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatortransport-internal)
    -- Indicates the respective [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
    -- is contacted using a [client device](https://www.w3.org/TR/webauthn-2/#client-device)-specific
    -- transport, i.e., it is a [platform authenticator](https://www.w3.org/TR/webauthn-2/#platform-authenticators).
    -- These authenticators are not removable from the [client device](https://www.w3.org/TR/webauthn-2/#client-device).
    AuthenticatorTransportInternal
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports)
    -- An unknown authenticator transport. Note that according to the current
    -- version 2 of the WebAuthn standard, unknown fields [must be
    -- ignored](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-transports-slot),
    -- which is a bit misleading because such unknown values still need to be
    -- stored. Draft version 3 of the standard [fixes
    -- this](https://github.com/w3c/webauthn/pull/1654).
    AuthenticatorTransportUnknown Text
  deriving (Eq, Show, Ord, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON AuthenticatorTransport

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment)
-- This enumeration’s values describe [authenticators](https://www.w3.org/TR/webauthn-2/#authenticator)'
-- [attachment modalities](https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality).
-- [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) use this to
-- express a preferred [authenticator attachment modality](https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality)
-- when calling [@navigator.credentials.create()@](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- to [create a credential](https://www.w3.org/TR/webauthn-2/#sctn-createCredential).
--
-- To decode\/encode this type from\/to its standard string, use
-- 'Crypto.WebAuthn.Encoding.Strings.decodeAuthenticatorAttachment'/'Crypto.WebAuthn.Encoding.Strings.encodeAuthenticatorAttachment'.
data AuthenticatorAttachment
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattachment-platform)
    -- This value indicates [platform attachment](https://www.w3.org/TR/webauthn-2/#platform-attachment).
    AuthenticatorAttachmentPlatform
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattachment-cross-platform)
    -- This value indicates [cross-platform attachment](https://www.w3.org/TR/webauthn-2/#cross-platform-attachment).
    AuthenticatorAttachmentCrossPlatform
  deriving (Eq, Show, Bounded, Enum, Ord, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON AuthenticatorAttachment

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-residentkeyrequirement)
-- This enumeration’s values describe the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s
-- requirements for [client-side discoverable credentials](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential)
-- (formerly known as [resident credentials](https://www.w3.org/TR/webauthn-2/#resident-credential)
-- or [resident keys](https://www.w3.org/TR/webauthn-2/#resident-key)):
--
-- To decode\/encode this type from\/to its standard string, use
-- 'Crypto.WebAuthn.Encoding.Strings.decodeResidentKeyRequirement'/'Crypto.WebAuthn.Encoding.Strings.encodeResidentKeyRequirement'.
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
    -- in this case. This takes precedence over the setting of 'coaUserVerification'.
    ResidentKeyRequirementPreferred
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-residentkeyrequirement-required)
    -- This value indicates the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- requires a [client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential),
    -- and is prepared to receive an error if a
    -- [client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential) cannot be created.
    ResidentKeyRequirementRequired
  deriving (Eq, Show, Bounded, Enum, Ord, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON ResidentKeyRequirement

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement)
-- A [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) may
-- require [user verification](https://www.w3.org/TR/webauthn-2/#user-verification) for some
-- of its operations but not for others, and may use this type to express its needs.
--
-- To decode\/encode this type from\/to its standard string, use
-- 'Crypto.WebAuthn.Encoding.Strings.decodeUserVerificationRequirement'/'Crypto.WebAuthn.Encoding.Strings.encodeUserVerificationRequirement'.
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
  deriving (Eq, Show, Bounded, Enum, Ord, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON UserVerificationRequirement

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-attestation-convey)
-- [WebAuthn Relying Parties](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) may use
-- [AttestationConveyancePreference](https://www.w3.org/TR/webauthn-2/#enumdef-attestationconveyancepreference)
-- to specify their preference regarding
-- [attestation conveyance](https://www.w3.org/TR/webauthn-2/#attestation-conveyance) during credential generation.
--
-- To decode\/encode this type from\/to its standard string, use
-- 'Crypto.WebAuthn.Encoding.Strings.decodeAttestationConveyancePreference'/'Crypto.WebAuthn.Encoding.Strings.encodeAttestationConveyancePreference'.
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
  deriving (Eq, Show, Bounded, Enum, Ord, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON AttestationConveyancePreference

-- | [(spec)](https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint)
-- [WebAuthn Relying Parties](https://www.w3.org/TR/webauthn-3/#webauthn-relying-party) may use
-- this enumeration to communicate hints to the user-agent about how a request may be best completed.
-- These hints are not requirements, and do not bind the user-agent, but may guide it in providing
-- the best experience by using contextual information that the Relying Party has about the request.
-- Hints are provided in order of decreasing preference so, if two hints are contradictory,
-- the first one controls.
--
-- Note: It is important for backwards compatibility that client platforms and Relying Parties
-- handle unknown values, which is why 'PublicKeyCredentialHintUnknown' exists.
--
-- To decode\/encode this type from\/to its standard string, use
-- 'Crypto.WebAuthn.Encoding.Strings.decodePublicKeyCredentialHint'/'Crypto.WebAuthn.Encoding.Strings.encodePublicKeyCredentialHint'.
data PublicKeyCredentialHint
  = -- | [(spec)](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-security-key)
    -- Indicates that the Relying Party believes that users will satisfy this request with a physical
    -- security key. For example, an enterprise Relying Party may set this hint if they have issued
    -- security keys to their employees and will only accept those authenticators for registration
    -- and authentication.
    PublicKeyCredentialHintSecurityKey
  | -- | [(spec)](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-client-device)
    -- Indicates that the Relying Party believes that users will satisfy this request with a platform
    -- authenticator attached to the client device.
    PublicKeyCredentialHintClientDevice
  | -- | [(spec)](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-hybrid)
    -- Indicates that the Relying Party believes that users will satisfy this request with general-purpose
    -- authenticators such as smartphones. For example, a consumer Relying Party may believe that only
    -- a small fraction of their customers possesses dedicated security keys. This option also implies
    -- that the local platform authenticator should not be promoted in the UI.
    PublicKeyCredentialHintHybrid
  | -- | An unknown credential hint value. This allows for forward compatibility
    -- when new hint values are added to the specification.
    PublicKeyCredentialHintUnknown Text
  deriving (Eq, Show, Ord, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON PublicKeyCredentialHint

-- | An X.509 certificate chain that can be used to verify an attestation
-- statement
data AttestationChain (p :: ProtocolKind) where
  -- | For Fido 2, we can have a chain consisting of multiple certificates.
  Fido2Chain :: NonEmpty X509.SignedCertificate -> AttestationChain 'Fido2
  -- | For Fido U2F, we can only have a single certificate, which is then also
  -- used to generate the 'Crypto.WebAuthn.Identifier.SubjectKeyIdentifier' from
  FidoU2FCert :: X509.SignedCertificate -> AttestationChain 'FidoU2F

deriving instance Eq (AttestationChain p)

deriving instance Show (AttestationChain p)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON (AttestationChain p) where
  toJSON (Fido2Chain chain) = toJSON chain
  toJSON (FidoU2FCert cert) = toJSON [cert]

-- | An [attestation type](https://www.w3.org/TR/webauthn-2/#attestation-type)
-- that is verifiable, indicating that we can have trusted information about
-- the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) that
-- created the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential)
data VerifiableAttestationType
  = -- | [Attestation statements](https://www.w3.org/TR/webauthn-2/#attestation-statement)
    -- conveying [attestations](https://www.w3.org/TR/webauthn-2/#attestation) of
    -- [type](https://www.w3.org/TR/webauthn-2/#attestation-type)
    -- [AttCA](https://www.w3.org/TR/webauthn-2/#attca) or
    -- [AnonCA](https://www.w3.org/TR/webauthn-2/#anonca) use the same data
    -- structure as those of [type](https://www.w3.org/TR/webauthn-2/#attestation-type)
    -- [Basic](https://www.w3.org/TR/webauthn-2/#basic), so the three attestation
    -- types are, in general, distinguishable only with externally provided knowledge regarding the contents
    -- of the [attestation certificates](https://www.w3.org/TR/webauthn-2/#attestation-certificate)
    -- conveyed in the [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement).
    VerifiableAttestationTypeUncertain
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#basic-attestation)
    -- In the case of basic attestation [UAFProtocol](https://www.w3.org/TR/webauthn-2/#biblio-uafprotocol),
    -- the authenticator’s [attestation key pair](https://www.w3.org/TR/webauthn-2/#attestation-key-pair)
    -- is specific to an authenticator "model", i.e., a "batch" of authenticators.
    -- Thus, authenticators of the same, or similar, model often share the same
    -- [attestation key pair](https://www.w3.org/TR/webauthn-2/#attestation-key-pair).
    -- See [§ 14.4.1 Attestation Privacy](https://www.w3.org/TR/webauthn-2/#sctn-attestation-privacy)
    -- for further information.
    VerifiableAttestationTypeBasic
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#attca)
    -- In this case, an [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
    -- is based on a Trusted Platform Module (TPM) and holds an authenticator-specific
    -- "endorsement key" (EK). This key is used to securely communicate with a
    -- trusted third party, the [Attestation CA](https://www.w3.org/TR/webauthn-2/#attestation-ca)
    -- [TCG-CMCProfile-AIKCertEnroll](https://www.w3.org/TR/webauthn-2/#biblio-tcg-cmcprofile-aikcertenroll)
    -- (formerly known as a "Privacy CA"). The [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
    -- can generate multiple attestation identity key pairs (AIK) and requests an
    -- [Attestation CA](https://www.w3.org/TR/webauthn-2/#attestation-ca) to
    -- issue an AIK certificate for each. Using this approach, such an
    -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) can
    -- limit the exposure of the EK (which is a global correlation handle) to
    -- Attestation CA(s). AIKs can be requested for each
    -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)\-generated
    -- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential)
    -- individually, and conveyed to [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- as [attestation certificates](https://www.w3.org/TR/webauthn-2/#attestation-certificate).
    VerifiableAttestationTypeAttCA
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#anonca)
    -- In this case, the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
    -- uses an [Anonymization CA](https://www.w3.org/TR/webauthn-2/#anonymization-ca)
    -- which dynamically generates per-[credential](https://w3c.github.io/webappsec-credential-management/#concept-credential)
    -- [attestation certificates](https://www.w3.org/TR/webauthn-2/#attestation-certificate)
    -- such that the [attestation statements](https://www.w3.org/TR/webauthn-2/#attestation-statement)
    -- presented to [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- do not provide uniquely identifiable information, e.g., that might be used for tracking purposes.
    VerifiableAttestationTypeAnonCA
  deriving (Eq, Show, Bounded, Enum, Ord, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON VerifiableAttestationType

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-attestation-types)
-- WebAuthn supports several [attestation types](https://www.w3.org/TR/webauthn-2/#attestation-type),
-- defining the semantics of [attestation statements](https://www.w3.org/TR/webauthn-2/#attestation-statement)
-- and their underlying trust models:
data AttestationType (k :: AttestationKind) where
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#none)
  -- In this case, no attestation information is available. See also
  -- [§ 8.7 None Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-none-attestation).
  AttestationTypeNone :: AttestationType 'Unverifiable
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#self-attestation)
  -- In the case of [self attestation](https://www.w3.org/TR/webauthn-2/#self-attestation),
  -- also known as surrogate basic attestation [UAFProtocol](https://www.w3.org/TR/webauthn-2/#biblio-uafprotocol),
  -- the Authenticator does not have any specific [attestation key pair](https://www.w3.org/TR/webauthn-2/#attestation-key-pair).
  -- Instead it uses the [credential private key](https://www.w3.org/TR/webauthn-2/#credential-private-key)
  -- to create the [attestation signature](https://www.w3.org/TR/webauthn-2/#attestation-signature).
  -- Authenticators without meaningful protection measures for an
  -- [attestation private key](https://www.w3.org/TR/webauthn-2/#attestation-private-key)
  -- typically use this attestation type.
  AttestationTypeSelf :: AttestationType 'Unverifiable
  -- | Grouping of attestations that are verifiable by a certificate chain
  AttestationTypeVerifiable ::
    { -- | The type of verifiable attestation
      atvType :: VerifiableAttestationType,
      -- | The certificate chain of this attestation type, can be used to
      -- validate the authenticator model
      atvChain :: AttestationChain p
    } ->
    AttestationType ('Verifiable p)

deriving instance Eq (AttestationType k)

deriving instance Show (AttestationType k)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON (AttestationType k) where
  toJSON AttestationTypeNone =
    object
      [ "tag" .= String "AttestationTypeNone"
      ]
  toJSON AttestationTypeSelf =
    object
      [ "tag" .= String "AttestationTypeSelf"
      ]
  toJSON AttestationTypeVerifiable {..} =
    object
      [ "tag" .= String "AttestationTypeVerifiable",
        "atvType" .= atvType,
        "atvChain" .= atvChain
      ]

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
-- the caller’s [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin)'s
-- [effective domain](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain).
--
-- TODO: 'RpId' is used for both <https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id>
-- and <https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-rpid>, but the former
-- uses DOMString, while the latter uses USVString. Is this a bug in the spec or is there an actual difference?
newtype RpId = RpId {unRpId :: Text}
  deriving (Eq, Show, Ord)
  deriving newtype (IsString)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving newtype instance ToJSON RpId

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
-- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability)
-- identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
-- intended only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
--
-- - [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD perform
-- enforcement, as prescribed in Section 2.3 of [RFC8266](https://www.w3.org/TR/webauthn-2/#biblio-rfc8266)
-- for the Nickname Profile of the PRECIS FreeformClass [RFC8264](https://www.w3.org/TR/webauthn-2/#biblio-rfc8264),
-- when setting 'RelyingPartyName's value, or displaying the value to the user.
-- - This string MAY contain language and direction metadata. [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
-- SHOULD consider providing this information. See [§ 6.4.2 Language and Direction Encoding](https://www.w3.org/TR/webauthn-2/#sctn-strings-langdir)
-- about how this metadata is encoded.
newtype RelyingPartyName = RelyingPartyName {unRelyingPartyName :: Text}
  deriving (Eq, Show)
  deriving newtype (IsString)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving newtype instance ToJSON RelyingPartyName

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#user-handle)
-- The user handle is specified by a [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
-- as the value of 'id', and used to [map](https://www.w3.org/TR/webauthn-2/#authenticator-credentials-map)
-- a specific [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential)
-- to a specific user account with the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party).
-- Authenticators in turn [map](https://www.w3.org/TR/webauthn-2/#authenticator-credentials-map)
-- [RP IDs](https://www.w3.org/TR/webauthn-2/#rp-id) and user handle pairs to [public key credential sources](https://www.w3.org/TR/webauthn-2/#public-key-credential-source).
-- A user handle is an opaque [byte sequence](https://infra.spec.whatwg.org/#byte-sequence)
-- with a maximum size of 64 bytes, and is not meant to be displayed to the user.
newtype UserHandle = UserHandle {unUserHandle :: BS.ByteString}
  deriving (Eq, Show, Ord)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving via PrettyHexByteString instance ToJSON UserHandle

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#user-handle)
-- A user handle is an opaque [byte sequence](https://infra.spec.whatwg.org/#byte-sequence)
-- with a maximum size of 64 bytes, and is not meant to be displayed to the user.
generateUserHandle :: (MonadRandom m) => m UserHandle
generateUserHandle = UserHandle <$> getRandomBytes 16

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
-- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) name for the user account,
-- intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD
-- let the user choose this, and SHOULD NOT restrict the choice more than necessary.
--
-- - [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD perform
-- enforcement, as prescribed in Section 2.3 of [RFC8266](https://www.w3.org/TR/webauthn-2/#biblio-rfc8266)
-- for the Nickname Profile of the PRECIS FreeformClass [RFC8264](https://www.w3.org/TR/webauthn-2/#biblio-rfc8264),
-- when setting 'cueDisplayName's value, or displaying the value to the user.
-- - This string MAY contain language and direction metadata. [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
-- SHOULD consider providing this information. See [§ 6.4.2 Language and Direction Encoding](https://www.w3.org/TR/webauthn-2/#sctn-strings-langdir)
-- about how this metadata is encoded.
newtype UserAccountDisplayName = UserAccountDisplayName {unUserAccountDisplayName :: Text}
  deriving (Eq, Show)
  deriving newtype (IsString)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving newtype instance ToJSON UserAccountDisplayName

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
-- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) identifier for a user account.
-- It is intended only for display, i.e., aiding the user in determining the difference between user accounts with
-- similar 'cueDisplayName's. For example, "alexm", "alex.mueller@example.com" or "+14255551234".
--
-- - The [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) MAY let the user choose this value.
--   The [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD perform enforcement,
--   as prescribed in Section 3.4.3 of [RFC8265](https://www.w3.org/TR/webauthn-2/#biblio-rfc8265)
--   for the UsernameCasePreserved Profile of the PRECIS IdentifierClass
--   [RFC8264](https://www.w3.org/TR/webauthn-2/#biblio-rfc8264), when setting 'UserAccountName's value,
--   or displaying the value to the user.
-- - This string MAY contain language and direction metadata.
--   [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD consider providing this information.
--   See [§ 6.4.2 Language and Direction Encoding](https://www.w3.org/TR/webauthn-2/#sctn-strings-langdir)
--   about how this metadata is encoded.
newtype UserAccountName = UserAccountName {unUserAccountName :: Text}
  deriving (Eq, Show)
  deriving newtype (IsString)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving newtype instance ToJSON UserAccountName

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#credential-id)
-- A probabilistically-unique [byte sequence](https://infra.spec.whatwg.org/#byte-sequence)
-- identifying a [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential-source)
-- source and its [authentication assertions](https://www.w3.org/TR/webauthn-2/#authentication-assertion).
newtype CredentialId = CredentialId {unCredentialId :: BS.ByteString}
  deriving (Eq, Show, Ord)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving via PrettyHexByteString instance ToJSON CredentialId

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#credential-id)
-- Generates a random 'CredentialId' using 16 random bytes.
-- This is only useful for authenticators, not for relying parties.
-- This function is only included for completeness and testing purposes.
generateCredentialId :: (MonadRandom m) => m CredentialId
generateCredentialId = CredentialId <$> getRandomBytes 16

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
-- This member contains a challenge intended to be used for generating the newly
-- created credential’s attestation object. See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
-- security consideration.
newtype Challenge = Challenge {unChallenge :: BS.ByteString}
  deriving (Eq, Show, Ord)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving via PrettyHexByteString instance ToJSON Challenge

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
-- In order to prevent replay attacks, the challenges MUST contain enough entropy
-- to make guessing them infeasible. Challenges SHOULD therefore be at least 16 bytes long.
generateChallenge :: (MonadRandom m) => m Challenge
generateChallenge = Challenge <$> getRandomBytes 16

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
-- This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
-- This is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
newtype Timeout = Timeout {unTimeout :: Word32}
  deriving (Eq, Show)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving newtype instance ToJSON Timeout

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#assertion-signature)
-- An assertion signature is produced when the
-- [authenticatorGetAssertion](https://www.w3.org/TR/webauthn-2/#authenticatorgetassertion)
-- method is invoked. It represents an assertion by the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
-- that the user has [consented](https://www.w3.org/TR/webauthn-2/#user-consent)
-- to a specific transaction, such as logging in, or completing a purchase. Thus,
-- an [assertion signature](https://www.w3.org/TR/webauthn-2/#assertion-signature)
-- asserts that the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
-- possessing a particular [credential private key](https://www.w3.org/TR/webauthn-2/#credential-private-key)
-- has established, to the best of its ability, that the user requesting this transaction
-- is the same user who [consented](https://www.w3.org/TR/webauthn-2/#user-consent)
-- to creating that particular [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential).
-- It also asserts additional information, termed [client data](https://www.w3.org/TR/webauthn-2/#client-data),
-- that may be useful to the caller, such as the means by which
-- [user consent](https://www.w3.org/TR/webauthn-2/#user-consent) was provided,
-- and the prompt shown to the user by the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator).
-- The [assertion signature](https://www.w3.org/TR/webauthn-2/#assertion-signature)
-- format is illustrated in [Figure 4, below](https://www.w3.org/TR/webauthn-2/#fig-signature).
newtype AssertionSignature = AssertionSignature {unAssertionSignature :: BS.ByteString}
  deriving (Eq, Show)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving via PrettyHexByteString instance ToJSON AssertionSignature

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#rpidhash)
-- SHA-256 hash of the [RP ID](https://www.w3.org/TR/webauthn-2/#rp-id) the
-- [credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) is
-- [scoped](https://www.w3.org/TR/webauthn-2/#scope) to.
newtype RpIdHash = RpIdHash {unRpIdHash :: Digest SHA256}
  deriving (Eq, Show)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving newtype instance ToJSON RpIdHash

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#collectedclientdata-hash-of-the-serialized-client-data)
-- This is the hash (computed using SHA-256) of the [JSON-compatible serialization of client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data),
-- as constructed by the client.
newtype ClientDataHash = ClientDataHash {unClientDataHash :: Digest SHA256}
  deriving (Eq, Show)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving newtype instance ToJSON ClientDataHash

-- | [(spec)](https://html.spec.whatwg.org/multipage/origin.html#concept-origin)
newtype Origin = Origin {unOrigin :: Text}
  deriving (Eq, Show)
  deriving newtype (IsString)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving newtype instance ToJSON Origin

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#signcount)
-- [Signature counter](https://www.w3.org/TR/webauthn-2/#signature-counter)
newtype SignatureCounter = SignatureCounter {unSignatureCounter :: Word32}
  deriving (Eq, Show)
  deriving newtype (Num, Ord)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving newtype instance ToJSON SignatureCounter

-- | The encoding of a 'Cose.CosePublicKey'
newtype PublicKeyBytes = PublicKeyBytes {unPublicKeyBytes :: BS.ByteString}
  deriving (Eq, Show)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving via PrettyHexByteString instance ToJSON PublicKeyBytes

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-inputs)
-- This is a dictionary containing the [client extension input](https://www.w3.org/TR/webauthn-2/#client-extension-input)
-- values for zero or more [WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#webauthn-extensions).
-- TODO: Most extensions are not implemented by this library, see "Crypto.WebAuthn.Model.Types#extensions".
newtype AuthenticationExtensionsClientInputs = AuthenticationExtensionsClientInputs
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-credential-properties-extension)
    -- When true, indicates that that extension is requested by the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party).
    aeciCredProps :: Maybe Bool
  }
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-credentialpropertiesoutput)
-- This is a dictionary containing the client properties output.
newtype CredentialPropertiesOutput = CredentialPropertiesOutput
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-credentialpropertiesoutput-rk)
    -- The resident key credential property (i.e., client-side discoverable
    -- credential property), indicating whether the `[PublicKeyCredential](https://www.w3.org/TR/webauthn-2/#publickeycredential)`
    -- returned as a result of a registration ceremony is a client-side discoverable credential.
    cpoRk :: Maybe Bool
  }
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-outputs)
-- This is a dictionary containing the [client extension output](https://www.w3.org/TR/webauthn-2/#client-extension-output)
-- values for zero or more [WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#webauthn-extensions).
-- TODO: Most extensions are not implemented by this library, see "Crypto.WebAuthn.Model.Types#extensions".
newtype AuthenticationExtensionsClientOutputs = AuthenticationExtensionsClientOutputs
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-credential-properties-extension)
    -- When provided, indicates the value of the requireResidentKey parameter
    -- that was used in the [invocation](https://www.w3.org/TR/webauthn-2/#CreateCred-InvokeAuthnrMakeCred)
    -- of the `[authenticatorMakeCredential](https://www.w3.org/TR/webauthn-2/#authenticatormakecredential)` operation.
    aecoCredProps :: Maybe CredentialPropertiesOutput
  }
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticator-extension-output)
data AuthenticatorExtensionOutputs = AuthenticatorExtensionOutputs
  {
  }
  deriving (Eq, Show)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON AuthenticatorExtensionOutputs where
  toJSON _ = object []

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params)
-- The 'CredentialRpEntity' dictionary is used to supply additional
-- [Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) attributes when creating a new credential.
data CredentialRpEntity = CredentialRpEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id)
    -- A unique identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- entity, which sets the 'RpId'.
    creId :: Maybe RpId,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability)
    -- identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
    -- intended only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
    creName :: RelyingPartyName
  }
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON CredentialRpEntity

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-user-credential-params)
-- The 'CredentialUserEntity' dictionary is used to supply additional
-- user account attributes when creating a new credential.
data CredentialUserEntity = CredentialUserEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id)
    -- The 'UserHandle' of the user account entity.
    -- To ensure secure operation, authentication and authorization decisions MUST
    -- be made on the basis of this 'cueId' member, not the 'cueDisplayName' nor 'cueName' members.
    -- See Section 6.1 of [RFC8266](https://www.w3.org/TR/webauthn-2/#biblio-rfc8266).
    -- The 'UserHandle' MUST NOT contain personally identifying information about the user, such as a username
    -- or e-mail address; see [§ 14.6.1 User Handle Contents](https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy)
    -- for details. The user handle MUST NOT be empty, though it MAY be null.
    -- NOTE: We don't allow encoding it as null here, because it isn't an
    -- allowed value in the client, see <https://www.w3.org/TR/webauthn-2/#sctn-createCredential>
    -- This was confirmed and a fix was merged: <https://github.com/w3c/webauthn/pull/1600>
    cueId :: UserHandle,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) name for the user account,
    -- intended only for display. For example, "Alex Müller" or "田中倫".
    cueDisplayName :: UserAccountDisplayName,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) identifier for a user account.
    -- It is intended only for display, i.e., aiding the user in determining the difference between user
    -- accounts with similar 'cueDisplayName's. For example, "alexm", "alex.mueller@example.com" or "+14255551234".
    cueName :: UserAccountName
  }
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON CredentialUserEntity

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-params)
-- This dictionary is used to supply additional parameters when creating a new credential.
data CredentialParameters = CredentialParameters
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-type)
    -- This member specifies the type of credential to be created.
    cpTyp :: CredentialType,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-alg)
    -- This member specifies the cryptographic signature algorithm with which the newly
    -- generated credential will be used, and thus also the type of asymmetric
    -- key pair to be generated, e.g., RSA or Elliptic Curve.
    cpAlg :: Cose.CoseSignAlg
  }
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON CredentialParameters

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor)
-- This dictionary contains the attributes that are specified by a caller when referring to a
-- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) as an input parameter to the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) or
-- [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) methods.
-- It mirrors the fields of the 'Credential' object returned by the latter methods.
data CredentialDescriptor = CredentialDescriptor
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-type)
    -- This member contains the type of the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    cdTyp :: CredentialType,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-id)
    -- This member contains the [credential ID](https://www.w3.org/TR/webauthn-2/#credential-id) of the
    -- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    cdId :: CredentialId,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports)
    -- This OPTIONAL member contains a hint as to how the [client](https://www.w3.org/TR/webauthn-2/#client)
    -- might communicate with the [managing authenticator](https://www.w3.org/TR/webauthn-2/#public-key-credential-source-managing-authenticator)
    -- of the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    cdTransports :: Maybe [AuthenticatorTransport]
  }
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON CredentialDescriptor

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria)
-- [WebAuthn Relying Parties](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)
-- may use the 'AuthenticatorSelectionCriteria' dictionary to specify their
-- requirements regarding authenticator attributes.
data AuthenticatorSelectionCriteria = AuthenticatorSelectionCriteria
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-authenticatorattachment)
    -- If this member is present, eligible authenticators are filtered to
    -- only authenticators attached with the specified [§ 5.4.5 Authenticator
    -- Attachment Enumeration (enum AuthenticatorAttachment)](https://www.w3.org/TR/webauthn-2/#enum-attachment).
    ascAuthenticatorAttachment :: Maybe AuthenticatorAttachment,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
    -- Specifies the extent to which the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- desires to create a [client-side discoverable credential](https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential).
    -- For historical reasons the naming retains the deprecated “resident” terminology.
    -- The default value of this field is 'Crypto.WebAuthn.Model.Defaults.ascResidentKeyDefault'.
    ascResidentKey :: ResidentKeyRequirement,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification)
    -- This member describes the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s
    -- requirements regarding [user verification](https://www.w3.org/TR/webauthn-2/#user-verification)
    -- for the [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
    -- operation. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    -- The default value of this field is 'Crypto.WebAuthn.Model.Defaults.ascUserVerificationDefault'.
    ascUserVerification :: UserVerificationRequirement
  }
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON AuthenticatorSelectionCriteria

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#flags)
data AuthenticatorDataFlags = AuthenticatorDataFlags
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#concept-user-present)
    -- Upon successful completion of a [user presence test](https://www.w3.org/TR/webauthn-2/#test-of-user-presence),
    -- the user is said to be "[present](https://www.w3.org/TR/webauthn-2/#concept-user-present)".
    adfUserPresent :: Bool,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#concept-user-verified)
    -- Upon successful completion of a [user verification](https://www.w3.org/TR/webauthn-2/#user-verification) process,
    -- the user is said to be "[verified](https://www.w3.org/TR/webauthn-2/#concept-user-verified)".
    adfUserVerified :: Bool
  }
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON AuthenticatorDataFlags

-- | A type encompassing the credential options, both for
-- [creation](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
-- and
-- [requesting](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options).
-- The CeremonyKind araument specifies which.
--
-- Values of this type are send to the client to
-- [create](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- and
-- [get](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- a credential. After they have been sent, they have to be stored awaiting the
-- response from the client for further validation. At least the following
-- fields have to be stored, the others are not currently used.
--
--  For `Crypto.WebAuthn.Operation.Registration.verifyRegistrationResponse`:
--
-- - `corChallenge`
-- - `ascUserVerification` of `corAuthenticatorSelection`
-- - `corPubKeyCredParams`
-- - `corUser` (of which `cueId` is used in the
--   `Crypto.WebAuthn.Operation.Registration.verifyRegistrationResponse`, and it
--   and the other fields are need to be stored permanently by the relying party
--   as the user entity).
--
--  For `Crypto.WebAuthn.Operation.Authentication.verifyAuthenticationResponse`:
--
-- - `coaChallenge`
-- - `coaUserVerification`
-- - `coaAllowCredentials`
--
-- Depending on implementation choices by the RP, some of these fields might
-- additionally be constants, and could thus also be omitted when storing.
data CredentialOptions (c :: CeremonyKind) where
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
  CredentialOptionsRegistration ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-rp)
      -- This member contains data about the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
      -- responsible for the request.
      corRp :: CredentialRpEntity,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user)
      -- This member contains data about the user account for which the
      -- [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) is requesting attestation.
      corUser :: CredentialUserEntity,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-challenge)
      -- This member contains a challenge intended to be used for generating the newly created
      -- credential’s attestation object. See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
      -- security consideration.
      corChallenge :: Challenge,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-pubkeycredparams)
      -- This member contains information about the desired properties of the credential to be created.
      -- The sequence is ordered from most preferred to least preferred.
      -- The [client](https://www.w3.org/TR/webauthn-2/#client) makes a best-effort
      -- to create the most preferred credential that it can.
      corPubKeyCredParams :: [CredentialParameters],
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
      -- This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
      -- This is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
      corTimeout :: Maybe Timeout,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials)
      -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
      -- that wish to limit the creation of multiple credentials for the same account on a single authenticator.
      -- The [client](https://www.w3.org/TR/webauthn-2/#client) is requested to return an error if the new credential
      -- would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
      -- The default value of this field is 'Crypto.WebAuthn.Model.Defaults.corExcludeCredentialsDefault'.
      corExcludeCredentials :: [CredentialDescriptor],
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection)
      -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
      -- that wish to select the appropriate authenticators to participate in the
      -- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) operation.
      corAuthenticatorSelection :: Maybe AuthenticatorSelectionCriteria,
      -- | [(spec)](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-hints)
      -- This OPTIONAL member contains zero or more elements from 'PublicKeyCredentialHint' to
      -- guide the user agent in interacting with the user. Hints are provided in order of
      -- decreasing preference so, if two hints are contradictory, the first one controls.
      -- The default value of this field is 'Crypto.WebAuthn.Model.Defaults.corHintsDefault'.
      corHints :: [PublicKeyCredentialHint],
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-attestation)
      -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
      -- that wish to express their preference for [attestation conveyance](https://www.w3.org/TR/webauthn-2/#attestation-conveyance).
      -- The default value of this field is 'Crypto.WebAuthn.Model.Defaults.corAttestationDefault'.
      corAttestation :: AttestationConveyancePreference,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-extensions)
      -- This member contains additional parameters requesting additional processing by the client and authenticator.
      -- For example, the caller may request that only authenticators with certain capabilities be used to create the credential,
      -- or that particular information be returned in the [attestation object](https://www.w3.org/TR/webauthn-2/#attestation-object).
      -- Some extensions are defined in [§ 9 WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#sctn-extensions);
      -- consult the IANA "WebAuthn Extension Identifiers" registry [IANA-WebAuthn-Registries](https://www.w3.org/TR/webauthn-2/#biblio-iana-webauthn-registries)
      -- established by [RFC8809](https://www.w3.org/TR/webauthn-2/#biblio-rfc8809) for an up-to-date
      -- list of registered [WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#webauthn-extensions).
      -- TODO: Extensions are not implemented by this library, see "Crypto.WebAuthn.Model.Types#extensions".
      corExtensions :: Maybe AuthenticationExtensionsClientInputs
    } ->
    CredentialOptions 'Registration
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
  -- The 'CredentialOptionsAuthentication' dictionary supplies `[get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)`
  -- with the data it needs to generate an assertion.
  CredentialOptionsAuthentication ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge)
      -- This member represents a challenge that the selected [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) signs,
      -- along with other data, when producing an [authentication assertion](https://www.w3.org/TR/webauthn-2/#authentication-assertion).
      -- See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges) security consideration.
      coaChallenge :: Challenge,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-timeout)
      -- This OPTIONAL member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
      -- The value is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
      coaTimeout :: Maybe Timeout,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-rpid)
      -- This OPTIONAL member specifies the [relying party identifier](https://www.w3.org/TR/webauthn-2/#relying-party-identifier) claimed by the caller.
      -- If omitted, its value will be the `[CredentialsContainer](https://w3c.github.io/webappsec-credential-management/#credentialscontainer)`
      -- object’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object)'s
      -- [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin)'s
      -- [effective domain](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain).
      coaRpId :: Maybe RpId,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials)
      -- This OPTIONAL member contains a list of 'CredentialDescriptor'
      -- objects representing [public key credentials](https://www.w3.org/TR/webauthn-2/#public-key-credential) acceptable to the caller,
      -- in descending order of the caller’s preference (the first item in the list is the most preferred credential, and so on down the list).
      -- The default value of this field is 'Crypto.WebAuthn.Model.Defaults.coaAllowCredentialsDefault'.
      coaAllowCredentials :: [CredentialDescriptor],
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-userverification)
      -- This OPTIONAL member describes the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s requirements regarding
      -- [user verification](https://www.w3.org/TR/webauthn-2/#user-verification) for the
      -- `[get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)` operation.
      -- The default value of this field is 'Crypto.WebAuthn.Model.Defaults.coaUserVerificationDefault'.
      coaUserVerification :: UserVerificationRequirement,
      -- | [(spec)](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-hints)
      -- This OPTIONAL member contains zero or more elements from 'PublicKeyCredentialHint' to
      -- guide the user agent in interacting with the user. Hints are provided in order of
      -- decreasing preference so, if two hints are contradictory, the first one controls.
      -- The default value of this field is 'Crypto.WebAuthn.Model.Defaults.coaHintsDefault'.
      coaHints :: [PublicKeyCredentialHint],
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-extensions)
      -- This OPTIONAL member contains additional parameters requesting additional processing by the client and authenticator.
      -- For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
      -- TODO: Extensions are not implemented by this library, see "Crypto.WebAuthn.Model.Types#extensions".
      coaExtensions :: Maybe AuthenticationExtensionsClientInputs
    } ->
    CredentialOptions 'Authentication

deriving instance Eq (CredentialOptions c)

deriving instance Show (CredentialOptions c)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON (CredentialOptions c) where
  toJSON CredentialOptionsRegistration {..} =
    object
      [ "tag" .= String "CredentialOptionsRegistration",
        "corRp" .= corRp,
        "corUser" .= corUser,
        "corChallenge" .= corChallenge,
        "corPubKeyCredParams" .= corPubKeyCredParams,
        "corTimeout" .= corTimeout,
        "corExcludeCredentials" .= corExcludeCredentials,
        "corAuthenticatorSelection" .= corAuthenticatorSelection,
        "corHints" .= corHints,
        "corAttestation" .= corAttestation,
        "corExtensions" .= corExtensions
      ]
  toJSON CredentialOptionsAuthentication {..} =
    object
      [ "tag" .= String "CredentialOptionsAuthentication",
        "coaChallenge" .= coaChallenge,
        "coaTimeout" .= coaTimeout,
        "coaRpId" .= coaRpId,
        "coaAllowCredentials" .= coaAllowCredentials,
        "coaUserVerification" .= coaUserVerification,
        "coaHints" .= coaHints,
        "coaExtensions" .= coaExtensions
      ]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
-- The client data represents the contextual bindings of both the
-- [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)
-- and the [client](https://www.w3.org/TR/webauthn-2/#client).
--
-- For binary serialization of thes type, see
-- "Crypto.WebAuthn.Encoding.Binary". If decoded with
-- 'Crypto.WebAuthn.Encoding.Binary.decodeCollectedClientData', the
-- 'ccdRawData' field is filled out with the raw bytes, while
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawCollectedClientData' can be used
-- to fill out this field when constructing this value otherwise. Unchecked
-- invariant: If @raw ~ 'True'@, then
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawCollectedClientData c = c',
-- ensuring that the 'ccdRawData' field should always correspond to its
-- encoding. This means that if @raw ~ 'True'@, it's not safe to modify
-- individual fields. To make changes, first use
-- 'Crypto.WebAuthn.Encoding.Binary.stripRawCollectedClientData', make the
-- changes on the result, then call
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawCollectedClientData' on that. Note
-- however that any modifications also invalidate signatures over the binary
-- data, specifically 'araSignature' and 'aoAttStmt'.
data CollectedClientData (c :: CeremonyKind) raw = CollectedClientData
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-challenge)
    -- This member contains the challenge provided by the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party).
    -- See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges) security consideration.
    ccdChallenge :: Challenge,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-origin)
    -- This member contains the fully qualified [origin](https://html.spec.whatwg.org/multipage/origin.html#concept-origin)
    -- of the requester, as provided to the authenticator by the client, in the syntax
    -- defined by [RFC6454](https://www.w3.org/TR/webauthn-2/#biblio-rfc6454).
    ccdOrigin :: Origin,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-crossorigin)
    -- This member contains the inverse of the @sameOriginWithAncestors@ araument value
    -- that was passed into the [internal method](https://tc39.github.io/ecma262/#sec-object-internal-methods-and-internal-slots).
    ccdCrossOrigin :: Maybe Bool,
    -- | Raw data of the client data, for verification purposes.
    ccdRawData :: RawField raw
    -- TODO: This library does not implement token binding, this is in
    -- anticipation of version 3 of the webauthn spec that likely removes this
    -- field in its entirety. Discussion can be found in
    -- [the relevant PR](https://github.com/w3c/webauthn/pull/1630).
    -- Chromium and Firefox both don't propagate this field.
    -- Once v3 of the webauthn has been released, and this library is updated
    -- to the new spec, this field and related references can be removed.
    -- tokenBinding :: Maybe TokenBinding,
  }
  deriving (Eq, Show)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance (SingI c) => ToJSON (CollectedClientData (c :: CeremonyKind) raw) where
  toJSON CollectedClientData {..} =
    object
      [ "webauthnKind" .= sing @c,
        "ccdChallenge" .= ccdChallenge,
        "ccdOrigin" .= ccdOrigin,
        "ccdCrossOrigin" .= ccdCrossOrigin,
        "ccdRawData" .= ccdRawData
      ]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data)
-- Attested credential data is a variable-length byte array added to the
-- [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
-- when generating an [attestation object](https://www.w3.org/TR/webauthn-2/#attestation-object)
-- for a given credential.
data AttestedCredentialData (c :: CeremonyKind) raw where
  AttestedCredentialData ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#aaguid)
      acdAaguid :: AAGUID,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#credentialid)
      acdCredentialId :: CredentialId,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#credentialpublickey)
      acdCredentialPublicKey :: Cose.CosePublicKey,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#credentialpublickey)
      acdCredentialPublicKeyBytes :: RawField raw
    } ->
    AttestedCredentialData 'Registration raw
  NoAttestedCredentialData ::
    AttestedCredentialData 'Authentication raw

deriving instance Eq (AttestedCredentialData c raw)

deriving instance Show (AttestedCredentialData c raw)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON (AttestedCredentialData c raw) where
  toJSON AttestedCredentialData {..} =
    object
      [ "acdAaguid" .= acdAaguid,
        "acdCredentialId" .= acdCredentialId,
        "acdCredentialPublicKey" .= acdCredentialPublicKey,
        "acdCredentialPublicKeyBytes" .= acdCredentialPublicKeyBytes
      ]
  toJSON NoAttestedCredentialData {} = Null

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data)
-- The authenticator data structure encodes contextual bindings made by the
-- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator). These
-- bindings are controlled by the authenticator itself, and derive their trust
-- from the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)'s
-- assessment of the security properties of the authenticator. In one extreme case,
-- the authenticator may be embedded in the client, and its bindings may be no
-- more trustworthy than the [client data](https://www.w3.org/TR/webauthn-2/#client-data).
-- At the other extreme, the authenticator may be a discrete entity with high-security
-- hardware and software, connected to the client over a secure channel. In both cases,
-- the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) receives
-- the [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
-- in the same format, and uses its knowledge of the authenticator to make trust decisions.
--
-- For the binary serialization of this type, see
-- "Crypto.WebAuthn.Encoding.Binary". If decoded with
-- 'Crypto.WebAuthn.Encoding.Binary.decodeAuthenticatorData', the 'adRawData'
-- field is filled out with the binary serialization, while
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawAuthenticatorData' can be used to
-- fill out this field when constructing this value otherwise. This also
-- applies to raw 'acdCredentialPublicKeyBytes' field in
-- 'adAttestedCredentialData'. Unchecked invariant: If @raw ~ 'True'@, then
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawAuthenticatorData d = d', ensuring
-- that the 'adRawData' and 'acdCredentialPublicKeyBytes' fields should always
-- correspond to their respective binary serializations. This means that if
-- @raw ~ 'True'@, it's not safe to modify individual fields. To make changes,
-- first use 'Crypto.WebAuthn.Encoding.Binary.stripRawAuthenticatorData', make
-- the changes on the result, then call
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawAuthenticatorData' on that. Note
-- however that any modifications also invalidate signatures over the binary
-- data, specifically 'araSignature' and 'aoAttStmt'.
data AuthenticatorData (c :: CeremonyKind) raw = AuthenticatorData
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#rpidhash)
    -- SHA-256 hash of the [RP ID](https://www.w3.org/TR/webauthn-2/#rp-id) the
    -- [credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) is
    -- [scoped](https://www.w3.org/TR/webauthn-2/#scope) to.
    adRpIdHash :: RpIdHash,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#flags)
    adFlags :: AuthenticatorDataFlags,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#signcount)
    -- [Signature counter](https://www.w3.org/TR/webauthn-2/#signature-counter)
    adSignCount :: SignatureCounter,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#attestedcredentialdata)
    -- [attested credential data](https://www.w3.org/TR/webauthn-2/#attested-credential-data) (if present)
    adAttestedCredentialData :: AttestedCredentialData c raw,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#authdataextensions)
    -- Extension-defined [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
    adExtensions :: Maybe AuthenticatorExtensionOutputs,
    -- | Raw encoded data for verification purposes
    adRawData :: RawField raw
  }
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON (AuthenticatorData c raw)

-- | The result from verifying an attestation statement.
-- Either the result is verifiable, in which case @k ~ 'Verifiable'@, the
-- 'AttestationType' contains a verifiable certificate chain.
-- Or the result is not verifiable, in which case @k ~ 'Unverifiable'@, the
-- 'AttestationType' is None or Self.
data SomeAttestationType = forall k. SomeAttestationType (AttestationType k)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats)
-- This class is used to specify an [attestation statement format](https://www.w3.org/TR/webauthn-2/#attestation-statement-format)'s
-- [identifier](https://www.w3.org/TR/webauthn-2/#sctn-attstn-fmt-ids)
-- and [attestation statement structure](https://www.w3.org/TR/webauthn-2/#attestation-statement)
class
  ( Eq (AttStmt a),
    Show (AttStmt a),
    ToJSON (AttStmt a),
    Typeable a,
    Show a,
    Exception (AttStmtVerificationError a)
  ) =>
  AttestationStatementFormat a
  where
  -- | The type of a fully-decoded and structurally valid attestation statement
  type AttStmt a :: Type

  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-attstn-fmt-ids)
  -- Attestation statement formats are identified by a string, called an attestation
  -- statement format identifier, chosen by the author of the
  -- [attestation statement format](https://www.w3.org/TR/webauthn-2/#attestation-statement-format).
  --
  -- Attestation statement format identifiers SHOULD be registered in the IANA "WebAuthn Attestation Statement Format Identifiers" registry
  -- [IANA-WebAuthn-Registries](https://www.w3.org/TR/webauthn-2/#biblio-iana-webauthn-registries)
  -- established by [RFC8809](https://www.w3.org/TR/webauthn-2/#biblio-rfc8809).
  -- All registered attestation statement format identifiers are unique amongst
  -- themselves as a matter of course.
  --
  -- Unregistered attestation statement format identifiers SHOULD use lowercase
  -- reverse domain-name naming, using a domain name registered by the developer,
  -- in order to assure uniqueness of the identifier. All attestation statement
  -- format identifiers MUST be a maximum of 32 octets in length and MUST
  -- consist only of printable USASCII characters, excluding backslash and
  -- doublequote, i.e., VCHAR as defined in [RFC5234](https://www.w3.org/TR/webauthn-2/#biblio-rfc5234)
  -- but without %x22 and %x5c.
  --
  -- Note: This means attestation statement format identifiers based on domain
  -- names MUST incorporate only LDH Labels [RFC5890](https://www.w3.org/TR/webauthn-2/#biblio-rfc5890).
  --
  -- Attestation statement formats that may exist in multiple versions SHOULD
  -- include a version in their identifier. In effect, different versions are
  -- thus treated as different formats, e.g., @packed2@ as a new version of the
  -- [§ 8.2 Packed Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation).
  asfIdentifier :: a -> Text

  -- | The type of verification errors that can occur when verifying this
  -- attestation statement using 'asfVerify'
  type AttStmtVerificationError a :: Type

  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#verification-procedure)
  -- The procedure to verify an [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement)
  asfVerify ::
    a ->
    HG.DateTime ->
    AttStmt a ->
    AuthenticatorData 'Registration 'True ->
    ClientDataHash ->
    Validation (NonEmpty (AttStmtVerificationError a)) SomeAttestationType

  -- | The trusted root certificates specifically for this attestation
  -- statement format. For attestation statement chain validation, these
  -- certificates are used, in addition to the ones from the metadata registry
  --
  -- [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential) step 20:
  -- If validation is successful, obtain a list of acceptable trust anchors
  -- (i.e. attestation root certificates) for that attestation type and
  -- attestation statement format fmt, from a trusted source or from policy.
  --
  -- While for the attestation statement formats we implement, none of them use
  -- the 'VerifiableAttestationType', it is implied that it could be used by
  -- the above sentence from the spec.
  asfTrustAnchors ::
    a ->
    VerifiableAttestationType ->
    X509.CertificateStore

  -- | A decoder for the attestation statement [syntax](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats).
  -- The @attStmt@ CBOR map is given as an input. See
  -- [Generating an Attestation Object](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
  asfDecode ::
    a ->
    HashMap Text CBOR.Term ->
    Either Text (AttStmt a)

  -- | An encoder for the attestation statement [syntax](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats).
  -- The @attStmt@ CBOR map is expected as the result. See
  -- [Generating an Attestation Object](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
  asfEncode ::
    a ->
    AttStmt a ->
    CBOR.Term

-- | An arbitrary [attestation statement format](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats).
-- In contrast to 'AttestationStatementFormat', this type can be put into a list.
-- This is used for 'singletonAttestationStatementFormat'
data SomeAttestationStatementFormat
  = forall a.
    (AttestationStatementFormat a) =>
    SomeAttestationStatementFormat a

-- | A type representing the set of supported attestation statement formats.
-- The constructor is intentionally not exported, use
-- 'singletonAttestationStatementFormat' instead to construct it and
-- 'lookupAttestationStatementFormat' to look up formats. '<>' can be used to
-- combine multiple formats. 'mempty' can be used for not supporting any formats.
newtype SupportedAttestationStatementFormats
  = -- HashMap invariant: asfIdentifier (hm ! k) == k
    SupportedAttestationStatementFormats (HashMap Text SomeAttestationStatementFormat)
  deriving newtype (Semigroup, Monoid)

-- | Creates a `SupportedAttestationStatementFormats`-Map containing a single
-- supported format.
singletonAttestationStatementFormat :: SomeAttestationStatementFormat -> SupportedAttestationStatementFormats
singletonAttestationStatementFormat someFormat@(SomeAttestationStatementFormat format) =
  SupportedAttestationStatementFormats $ HashMap.singleton (asfIdentifier format) someFormat

-- | Attempt to find the desired attestation statement format in a map of
-- supported formats. Can then be used to perform attestation.
lookupAttestationStatementFormat ::
  -- | The desired format, e.g. "android-safetynet" or "none"
  Text ->
  -- | The [attestation statement formats](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats)
  -- that should be supported. The value of 'Crypto.WebAuthn.allSupportedFormats'
  -- can be passed here, but additional or custom formats may also be used if needed.
  SupportedAttestationStatementFormats ->
  Maybe SomeAttestationStatementFormat
lookupAttestationStatementFormat id (SupportedAttestationStatementFormats sasf) = sasf !? id

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#attestation-object)
--
-- For the [binary
-- serialization](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
-- of this type, see "Crypto.WebAuthn.Encoding.Binary". If decoded with
-- 'Crypto.WebAuthn.Encoding.Binary.decodeAttestationObject', the 'aoAuthData'
-- field is filled out with the binary serialization of its fields, while
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawAttestationObject' can be used to
-- fill out this field when constructing this value otherwise. Unchecked
-- invariant: If @raw ~ 'True'@, then
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawAttestationObject o = o', ensuring
-- that the binary fields of the 'aoAuthData' field should always correspond to
-- their respective serializations. This means that if @raw ~ 'True'@, it's not
-- safe to modify individual fields. To make changes, first use
-- 'Crypto.WebAuthn.Encoding.Binary.stripRawAttestationObject', make the
-- changes on the result, then call
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawAttestationObject' on that. Note
-- however that any modifications also invalidate signatures over the binary
-- data, specifically 'aoAttStmt'. The
-- 'Crypto.WebAuthn.Encoding.Binary.encodeAttestationObject' can be used to get
-- the binary encoding of this type when @raw ~ 'True'@.
data AttestationObject raw = forall a.
  (AttestationStatementFormat a) =>
  AttestationObject
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticator-data)
    -- The authenticator data structure encodes contextual bindings made by the
    -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator).
    -- These bindings are controlled by the authenticator itself, and derive
    -- their trust from the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)'s
    -- assessment of the security properties of the authenticator. In one
    -- extreme case, the authenticator may be embedded in the client, and its
    -- bindings may be no more trustworthy than the [client data](https://www.w3.org/TR/webauthn-2/#client-data).
    -- At the other extreme, the authenticator may be a discrete entity with high-security hardware
    -- and software, connected to the client over a secure channel. In both cases,
    -- the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) receives
    -- the [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
    -- in the same format, and uses its knowledge of the authenticator to make trust decisions.
    aoAuthData :: AuthenticatorData 'Registration raw,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#attestation-statement-format)
    -- The attestation statement format is the manner in which the signature is
    -- represented and the various contextual bindings are incorporated into
    -- the attestation statement by the
    -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator). In
    -- other words, this defines the syntax of the statement. Various existing
    -- components and OS platforms (such as TPMs and the Android OS) have
    -- previously defined [attestation statement
    -- formats](https://www.w3.org/TR/webauthn-2/#attestation-statement-format).
    -- This specification supports a variety of such formats in an extensible
    -- way, as defined in [§ 6.5.2 Attestation Statement
    -- Formats](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats).
    -- The formats themselves are identified by strings, as described in [§ 8.1
    -- Attestation Statement Format
    -- Identifiers](https://www.w3.org/TR/webauthn-2/#sctn-attstn-fmt-ids).
    --
    -- This value is of a type that's an instance of
    -- 'AttestationStatementFormat', which encodes everything needed about the
    -- attestation statement.
    aoFmt :: a,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#attestation-statement)
    -- The [(spec)](https://www.w3.org/TR/webauthn-2/#attestation-statement) is
    -- a specific type of signed data object, containing statements about a
    -- [public key
    -- credential](https://www.w3.org/TR/webauthn-2/#public-key-credential)
    -- itself and the
    -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) that
    -- created it. It contains an [attestation
    -- signature](https://www.w3.org/TR/webauthn-2/#attestation-signature)
    -- created using the key of the attesting authority (except for the case of
    -- [self attestation](https://www.w3.org/TR/webauthn-2/#self-attestation),
    -- when it is created using the [credential private
    -- key](https://www.w3.org/TR/webauthn-2/#credential-private-key)).
    aoAttStmt :: AttStmt a
  }

instance Eq (AttestationObject raw) where
  AttestationObject {aoAuthData = lAuthData, aoFmt = lFmt, aoAttStmt = lAttStmt}
    == AttestationObject {aoAuthData = rAuthData, aoFmt = rFmt, aoAttStmt = rAttStmt} =
      lAuthData == rAuthData
        -- We need to use some simple reflection in order to be able to compare the attestation statements
        && case eqTypeRep (typeOf lFmt) (typeOf rFmt) of
          Just HRefl -> lAttStmt == rAttStmt
          Nothing -> False

deriving instance Show (AttestationObject raw)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON (AttestationObject raw) where
  toJSON AttestationObject {..} =
    object
      [ "aoAuthData" .= aoAuthData,
        "aoFmt" .= asfIdentifier aoFmt,
        "aoAttStmt" .= aoAttStmt
      ]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticatorresponse)
-- [Authenticators](https://www.w3.org/TR/webauthn-2/#authenticator) respond to
-- [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) requests by
-- returning an object derived from the `[AuthenticatorResponse](https://www.w3.org/TR/webauthn-2/#authenticatorresponse)` interface
data AuthenticatorResponse (c :: CeremonyKind) raw where
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse)
  -- The [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse)
  -- interface represents the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)'s response
  -- to a client’s request for the creation of a new
  -- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential).
  -- It contains information about the new credential that can be used to identify
  -- it for later use, and metadata that can be used by the
  -- [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)
  -- to assess the characteristics of the credential during registration.
  AuthenticatorResponseRegistration ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
      -- This attribute, inherited from `[AuthenticatorResponse](https://www.w3.org/TR/webauthn-2/#authenticatorresponse)`,
      -- contains the [JSON-compatible serialization of client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data)
      -- (see [§ 6.5 Attestation](https://www.w3.org/TR/webauthn-2/#sctn-attestation))
      -- passed to the authenticator by the client in order to generate this credential.
      -- The exact JSON serialization MUST be preserved, as the
      -- [hash of the serialized client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-hash-of-the-serialized-client-data) has been computed over it.
      arrClientData :: CollectedClientData 'Registration raw,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject)
      -- This attribute contains an [attestation object](https://www.w3.org/TR/webauthn-2/#attestation-object),
      -- which is opaque to, and cryptographically protected against tampering by, the client.
      -- The [attestation object](https://www.w3.org/TR/webauthn-2/#attestation-object) contains both
      -- [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data) and an
      -- [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement).
      -- The former contains the AAGUID, a unique [credential ID](https://www.w3.org/TR/webauthn-2/#credential-id),
      -- and the [credential public key](https://www.w3.org/TR/webauthn-2/#credential-public-key).
      -- The contents of the [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement)
      -- are determined by the [attestation statement format](https://www.w3.org/TR/webauthn-2/#attestation-statement-format)
      -- used by the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator).
      -- It also contains any additional information that the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s
      -- server requires to validate the [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement),
      -- as well as to decode and validate the [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
      -- along with the [JSON-compatible serialization of client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data).
      -- For more details, see [§ 6.5 Attestation](https://www.w3.org/TR/webauthn-2/#sctn-attestation),
      -- [§ 6.5.4 Generating an Attestation Object](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object),
      -- and [Figure 6](https://www.w3.org/TR/webauthn-2/#fig-attStructs).
      arrAttestationObject :: AttestationObject raw,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-gettransports)
      -- This [internal slot](https://tc39.github.io/ecma262/#sec-object-internal-methods-and-internal-slots)
      -- contains a sequence of zero or more unique `[DOMString](https://heycam.github.io/webidl/#idl-DOMString)`s
      -- in lexicoaraphical order. These values are the transports that the
      -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) is believed to support,
      -- or an empty sequence if the information is unavailable.
      arrTransports :: [AuthenticatorTransport]
    } ->
    AuthenticatorResponse 'Registration raw
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse)
  -- The [AuthenticatorAssertionResponse](https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse) interface represents an
  -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)'s response
  -- to a client’s request for generation of a new
  -- [authentication assertion](https://www.w3.org/TR/webauthn-2/#authentication-assertion)
  -- given the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)'s
  -- challenge and OPTIONAL list of credentials it is aware of. This response
  -- contains a cryptographic signature proving possession of the
  -- [credential private key](https://www.w3.org/TR/webauthn-2/#credential-private-key),
  -- and optionally evidence of [user consent](https://www.w3.org/TR/webauthn-2/#user-consent)
  -- to a specific transaction.
  AuthenticatorResponseAuthentication ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
      -- This attribute, inherited from `[AuthenticatorResponse](https://www.w3.org/TR/webauthn-2/#authenticatorresponse)`,
      -- contains the [JSON-compatible serialization of client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data)
      -- (see [§ 6.5 Attestation](https://www.w3.org/TR/webauthn-2/#sctn-attestation))
      -- passed to the authenticator by the client in order to generate this credential.
      -- The exact JSON serialization MUST be preserved, as the
      -- [hash of the serialized client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-hash-of-the-serialized-client-data) has been computed over it.
      araClientData :: CollectedClientData 'Authentication raw,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata)
      -- This attribute contains the [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
      -- returned by the authenticator. See [§ 6.1 Authenticator Data](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data).
      araAuthenticatorData :: AuthenticatorData 'Authentication raw,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-signature)
      -- This attribute contains the raw [assertion
      -- signature](https://www.w3.org/TR/webauthn-2/#assertion-signature)
      -- returned from the authenticator.
      -- See [§ 6.3.3 The authenticatorGetAssertion Operation](https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion).
      araSignature :: AssertionSignature,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-userhandle)
      -- This attribute contains the [user handle](https://www.w3.org/TR/webauthn-2/#user-handle)
      -- returned from the authenticator, or null if the authenticator did not return a
      -- [user handle](https://www.w3.org/TR/webauthn-2/#user-handle). See
      -- [§ 6.3.3 The authenticatorGetAssertion Operation](https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion).
      araUserHandle :: Maybe UserHandle
    } ->
    AuthenticatorResponse 'Authentication raw

deriving instance Eq (AuthenticatorResponse c raw)

deriving instance Show (AuthenticatorResponse c raw)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON (AuthenticatorResponse c raw) where
  toJSON AuthenticatorResponseRegistration {..} =
    object
      [ "arrClientData" .= arrClientData,
        "arrAttestationObject" .= arrAttestationObject
      ]
  toJSON AuthenticatorResponseAuthentication {..} =
    object
      [ "araClientData" .= araClientData,
        "araAuthenticatorData" .= araAuthenticatorData,
        "araSignature" .= araSignature,
        "araUserHandle" .= araUserHandle
      ]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- The 'Credential' interface contains the attributes that are returned to the caller when a new credential is created, or a new assertion is requested.
--
-- This type has nested fields which use a binary encoding that needs to be
-- preserved for verification purposes. The binary encoding of these fields can
-- be removed or recomputed using functions from
-- "Crypto.WebAuthn.Encoding.Binary". Specifically
-- 'Crypto.WebAuthn.Encoding.Binary.stripRawCredential' and
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawCredential' respectively.
-- Unchecked invariant: If @raw ~ 'True'@, then
-- 'Crypto.WebAuthn.Encoding.Binary.encodeRawCredential c = c', ensuring that
-- the binary fields should always correspond to the values respective
-- serializations. This means that if @raw ~ 'True'@, it's not safe to modify
-- individual fields. To make changes, first use
-- 'Crypto.WebAuthn.Encoding.Binary.stripRawCredential', make the changes on
-- the result, then call 'Crypto.WebAuthn.Encoding.Binary.encodeRawCredential'
-- on that. Note however that any modifications also invalidate signatures over
-- the binary data, specifically 'araSignature' and 'aoAttStmt'.
data Credential (c :: CeremonyKind) raw = Credential
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-identifier-slot)
    -- Contains the [credential ID](https://www.w3.org/TR/webauthn-2/#credential-id),
    -- chosen by the authenticator. The [credential ID](https://www.w3.org/TR/webauthn-2/#credential-id)
    -- is used to look up credentials for use, and is therefore expected to be globally
    -- unique with high probability across all credentials of the same type, across all authenticators.
    cIdentifier :: CredentialId,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-response)
    -- This attribute contains the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)'s
    -- response to the client’s request to either create a [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential),
    -- or generate an [authentication assertion](https://www.w3.org/TR/webauthn-2/#authentication-assertion).
    -- If the `[PublicKeyCredential](https://www.w3.org/TR/webauthn-2/#publickeycredential)`
    -- is created in response to `[create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)`,
    -- this attribute’s value will be an `[AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse)`,
    -- otherwise, the `[PublicKeyCredential](https://www.w3.org/TR/webauthn-2/#publickeycredential)`
    -- was created in response to `[get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)`,
    -- and this attribute’s value will be an `[AuthenticatorAssertionResponse](https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse)`.
    cResponse :: AuthenticatorResponse c raw,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-getclientextensionresults)
    -- This operation returns the value of `[[[clientExtensionsResults]]](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-clientextensionsresults-slot)`,
    -- which is a [map](https://infra.spec.whatwg.org/#ordered-map) containing
    -- [extension identifier](https://www.w3.org/TR/webauthn-2/#extension-identifier) →
    -- [client extension output](https://www.w3.org/TR/webauthn-2/#client-extension-output) entries produced
    -- by the extension’s [client extension processing](https://www.w3.org/TR/webauthn-2/#client-extension-processing).
    cClientExtensionResults :: AuthenticationExtensionsClientOutputs
  }
  deriving (Eq, Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON (Credential c raw)
