{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- |
-- This module contains the same top-level definitions as 'Crypto.WebAuthn.Client.JavaScript',
-- but with the types containing a more Haskell-friendly structure.
--
-- Note: The 'ToJSON' instances of these types are for pretty-printing purposes
-- only.
module Crypto.WebAuthn.Model
  ( -- * Enumerations
    PublicKeyCredentialType (..),
    AuthenticatorTransport (..),
    AuthenticatorAttachment (..),
    ResidentKeyRequirement (..),
    UserVerificationRequirement (..),
    AttestationConveyancePreference (..),
    AttestationChain (..),
    AttestationKind (..),
    AttestationType (..),
    VerifiableAttestationType (..),
    AuthenticatorIdentifier (..),

    -- * Newtypes
    AAGUID (..),
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

    -- * Extensions (unimplemented)
    AuthenticationExtensionsClientInputs (..),
    AuthenticationExtensionsClientOutputs (..),
    AuthenticatorExtensionOutputs (..),

    -- * Dictionaries
    PublicKeyCredentialRpEntity (..),
    PublicKeyCredentialUserEntity (..),
    PublicKeyCredentialParameters (..),
    PublicKeyCredentialDescriptor (..),
    AuthenticatorSelectionCriteria (..),
    AuthenticatorDataFlags (..),
    CollectedClientData (..),
    AttestedCredentialData (..),
    AuthenticatorData (..),
    AttestationObject (..),
    AuthenticatorResponse (..),
    AttestationStatementFormat (..),
    SomeAttestationType (..),
    SomeAttestationStatementFormat (..),
    SupportedAttestationStatementFormats,

    -- * Utility functions
    sasfSingleton,
    sasfLookup,

    -- * Raw fields
    RawField (..),

    -- * Top-level types
    PublicKeyCredentialOptions (..),
    PublicKeyCredential (..),

    -- * Reexports
    module Crypto.WebAuthn.Model.Kinds,
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Crypto.Hash (Digest)
import Crypto.Hash.Algorithms (SHA256)
import Crypto.Random (MonadRandom, getRandomBytes)
import Crypto.WebAuthn.Model.Kinds
  ( AttestationKind (Unverifiable, Verifiable),
    ProtocolKind (Fido2, FidoU2F),
    SProtocolKind (SFido2, SFidoU2F),
    SWebauthnKind (SCreate, SGet),
    WebauthnKind (Create, Get),
  )
import Crypto.WebAuthn.PublicKey (COSEAlgorithmIdentifier, PublicKey)
import Crypto.WebAuthn.SubjectKeyIdentifier (SubjectKeyIdentifier)
import Crypto.WebAuthn.ToJSONOrphans ()
import Data.Aeson (ToJSON, Value (Null, String), object, (.=))
import Data.Aeson.Types (toJSON)
import qualified Data.ByteString as BS
import Data.HashMap.Strict (HashMap, (!?))
import qualified Data.HashMap.Strict as HashMap
import Data.Hashable (Hashable)
import Data.Kind (Type)
import Data.List.NonEmpty (NonEmpty)
import Data.Singletons (SingI, sing)
import Data.String (IsString)
import Data.Text (Text)
import Data.UUID (UUID)
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

instance ToJSON (RawField raw) where
  toJSON NoRaw = "<none>"
  toJSON (WithRaw bytes) = toJSON bytes

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype)
-- This enumeration defines the valid credential types. It is an extension point;
-- values can be added to it in the future, as more credential types are defined.
-- The values of this enumeration are used for versioning the Authentication Assertion
-- and attestation structures according to the type of the authenticator.
data PublicKeyCredentialType = PublicKeyCredentialTypePublicKey
  deriving (Eq, Show, Bounded, Enum, Ord, Generic)

instance ToJSON PublicKeyCredentialType where
  toJSON PublicKeyCredentialTypePublicKey = "PublicKeyCredentialTypePublicKey"

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
  deriving (Eq, Show, Bounded, Enum, Ord, Generic, ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment)
-- This enumeration’s values describe [authenticators](https://www.w3.org/TR/webauthn-2/#authenticator)'
-- [attachment modalities](https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality).
-- [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) use this to
-- express a preferred [authenticator attachment modality](https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality)
-- when calling [@navigator.credentials.create()@](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- to [create a credential](https://www.w3.org/TR/webauthn-2/#sctn-createCredential).
data AuthenticatorAttachment
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattachment-platform)
    -- This value indicates [platform attachment](https://www.w3.org/TR/webauthn-2/#platform-attachment).
    AuthenticatorAttachmentPlatform
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattachment-cross-platform)
    -- This value indicates [cross-platform attachment](https://www.w3.org/TR/webauthn-2/#cross-platform-attachment).
    AuthenticatorAttachmentCrossPlatform
  deriving (Eq, Show, Bounded, Enum, Ord, Generic, ToJSON)

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
  deriving (Eq, Show, Bounded, Enum, Ord, Generic, ToJSON)

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
  deriving (Eq, Show, Bounded, Enum, Ord, Generic, ToJSON)

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
  deriving (Eq, Show, Bounded, Enum, Ord, Generic, ToJSON)

-- | An X.509 certificate chain that can be used to verify an attestation
-- statement
data AttestationChain (p :: ProtocolKind) where
  -- | For Fido 2, we can have a chain consisting of multiple certificates.
  Fido2Chain :: NonEmpty X509.SignedCertificate -> AttestationChain 'Fido2
  -- | For Fido U2F, we can only have a single certificate, which is then also
  -- used to generate the 'SubjectKeyIdentifier' from
  FidoU2FCert :: X509.SignedCertificate -> AttestationChain 'FidoU2F

deriving instance Eq (AttestationChain p)

deriving instance Show (AttestationChain p)

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
  deriving (Eq, Show, Bounded, Enum, Ord, Generic, ToJSON)

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

-- | A way to identify an authenticator
data AuthenticatorIdentifier (p :: ProtocolKind) where
  -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-aaguid)
  -- A known FIDO2 [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator),
  -- identified by a 'AAGUID'. Note that the 'AAGUID' may be zero, meaning that
  -- we were able to verify that the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential).
  -- was generated by a trusted [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator),
  -- but we don't know which model it is.
  AuthenticatorIdentifierFido2 ::
    {idAaguid :: AAGUID} ->
    AuthenticatorIdentifier 'Fido2
  -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationcertificatekeyidentifiers)
  -- A known FIDO U2F [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator),
  -- identified by a 'SubjectKeyIdentifier'. Clients that don't implement CTAP2
  -- (which is used to communicate with FIDO2 authenticators) will use U2F to
  -- communicate with the authenticator instead, which doesn't have support for 'AAGUID's.
  AuthenticatorIdentifierFidoU2F ::
    {idSubjectKeyIdentifier :: SubjectKeyIdentifier} ->
    AuthenticatorIdentifier 'FidoU2F

deriving instance Show (AuthenticatorIdentifier p)

deriving instance Eq (AuthenticatorIdentifier p)

instance ToJSON (AuthenticatorIdentifier p) where
  toJSON (AuthenticatorIdentifierFido2 aaguid) =
    object
      [ "tag" .= String "AuthenticatorIdentifierFido2",
        "idAaguid" .= aaguid
      ]
  toJSON (AuthenticatorIdentifierFidoU2F subjectKeyIdentifier) =
    object
      [ "tag" .= String "AuthenticatorIdentifierFidoU2F",
        "idSubjectKeyIdentifier" .= subjectKeyIdentifier
      ]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#aaguid)
newtype AAGUID = AAGUID {unAAGUID :: UUID}
  deriving (Eq, Show)
  deriving newtype (Hashable, ToJSON)

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
-- TODO: 'RpId' is used for both https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id
-- and https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-rpid, but the former
-- uses DOMString, while the latter uses USVString. Is this a bug in the spec or is there an actual difference?
newtype RpId = RpId {unRpId :: Text}
  deriving (Eq, Show, Ord)
  deriving newtype (IsString, ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
-- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability)
-- identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
-- intended only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
--
-- - [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD perform
-- enforcement, as prescribed in Section 2.3 of [RFC8266](https://www.w3.org/TR/webauthn-2/#biblio-rfc8266)
-- for the Nickname Profile of the PRECIS FreeformClass [RFC8264](https://www.w3.org/TR/webauthn-2/#biblio-rfc8264),
-- when setting 'RelyingPartyName''s value, or displaying the value to the user.
-- - This string MAY contain language and direction metadata. [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
-- SHOULD consider providing this information. See [§ 6.4.2 Language and Direction Encoding](https://www.w3.org/TR/webauthn-2/#sctn-strings-langdir)
-- about how this metadata is encoded.
newtype RelyingPartyName = RelyingPartyName {unRelyingPartyName :: Text}
  deriving (Eq, Show)
  deriving newtype (IsString, ToJSON)

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
  deriving newtype (ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#user-handle)
-- A user handle is an opaque [byte sequence](https://infra.spec.whatwg.org/#byte-sequence)
-- with a maximum size of 64 bytes, and is not meant to be displayed to the user.
generateUserHandle :: MonadRandom m => m UserHandle
generateUserHandle = UserHandle <$> getRandomBytes 16

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
-- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) name for the user account,
-- intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD
-- let the user choose this, and SHOULD NOT restrict the choice more than necessary.
--
-- - [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) SHOULD perform
-- enforcement, as prescribed in Section 2.3 of [RFC8266](https://www.w3.org/TR/webauthn-2/#biblio-rfc8266)
-- for the Nickname Profile of the PRECIS FreeformClass [RFC8264](https://www.w3.org/TR/webauthn-2/#biblio-rfc8264),
-- when setting 'displayName''s value, or displaying the value to the user.
-- - This string MAY contain language and direction metadata. [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
-- SHOULD consider providing this information. See [§ 6.4.2 Language and Direction Encoding](https://www.w3.org/TR/webauthn-2/#sctn-strings-langdir)
-- about how this metadata is encoded.
newtype UserAccountDisplayName = UserAccountDisplayName {unUserAccountDisplayName :: Text}
  deriving (Eq, Show)
  deriving newtype (IsString, ToJSON)

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
  deriving newtype (IsString, ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#credential-id)
-- A probabilistically-unique [byte sequence](https://infra.spec.whatwg.org/#byte-sequence)
-- identifying a [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential-source)
-- source and its [authentication assertions](https://www.w3.org/TR/webauthn-2/#authentication-assertion).
newtype CredentialId = CredentialId {unCredentialId :: BS.ByteString}
  deriving (Eq, Show, Ord)
  deriving newtype (ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#credential-id)
-- Generates a random 'CredentialId' using 16 random bytes.
-- This is only useful for authenticators, not for relying parties.
-- This function is only included for completeness and testing purposes.
generateCredentialId :: MonadRandom m => m CredentialId
generateCredentialId = CredentialId <$> getRandomBytes 16

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
-- This member contains a challenge intended to be used for generating the newly
-- created credential’s attestation object. See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
-- security consideration.
newtype Challenge = Challenge {unChallenge :: BS.ByteString}
  deriving (Eq, Show, Ord)
  deriving newtype (ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
-- In order to prevent replay attacks, the challenges MUST contain enough entropy
-- to make guessing them infeasible. Challenges SHOULD therefore be at least 16 bytes long.
generateChallenge :: MonadRandom m => m Challenge
generateChallenge = Challenge <$> getRandomBytes 16

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
-- This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
-- This is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
newtype Timeout = Timeout {unTimeout :: Word32}
  deriving (Eq, Show)
  deriving newtype (ToJSON)

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
  deriving newtype (ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#rpidhash)
-- SHA-256 hash of the [RP ID](https://www.w3.org/TR/webauthn-2/#rp-id) the
-- [credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) is
-- [scoped](https://www.w3.org/TR/webauthn-2/#scope) to.
newtype RpIdHash = RpIdHash {unRpIdHash :: Digest SHA256}
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#collectedclientdata-hash-of-the-serialized-client-data)
-- This is the hash (computed using SHA-256) of the [JSON-compatible serialization of client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data),
-- as constructed by the client.
newtype ClientDataHash = ClientDataHash {unClientDataHash :: Digest SHA256}
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | [(spec)](https://html.spec.whatwg.org/multipage/origin.html#concept-origin)
newtype Origin = Origin {unOrigin :: Text}
  deriving (Eq, Show)
  deriving newtype (IsString, ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#signcount)
-- [Signature counter](https://www.w3.org/TR/webauthn-2/#signature-counter)
newtype SignatureCounter = SignatureCounter {unSignatureCounter :: Word32}
  deriving (Eq, Show)
  deriving newtype (Num, Ord, ToJSON)

-- | The encoding of a 'PublicKey'
newtype PublicKeyBytes = PublicKeyBytes {unPublicKeyBytes :: BS.ByteString}
  deriving (Eq, Show)
  deriving newtype (ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-inputs)
-- This is a dictionary containing the [client extension input](https://www.w3.org/TR/webauthn-2/#client-extension-input)
-- values for zero or more [WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#webauthn-extensions).
-- TODO: Implement a way to specify extensions, or implement them here directly
data AuthenticationExtensionsClientInputs = AuthenticationExtensionsClientInputs
  {
  }
  deriving (Eq, Show)

instance ToJSON AuthenticationExtensionsClientInputs where
  toJSON _ = object []

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authentication-extensions-client-outputs)
-- This is a dictionary containing the [client extension output](https://www.w3.org/TR/webauthn-2/#client-extension-output)
-- values for zero or more [WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#webauthn-extensions).
-- TODO: Implement a way to specify extensions, or implement them here directly
data AuthenticationExtensionsClientOutputs = AuthenticationExtensionsClientOutputs
  {
  }
  deriving (Eq, Show)

instance ToJSON AuthenticationExtensionsClientOutputs where
  toJSON _ = object []

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticator-extension-output)
data AuthenticatorExtensionOutputs = AuthenticatorExtensionOutputs
  {
  }
  deriving (Eq, Show)

instance ToJSON AuthenticatorExtensionOutputs where
  toJSON _ = object []

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params)
-- The 'PublicKeyCredentialRpEntity' dictionary is used to supply additional
-- [Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) attributes when creating a new credential.
data PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id)
    -- A unique identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- entity, which sets the 'RpId'.
    pkcreId :: Maybe RpId,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability)
    -- identifier for the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party),
    -- intended only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
    pkcreName :: RelyingPartyName
  }
  deriving (Eq, Show, Generic, ToJSON)

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
    -- FIXME: We don't allow encoding it as null here, because it doesn't seem
    -- to be an allowed value in the client, see <https://www.w3.org/TR/webauthn-2/#sctn-createCredential>
    pkcueId :: UserHandle,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) name for the user account,
    -- intended only for display. For example, "Alex Müller" or "田中倫".
    pkcueDisplayName :: UserAccountDisplayName,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    -- A [human-palatable](https://www.w3.org/TR/webauthn-2/#human-palatability) identifier for a user account.
    -- It is intended only for display, i.e., aiding the user in determining the difference between user
    -- accounts with similar displayNames. For example, "alexm", "alex.mueller@example.com" or "+14255551234".
    pkcueName :: UserAccountName
  }
  deriving (Eq, Show, Generic, ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-params)
-- This dictionary is used to supply additional parameters when creating a new credential.
data PublicKeyCredentialParameters = PublicKeyCredentialParameters
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-type)
    -- This member specifies the type of credential to be created.
    pkcpTyp :: PublicKeyCredentialType,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-alg)
    -- This member specifies the cryptographic signature algorithm with which the newly
    -- generated credential will be used, and thus also the type of asymmetric
    -- key pair to be generated, e.g., RSA or Elliptic Curve.
    pkcpAlg :: COSEAlgorithmIdentifier
  }
  deriving (Eq, Show, Generic, ToJSON)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor)
-- This dictionary contains the attributes that are specified by a caller when referring to a
-- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) as an input parameter to the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) or
-- [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) methods.
-- It mirrors the fields of the 'PublicKeyCredential' object returned by the latter methods.
data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-type)
    -- This member contains the type of the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    pkcdTyp :: PublicKeyCredentialType,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-id)
    -- This member contains the [credential ID](https://www.w3.org/TR/webauthn-2/#credential-id) of the
    -- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    pkcdId :: CredentialId,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports)
    -- This OPTIONAL member contains a hint as to how the [client](https://www.w3.org/TR/webauthn-2/#client)
    -- might communicate with the [managing authenticator](https://www.w3.org/TR/webauthn-2/#public-key-credential-source-managing-authenticator)
    -- of the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential) the caller is referring to.
    -- The values SHOULD be members of 'AuthenticatorTransport' but [client platforms](https://www.w3.org/TR/webauthn-2/#client-platform) MUST ignore unknown values.
    pkcdTransports :: Maybe [AuthenticatorTransport]
  }
  deriving (Eq, Show, Generic, ToJSON)

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
    ascResidentKey :: ResidentKeyRequirement,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification)
    -- This member describes the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s
    -- requirements regarding [user verification](https://www.w3.org/TR/webauthn-2/#user-verification)
    -- for the [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
    -- operation. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    -- The value SHOULD be a member of 'UserVerificationRequirement' but
    -- [client platforms](https://www.w3.org/TR/webauthn-2/#client-platform) MUST ignore unknown values,
    -- treating an unknown value as if the [member does not exist](https://infra.spec.whatwg.org/#map-exists).
    ascUserVerification :: UserVerificationRequirement
  }
  deriving (Eq, Show, Generic, ToJSON)

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
  deriving (Eq, Show, Generic, ToJSON)

data PublicKeyCredentialOptions (t :: WebauthnKind) where
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
  PublicKeyCredentialCreationOptions ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-rp)
      -- This member contains data about the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
      -- responsible for the request.
      pkcocRp :: PublicKeyCredentialRpEntity,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user)
      -- This member contains data about the user account for which the
      -- [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) is requesting attestation.
      pkcocUser :: PublicKeyCredentialUserEntity,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-challenge)
      -- This member contains a challenge intended to be used for generating the newly created
      -- credential’s attestation object. See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
      -- security consideration.
      pkcocChallenge :: Challenge,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-pubkeycredparams)
      -- This member contains information about the desired properties of the credential to be created.
      -- The sequence is ordered from most preferred to least preferred.
      -- The [client](https://www.w3.org/TR/webauthn-2/#client) makes a best-effort
      -- to create the most preferred credential that it can.
      pkcocPubKeyCredParams :: [PublicKeyCredentialParameters],
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
      -- This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
      -- This is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
      pkcocTimeout :: Maybe Timeout,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials)
      -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
      -- that wish to limit the creation of multiple credentials for the same account on a single authenticator.
      -- The [client](https://www.w3.org/TR/webauthn-2/#client) is requested to return an error if the new credential
      -- would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
      pkcocExcludeCredentials :: [PublicKeyCredentialDescriptor],
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection)
      -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
      -- that wish to select the appropriate authenticators to participate in the
      -- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) operation.
      pkcocAuthenticatorSelection :: Maybe AuthenticatorSelectionCriteria,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-attestation)
      -- This member is intended for use by [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party)
      -- that wish to express their preference for [attestation conveyance](https://www.w3.org/TR/webauthn-2/#attestation-conveyance).
      pkcocAttestation :: AttestationConveyancePreference,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-extensions)
      -- This member contains additional parameters requesting additional processing by the client and authenticator.
      -- For example, the caller may request that only authenticators with certain capabilities be used to create the credential,
      -- or that particular information be returned in the [attestation object](https://www.w3.org/TR/webauthn-2/#attestation-object).
      -- Some extensions are defined in [§ 9 WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#sctn-extensions);
      -- consult the IANA "WebAuthn Extension Identifiers" registry [IANA-WebAuthn-Registries](https://www.w3.org/TR/webauthn-2/#biblio-iana-webauthn-registries)
      -- established by [RFC8809](https://www.w3.org/TR/webauthn-2/#biblio-rfc8809) for an up-to-date
      -- list of registered [WebAuthn Extensions](https://www.w3.org/TR/webauthn-2/#webauthn-extensions).
      pkcocExtensions :: Maybe AuthenticationExtensionsClientInputs
    } ->
    PublicKeyCredentialOptions 'Create
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
  -- The 'PublicKeyCredentialRequestOptions' dictionary supplies `[get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)`
  -- with the data it needs to generate an assertion.
  PublicKeyCredentialRequestOptions ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge)
      -- This member represents a challenge that the selected [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) signs,
      -- along with other data, when producing an [authentication assertion](https://www.w3.org/TR/webauthn-2/#authentication-assertion).
      -- See the [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges) security consideration.
      pkcogChallenge :: Challenge,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-timeout)
      -- This OPTIONAL member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
      -- The value is treated as a hint, and MAY be overridden by the [client](https://www.w3.org/TR/webauthn-2/#client).
      pkcogTimeout :: Maybe Timeout,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-rpid)
      -- This OPTIONAL member specifies the [relying party identifier](https://www.w3.org/TR/webauthn-2/#relying-party-identifier) claimed by the caller.
      -- If omitted, its value will be the `[CredentialsContainer](https://w3c.github.io/webappsec-credential-management/#credentialscontainer)`
      -- object’s [relevant settings object](https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object)'s
      -- [origin](https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin)'s
      -- [effective domain](https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain).
      pkcogRpId :: Maybe RpId,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials)
      -- This OPTIONAL member contains a list of 'PublicKeyCredentialDescriptor'
      -- objects representing [public key credentials](https://www.w3.org/TR/webauthn-2/#public-key-credential) acceptable to the caller,
      -- in descending order of the caller’s preference (the first item in the list is the most preferred credential, and so on down the list).
      pkcogAllowCredentials :: [PublicKeyCredentialDescriptor],
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-userverification)
      -- This OPTIONAL member describes the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)'s requirements regarding
      -- [user verification](https://www.w3.org/TR/webauthn-2/#user-verification) for the
      -- `[get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)` operation.
      pkcogUserVerification :: UserVerificationRequirement,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-extensions)
      -- This OPTIONAL member contains additional parameters requesting additional processing by the client and authenticator.
      -- For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
      pkcogExtensions :: Maybe AuthenticationExtensionsClientInputs
    } ->
    PublicKeyCredentialOptions 'Get

deriving instance Eq (PublicKeyCredentialOptions t)

deriving instance Show (PublicKeyCredentialOptions t)

instance ToJSON (PublicKeyCredentialOptions t) where
  toJSON PublicKeyCredentialCreationOptions {..} =
    object
      [ "tag" .= String "PublicKeyCredentialCreationOptions",
        "pkcocRp" .= pkcocRp,
        "pkcocUser" .= pkcocUser,
        "pkcocChallenge" .= pkcocChallenge,
        "pkcocPubKeyCredParams" .= pkcocPubKeyCredParams,
        "pkcocTimeout" .= pkcocTimeout,
        "pkcocExcludeCredentials" .= pkcocExcludeCredentials,
        "pkcocAuthenticatorSelection" .= pkcocAuthenticatorSelection,
        "pkcocAttestation" .= pkcocAttestation,
        "pkcocExtensions" .= pkcocExtensions
      ]
  toJSON PublicKeyCredentialRequestOptions {..} =
    object
      [ "tag" .= String "PublicKeyCredentialRequestOptions",
        "pkcogChallenge" .= pkcogChallenge,
        "pkcogTimeout" .= pkcogTimeout,
        "pkcogRpId" .= pkcogRpId,
        "pkcogAllowCredentials" .= pkcogAllowCredentials,
        "pkcogUserVerification" .= pkcogUserVerification,
        "pkcogExtensions" .= pkcogExtensions
      ]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
-- The client data represents the contextual bindings of both the
-- [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)
-- and the [client](https://www.w3.org/TR/webauthn-2/#client).
data CollectedClientData (t :: WebauthnKind) raw = CollectedClientData
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
    -- This member contains the inverse of the `sameOriginWithAncestors` argument value
    -- that was passed into the [internal method](https://tc39.github.io/ecma262/#sec-object-internal-methods-and-internal-slots).
    ccdCrossOrigin :: Bool,
    -- | Raw data of the client data, for verification purposes
    ccdRawData :: RawField raw
    -- TODO: Implement this
    -- tokenBinding :: Maybe TokenBinding,
  }
  deriving (Eq, Show)

instance SingI t => ToJSON (CollectedClientData t raw) where
  toJSON CollectedClientData {..} =
    object
      [ "webauthnKind" .= sing @t,
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
data AttestedCredentialData (t :: WebauthnKind) raw where
  AttestedCredentialData ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#aaguid)
      acdAaguid :: AAGUID,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#credentialid)
      acdCredentialId :: CredentialId,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#credentialpublickey)
      acdCredentialPublicKey :: PublicKey,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#credentialpublickey)
      acdCredentialPublicKeyBytes :: RawField raw
    } ->
    AttestedCredentialData 'Create raw
  NoAttestedCredentialData ::
    AttestedCredentialData 'Get raw

deriving instance Eq (AttestedCredentialData t raw)

deriving instance Show (AttestedCredentialData t raw)

instance ToJSON (AttestedCredentialData t raw) where
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
data AuthenticatorData (t :: WebauthnKind) raw = AuthenticatorData
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
    adAttestedCredentialData :: AttestedCredentialData t raw,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#authdataextensions)
    -- Extension-defined [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
    adExtensions :: Maybe AuthenticatorExtensionOutputs,
    -- | Raw encoded data for verification purposes
    adRawData :: RawField raw
  }
  deriving (Eq, Show, Generic, ToJSON)

-- | The result from verifying an attestation statement.
-- Either the result is verifiable, in which case @k ~ 'Verifiable'@, the
-- 'AttestationType' contains a verifiable certificate chain and
-- 'AuthenticatorModel' contains a known authenticator.
-- Or the result is not verifiable, in which case @k ~ 'Unverifiable'@, the
-- 'AttestationType' is None or Self, and the 'AuthenticatorModel' is unknown.
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
    Exception (AttStmtDecodingError a),
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
  -- thus treated as different formats, e.g., `packed2` as a new version of the
  -- [§ 8.2 Packed Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation).
  asfIdentifier :: a -> Text

  -- | The type of verification errors that can occur when verifying this
  -- attestation statement using 'asfVerify'
  type AttStmtVerificationError a :: Type

  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#verification-procedure)
  -- The procedure to verify an [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement)
  asfVerify ::
    a ->
    AttStmt a ->
    AuthenticatorData 'Create 'True ->
    ClientDataHash ->
    Either (AttStmtVerificationError a) SomeAttestationType

  -- | The trusted root certificates specifically for this attestation
  -- statement format. For attestation statement chain validation, these
  -- certificates are used, in addition to the ones from the metadata registry
  --
  -- [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential) step 20
  -- > If validation is successful, obtain a list of acceptable trust anchors
  -- > (i.e. attestation root certificates) for that attestation type and
  -- > attestation statement format fmt, from a trusted source or from policy.
  --
  -- While for the attestation statement formats we implement, none of them use
  -- the 'VerifiableAttestationType', it is implied that it could be used by
  -- the above sentence from the spec.
  asfTrustAnchors ::
    a ->
    VerifiableAttestationType ->
    X509.CertificateStore

  -- | The type of decoding errors that can occur when decoding this
  -- attestation statement using 'asfDecode'
  type AttStmtDecodingError a :: Type

  -- | A decoder for the attestation statement [syntax](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats).
  -- The @attStmt@ CBOR map is given as an input. See
  -- [Generating an Attestation Object](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
  asfDecode ::
    a ->
    HashMap Text CBOR.Term ->
    Either (AttStmtDecodingError a) (AttStmt a)

  -- | An encoder for the attestation statement [syntax](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats).
  -- The @attStmt@ CBOR map is expected as the result. See
  -- [Generating an Attestation Object](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
  asfEncode ::
    a ->
    AttStmt a ->
    CBOR.Term

-- | An arbitrary [attestation statement format](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats).
-- In contrast to 'DecodingAttestationStatementFormat', this type can be put into a list.
-- This is used for 'mkSupportedAttestationStatementFormats'
data SomeAttestationStatementFormat
  = forall a.
    AttestationStatementFormat a =>
    SomeAttestationStatementFormat a

-- | A type representing the set of supported attestation statement formats.
-- The constructor is intentionally not exported, use
-- 'sasfSingleton' instead to construct it and
-- 'sasfLookup' to look up formats. This types 'Semigroup'
-- instance can be used to combine multiple formats
newtype SupportedAttestationStatementFormats
  = -- HashMap invariant: asfIdentifier (hm ! k) == k
    SupportedAttestationStatementFormats (HashMap Text SomeAttestationStatementFormat)
  deriving newtype (Semigroup, Monoid)

sasfSingleton :: SomeAttestationStatementFormat -> SupportedAttestationStatementFormats
sasfSingleton someFormat@(SomeAttestationStatementFormat format) =
  SupportedAttestationStatementFormats $ HashMap.singleton (asfIdentifier format) someFormat

sasfLookup :: Text -> SupportedAttestationStatementFormats -> Maybe SomeAttestationStatementFormat
sasfLookup id (SupportedAttestationStatementFormats sasf) = sasf !? id

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#attestation-object)
data AttestationObject raw = forall a.
  AttestationStatementFormat a =>
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
    aoAuthData :: AuthenticatorData 'Create raw,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#attestation-statement-format)
    aoFmt :: a,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#attestation-statement)
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
data AuthenticatorResponse (t :: WebauthnKind) raw where
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse)
  -- The 'AuthenticatorAttestationResponse' interface represents the
  -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)'s response
  -- to a client’s request for the creation of a new
  -- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential).
  -- It contains information about the new credential that can be used to identify
  -- it for later use, and metadata that can be used by the
  -- [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)
  -- to assess the characteristics of the credential during registration.
  AuthenticatorAttestationResponse ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
      -- This attribute, inherited from `[AuthenticatorResponse](https://www.w3.org/TR/webauthn-2/#authenticatorresponse)`,
      -- contains the [JSON-compatible serialization of client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data)
      -- (see [§ 6.5 Attestation](https://www.w3.org/TR/webauthn-2/#sctn-attestation))
      -- passed to the authenticator by the client in order to generate this credential.
      -- The exact JSON serialization MUST be preserved, as the
      -- [hash of the serialized client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-hash-of-the-serialized-client-data) has been computed over it.
      arcClientData :: CollectedClientData 'Create raw,
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
      arcAttestationObject :: AttestationObject raw
      -- TODO: This property is currently not propagated by webauthn-json
      -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-gettransports)
      -- This [internal slot](https://tc39.github.io/ecma262/#sec-object-internal-methods-and-internal-slots)
      -- contains a sequence of zero or more unique `[DOMString](https://heycam.github.io/webidl/#idl-DOMString)`s
      -- in lexicographical order. These values are the transports that the
      -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) is believed to support,
      -- or an empty sequence if the information is unavailable.
      -- arcTransports :: Set AuthenticatorTransport
    } ->
    AuthenticatorResponse 'Create raw
  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse)
  -- The 'AuthenticatorAssertionResponse' interface represents an
  -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)'s response
  -- to a client’s request for generation of a new
  -- [authentication assertion](https://www.w3.org/TR/webauthn-2/#authentication-assertion)
  -- given the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party)'s
  -- challenge and OPTIONAL list of credentials it is aware of. This response
  -- contains a cryptographic signature proving possession of the
  -- [credential private key](https://www.w3.org/TR/webauthn-2/#credential-private-key),
  -- and optionally evidence of [user consent](https://www.w3.org/TR/webauthn-2/#user-consent)
  -- to a specific transaction.
  AuthenticatorAssertionResponse ::
    { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
      -- This attribute, inherited from `[AuthenticatorResponse](https://www.w3.org/TR/webauthn-2/#authenticatorresponse)`,
      -- contains the [JSON-compatible serialization of client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data)
      -- (see [§ 6.5 Attestation](https://www.w3.org/TR/webauthn-2/#sctn-attestation))
      -- passed to the authenticator by the client in order to generate this credential.
      -- The exact JSON serialization MUST be preserved, as the
      -- [hash of the serialized client data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-hash-of-the-serialized-client-data) has been computed over it.
      argClientData :: CollectedClientData 'Get raw,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata)
      -- This attribute contains the [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data)
      -- returned by the authenticator. See [§ 6.1 Authenticator Data](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data).
      argAuthenticatorData :: AuthenticatorData 'Get raw,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-signature)
      -- This attribute contains the raw signature returned from the authenticator.
      -- See [§ 6.3.3 The authenticatorGetAssertion Operation](https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion).
      argSignature :: AssertionSignature,
      -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-userhandle)
      -- This attribute contains the [user handle](https://www.w3.org/TR/webauthn-2/#user-handle)
      -- returned from the authenticator, or null if the authenticator did not return a
      -- [user handle](https://www.w3.org/TR/webauthn-2/#user-handle). See
      -- [§ 6.3.3 The authenticatorGetAssertion Operation](https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion).
      argUserHandle :: Maybe UserHandle
    } ->
    AuthenticatorResponse 'Get raw

deriving instance Eq (AuthenticatorResponse t raw)

deriving instance Show (AuthenticatorResponse t raw)

instance ToJSON (AuthenticatorResponse t raw) where
  toJSON AuthenticatorAttestationResponse {..} =
    object
      [ "arcClientData" .= arcClientData,
        "arcAttestationObject" .= arcAttestationObject
      ]
  toJSON AuthenticatorAssertionResponse {..} =
    object
      [ "argClientData" .= argClientData,
        "argAuthenticatorData" .= argAuthenticatorData,
        "argSignature" .= argSignature,
        "argUserHandle" .= argUserHandle
      ]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- The 'PublicKeyCredential' interface contains the attributes that are returned to the caller when a new credential is created, or a new assertion is requested.
data PublicKeyCredential (t :: WebauthnKind) raw = PublicKeyCredential
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-identifier-slot)
    -- Contains the [credential ID](https://www.w3.org/TR/webauthn-2/#credential-id),
    -- chosen by the authenticator. The [credential ID](https://www.w3.org/TR/webauthn-2/#credential-id)
    -- is used to look up credentials for use, and is therefore expected to be globally
    -- unique with high probability across all credentials of the same type, across all authenticators.
    pkcIdentifier :: CredentialId,
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
    pkcResponse :: AuthenticatorResponse t raw,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-getclientextensionresults)
    -- This operation returns the value of `[[[clientExtensionsResults]]](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-clientextensionsresults-slot)`,
    -- which is a [map](https://infra.spec.whatwg.org/#ordered-map) containing
    -- [extension identifier](https://www.w3.org/TR/webauthn-2/#extension-identifier) →
    -- [client extension output](https://www.w3.org/TR/webauthn-2/#client-extension-output) entries produced
    -- by the extension’s [client extension processing](https://www.w3.org/TR/webauthn-2/#client-extension-processing).
    pkcClientExtensionResults :: AuthenticationExtensionsClientOutputs
  }
  deriving (Eq, Show, Generic, ToJSON)
