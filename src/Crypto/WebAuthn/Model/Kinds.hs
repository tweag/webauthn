{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Stability: experimental
-- This module contains some useful kinds used throughout this library to
-- ensure better type safety. Also included are some singleton types for these
-- kinds via the [singletons](https://hackage.haskell.org/package/singletons)
-- library
module Crypto.WebAuthn.Model.Kinds
  ( CeremonyKind (..),
    SCeremonyKind (..),
    ProtocolKind (..),
    SProtocolKind (..),
    AttestationKind (..),
  )
where

import Data.Aeson (ToJSON, toJSON)
import Data.Kind (Type)
import Data.Singletons (Sing, SingI (sing))

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#ceremony)
-- A Haskell kind for a Webauthn [ceremony](https://www.w3.org/TR/webauthn-2/#ceremony).
-- This is used throughout this library for extra type safety and API clarity.
data CeremonyKind
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#registration)
    -- The [ceremony](https://www.w3.org/TR/webauthn-2/#ceremony) where a user,
    -- a [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party), and
    -- the user’s [client](https://www.w3.org/TR/webauthn-2/#client) (containing
    -- at least one [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator))
    -- work in concert to create a
    -- [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential)
    -- and associate it with the user’s [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- account. Note that this includes employing a
    -- [test of user presence](https://www.w3.org/TR/webauthn-2/#test-of-user-presence)
    -- or [user verification](https://www.w3.org/TR/webauthn-2/#user-verification).
    -- After a successful [registration ceremony](https://www.w3.org/TR/webauthn-2/#registration-ceremony),
    -- the user can be authenticated by an
    -- [authentication ceremony](https://www.w3.org/TR/webauthn-2/#authentication-ceremony).
    -- The WebAuthn [registration ceremony](https://www.w3.org/TR/webauthn-2/#registration-ceremony) is defined in
    -- [§ 7.1 Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential),
    -- and is initiated by the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) calling
    -- [@navigator.credentials.create()@](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
    -- with a [@publicKey@](https://www.w3.org/TR/webauthn-2/#dom-credentialcreationoptions-publickey) argument.
    -- See [§ 5 Web Authentication API](https://www.w3.org/TR/webauthn-2/#sctn-api) for an introductory
    -- overview and [§ 1.3.1 Registration](https://www.w3.org/TR/webauthn-2/#sctn-sample-registration)
    -- for implementation examples.
    Registration
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#authentication)
    -- The [ceremony](https://www.w3.org/TR/webauthn-2/#ceremony) where a user,
    -- and the user’s [client](https://www.w3.org/TR/webauthn-2/#client) (containing
    -- at least one [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)) work in concert
    -- to cryptographically prove to a [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party)
    -- that the user controls the
    -- [credential private key](https://www.w3.org/TR/webauthn-2/#credential-private-key)
    -- of a previously-registered [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential)
    -- (see [Registration](https://www.w3.org/TR/webauthn-2/#registration)).
    -- Note that this includes a [test of user presence](https://www.w3.org/TR/webauthn-2/#test-of-user-presence)
    -- or [user verification](https://www.w3.org/TR/webauthn-2/#user-verification).
    --
    -- The WebAuthn [authentication ceremony](https://www.w3.org/TR/webauthn-2/#authentication-ceremony)
    -- is defined in [§ 7.2 Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion),
    -- and is initiated by the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) calling
    -- [@navigator.credentials.get()@](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
    -- with a [@publicKey@](https://www.w3.org/TR/webauthn-2/#dom-credentialrequestoptions-publickey)
    -- argument. See [§ 5 Web Authentication API](https://www.w3.org/TR/webauthn-2/#sctn-api)
    -- for an introductory overview and
    -- [§ 1.3.3 Authentication](https://www.w3.org/TR/webauthn-2/#sctn-sample-authentication) for implementation examples.
    Authentication

-- | The singleton type for 'CeremonyKind'
data SCeremonyKind :: CeremonyKind -> Type where
  SRegistration :: SCeremonyKind 'Registration
  SAuthentication :: SCeremonyKind 'Authentication

deriving instance Show (SCeremonyKind c)

deriving instance Eq (SCeremonyKind c)

instance ToJSON (SCeremonyKind c) where
  toJSON SRegistration = "Registration"
  toJSON SAuthentication = "Authentication"

type instance Sing = SCeremonyKind

instance SingI 'Registration where
  sing = SRegistration

instance SingI 'Authentication where
  sing = SAuthentication

-- | Authenticator protocols supported by webauthn attestations
data ProtocolKind
  = -- | FIDO U2F Protocol, supported via the
    -- [fido-u2f](https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation)
    -- attestation format
    FidoU2F
  | -- | FIDO 2 Protocol
    Fido2

-- | The singleton type for 'ProtocolKind'
data SProtocolKind :: ProtocolKind -> Type where
  SFidoU2F :: SProtocolKind 'FidoU2F
  SFido2 :: SProtocolKind 'Fido2

deriving instance Show (SProtocolKind p)

deriving instance Eq (SProtocolKind p)

instance ToJSON (SProtocolKind p) where
  toJSON SFidoU2F = "FidoU2F"
  toJSON SFido2 = "Fido2"

type instance Sing = SProtocolKind

instance SingI 'FidoU2F where
  sing = SFidoU2F

instance SingI 'Fido2 where
  sing = SFido2

-- | A Haskell kind for the [attestation type](https://www.w3.org/TR/webauthn-2/#attestation-type),
-- indicating whether we have verifiable information about the
-- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) that created
-- the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential).
data AttestationKind
  = -- | An unverifiable [attestation type](https://www.w3.org/TR/webauthn-2/#attestation-type).
    -- This includes [None](https://www.w3.org/TR/webauthn-2/#none)
    -- and [Self](https://www.w3.org/TR/webauthn-2/#self-attestation) attestation.
    -- This kind indicates that we do not have any information about the
    -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) model used.
    Unverifiable
  | -- | A verifiable [attestation type](https://www.w3.org/TR/webauthn-2/#attestation-type).
    -- This includes [Basic](https://www.w3.org/TR/webauthn-2/#basic-attestation),
    -- [AttCA](https://www.w3.org/TR/webauthn-2/#attca) and
    -- [AnonCA](https://www.w3.org/TR/webauthn-2/#anonca) attestation.
    -- This kind indicates that we have verifiable information about the
    -- [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) model used.
    Verifiable ProtocolKind
