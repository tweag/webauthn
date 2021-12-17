{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | This module contains some useful kinds used throughout this library to
-- ensure better type safety. Also included are some singleton types for these
-- kinds via the [singletons](https://hackage.haskell.org/package/singletons)
-- library
module Crypto.WebAuthn.Model.Kinds
  ( WebauthnKind (..),
    SWebauthnKind (..),
    ProtocolKind (..),
    SProtocolKind (..),
    AttestationKind (..),
  )
where

import Data.Kind (Type)
import Data.Singletons (Sing, SingI (sing))

-- | A Haskell kind for the type of Webauthn relying party operation that is being executed.
-- Used by the [type](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type)
-- member of the client data
data WebauthnKind
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
    Create
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
    Get

-- | The singleton type for 'WebauthnKind'
data SWebauthnKind :: WebauthnKind -> Type where
  SCreate :: SWebauthnKind 'Create
  SGet :: SWebauthnKind 'Get

deriving instance Show (SWebauthnKind t)

deriving instance Eq (SWebauthnKind t)

type instance Sing = SWebauthnKind

instance SingI 'Create where
  sing = SCreate

instance SingI 'Get where
  sing = SGet

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
