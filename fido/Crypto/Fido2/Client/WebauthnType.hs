{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}

-- | Types of webauthn operations, either credential creation (attestation),
-- or credential getting (aka assertion). For these operations, both a Haskell
-- kind 'WebauthnType' and a Haskell type 'SWebauthnType' are exported, along
-- with corresponding singleton instances 'Sing' and 'SingI', in order to
-- facilitate interoperability of kind and type between compile time and
-- runtime.
module Crypto.Fido2.Client.WebauthnType
  ( WebauthnType (..),
    SWebauthnType (..),
    module Data.Singletons,
  )
where

import Data.Kind (Type)
import Data.Singletons (Sing, SingI (sing))

-- | The type of Webauthn relying party operation that is being executed
-- Used by the [type](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type)
-- member of the client data
data WebauthnType
  = -- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
    Create
  | -- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
    Get
  deriving (Eq, Show)

-- | The singleton type that ties the values 'SCreate' and 'SGet' to types
-- 'Create' and 'Get' respectively
data SWebauthnType :: WebauthnType -> Type where
  SCreate :: SWebauthnType 'Create
  SGet :: SWebauthnType 'Get

deriving instance Show (SWebauthnType t)

deriving instance Eq (SWebauthnType t)

type instance Sing = SWebauthnType

instance SingI 'Create where
  sing = SCreate

instance SingI 'Get where
  sing = SGet
