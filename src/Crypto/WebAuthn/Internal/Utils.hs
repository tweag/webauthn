{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}

-- |
-- /Warning/: this is an internal module, and does not have a stable
-- API or name. Use at your own risk!
--
-- Utilities
module Crypto.WebAuthn.Internal.Utils
  ( JSONEncoding,
    EnumJSONEncoding,
    Aeson.CustomJSON (..),
    Lowercase,
    failure,
  )
where

import Data.Char (toLower)
import Data.List.NonEmpty (NonEmpty)
import Data.Validation (Validation (Failure))
import qualified Deriving.Aeson as Aeson
import GHC.TypeLits (Symbol)

-- | Custom JSONEncoding for use in the library. We add a "lit" prefix to every
-- field that would otherwise be a Haskell keyword.
type JSONEncoding = Aeson.CustomJSON '[Aeson.OmitNothingFields, Aeson.FieldLabelModifier (Aeson.StripPrefix "lit")]

-- | Type for 'Aeson.StringModifier' that makes all characters lowercase
data Lowercase

-- | Deriving.Aeson instance turning a string into lowercase.
instance Aeson.StringModifier Lowercase where
  getStringModifier = map toLower

-- | Custom JSON Encoding for enumerations, strips the given prefix and maps
-- all constructors to lowercase.
type EnumJSONEncoding (prefix :: Symbol) = Aeson.CustomJSON '[Aeson.ConstructorTagModifier '[Aeson.StripPrefix prefix, Lowercase]]

-- | A convenience function for creating a 'Validation' failure of a single
-- 'NonEmpty' value
failure :: e -> Validation (NonEmpty e) a
failure = Failure . pure
