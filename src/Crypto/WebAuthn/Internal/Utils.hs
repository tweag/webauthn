{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}

module Crypto.WebAuthn.Internal.Utils (JSONEncoding, EnumJSONEncoding, Aeson.CustomJSON (..), failure) where

import Data.Char (toLower)
import Data.List.NonEmpty (NonEmpty)
import Data.Validation (Validation (Failure))
import qualified Deriving.Aeson as Aeson
import GHC.TypeLits (Symbol)

type JSONEncoding = Aeson.CustomJSON '[Aeson.OmitNothingFields, Aeson.FieldLabelModifier (Aeson.StripPrefix "lit")]

data Lowercase

instance Aeson.StringModifier Lowercase where
  getStringModifier = map toLower

type EnumJSONEncoding (prefix :: Symbol) = Aeson.CustomJSON '[Aeson.ConstructorTagModifier '[Aeson.StripPrefix prefix, Lowercase]]

failure :: e -> Validation (NonEmpty e) a
failure = Failure . pure
