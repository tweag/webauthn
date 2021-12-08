{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}

module Crypto.WebAuthn.EncodingUtils (JSONEncoding, EnumJSONEncoding, Aeson.CustomJSON (..)) where

import Data.Char (toLower)
import qualified Deriving.Aeson as Aeson
import GHC.TypeLits (Symbol)

type JSONEncoding = Aeson.CustomJSON '[Aeson.OmitNothingFields, Aeson.FieldLabelModifier (Aeson.StripPrefix "lit")]

data Lowercase

instance Aeson.StringModifier Lowercase where
  getStringModifier = map toLower

type EnumJSONEncoding (prefix :: Symbol) = Aeson.CustomJSON '[Aeson.ConstructorTagModifier '[Aeson.StripPrefix prefix, Lowercase]]
