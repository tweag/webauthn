{-# LANGUAGE DataKinds #-}

module Crypto.WebAuthn.UAF
  ( AAID (..),
    KeyIdentifier (..),
    Version (..),
  )
where

import Crypto.WebAuthn.EncodingUtils (JSONEncoding)
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import qualified Deriving.Aeson as Aeson
import GHC.Generics (Generic)

-- https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef
newtype AAID = AAID Text
  deriving (Show, Eq)
  deriving newtype (Aeson.FromJSON, Aeson.ToJSON)

-- Hex string, this value MUST be calculated according to method 1 for computing the keyIdentifier as defined in [RFC5280] section 4.2.1.2. https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
-- TODO: Implement a way to reproduce this value
newtype KeyIdentifier = KeyIdentifier Text
  deriving (Show, Eq)
  deriving newtype (Aeson.FromJSON, Aeson.ToJSON)

-- | [(spec)](https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface)
data Version = Version
  { -- | [(spec)](https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#widl-Version-major)
    major :: IDL.UnsignedShort,
    -- | [(spec)](https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#widl-Version-minor)
    minor :: IDL.UnsignedShort
  }
  deriving (Show, Eq, Generic)
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding Version
