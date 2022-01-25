-- | Stability: experimental
-- Types related to the FIDO UAF Protocol as defined in the relevant
-- [(spec)](https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html)
module Crypto.WebAuthn.Metadata.UAF
  ( AAID (..),
    KeyIdentifier (..),
    Version (..),
  )
where

import Crypto.WebAuthn.Internal.Utils (jsonEncodingOptions)
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.Text (Text)
import GHC.Generics (Generic)

-- | [(spec)](https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef)
newtype AAID = AAID Text
  deriving (Show, Eq)
  deriving newtype (Aeson.FromJSON, Aeson.ToJSON)

-- | Hex string, this value MUST be calculated according to method 1 for
-- computing the keyIdentifier as defined in
-- [RFC5280 section 4.2.1.2](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2).
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

instance Aeson.FromJSON Version where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON Version where
  toJSON = Aeson.genericToJSON jsonEncodingOptions
