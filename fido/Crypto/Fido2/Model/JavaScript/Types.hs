{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Model.JavaScript.Types
  ( Convert (..),
    ClientDataJSON (..),
  )
where

import Crypto.Fido2.EncodingUtils (CustomJSON (CustomJSON), JSONEncoding)
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import qualified Crypto.Fido2.PublicKey as PublicKey
import qualified Crypto.Fido2.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.Kind (Type)
import Data.Map (Map)
import Data.Text (Text)
import GHC.Generics (Generic)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
-- Intermediate type used to extract the JSON structure stored in the
-- CBOR-encoded [clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson).
-- NOTE: Do not rely on the ToJSON instance of this type, it is not implemented according to spec.
data ClientDataJSON = ClientDataJSON
  { littype :: IDL.DOMString,
    challenge :: IDL.DOMString,
    origin :: IDL.DOMString,
    crossOrigin :: Maybe Bool
    -- TODO
    -- tokenBinding :: Maybe TokenBinding
  }
  deriving (Generic)
  -- Note: Encoding can NOT be derived automatically, and most likely not even
  -- be provided correctly with the Aeson.ToJSON class, because it is only a
  -- JSON-_compatible_ encoding, but it also contains some extra structure
  -- allowing for verification without a full JSON parser
  -- See <https://www.w3.org/TR/webauthn-2/#clientdatajson-serialization>
  -- TODO/FIXME: As described above the ToJSON instance should not be derived,
  -- but implemented manually using the description provided in the specification.
  -- For now the ToJSON instance is only used for tests so it suffices, but
  -- library users should not rely on it.
  deriving (Aeson.FromJSON, Aeson.ToJSON) via JSONEncoding ClientDataJSON

-- | @'Convert' hs@ indicates that the Haskell-specific type @hs@ has a more
-- general JavaScript-specific type associated with it, which can be accessed with 'JS'.
class Convert hs where
  type JS hs :: Type

instance Convert hs => Convert (Maybe hs) where
  type JS (Maybe hs) = Maybe (JS hs)

instance Convert M.RpId where
  type JS M.RpId = IDL.DOMString

instance Convert M.RelyingPartyName where
  type JS M.RelyingPartyName = IDL.DOMString

instance Convert M.PublicKeyCredentialRpEntity where
  type JS M.PublicKeyCredentialRpEntity = JS.PublicKeyCredentialRpEntity

instance Convert M.UserHandle where
  type JS M.UserHandle = IDL.BufferSource

instance Convert M.UserAccountDisplayName where
  type JS M.UserAccountDisplayName = IDL.DOMString

instance Convert M.UserAccountName where
  type JS M.UserAccountName = IDL.DOMString

instance Convert M.PublicKeyCredentialUserEntity where
  type JS M.PublicKeyCredentialUserEntity = JS.PublicKeyCredentialUserEntity

instance Convert M.Challenge where
  type JS M.Challenge = IDL.BufferSource

instance Convert M.PublicKeyCredentialType where
  type JS M.PublicKeyCredentialType = IDL.DOMString

instance Convert PublicKey.COSEAlgorithmIdentifier where
  type JS PublicKey.COSEAlgorithmIdentifier = JS.COSEAlgorithmIdentifier

instance Convert [M.PublicKeyCredentialParameters] where
  type JS [M.PublicKeyCredentialParameters] = [JS.PublicKeyCredentialParameters]

instance Convert M.Timeout where
  type JS M.Timeout = IDL.UnsignedLong

instance Convert M.CredentialId where
  type JS M.CredentialId = IDL.BufferSource

instance Convert [M.AuthenticatorTransport] where
  type JS [M.AuthenticatorTransport] = [IDL.DOMString]

instance Convert M.PublicKeyCredentialDescriptor where
  type JS M.PublicKeyCredentialDescriptor = JS.PublicKeyCredentialDescriptor

instance Convert [M.PublicKeyCredentialDescriptor] where
  type JS [M.PublicKeyCredentialDescriptor] = Maybe [JS.PublicKeyCredentialDescriptor]

instance Convert M.AuthenticatorAttachment where
  type JS M.AuthenticatorAttachment = IDL.DOMString

instance Convert M.ResidentKeyRequirement where
  type JS M.ResidentKeyRequirement = Maybe IDL.DOMString

instance Convert M.UserVerificationRequirement where
  type JS M.UserVerificationRequirement = Maybe IDL.DOMString

instance Convert M.AuthenticatorSelectionCriteria where
  type JS M.AuthenticatorSelectionCriteria = JS.AuthenticatorSelectionCriteria

instance Convert M.AttestationConveyancePreference where
  type JS M.AttestationConveyancePreference = Maybe IDL.DOMString

instance Convert M.AuthenticationExtensionsClientInputs where
  type JS M.AuthenticationExtensionsClientInputs = Map Text Aeson.Value

instance Convert (M.PublicKeyCredentialOptions 'M.Create) where
  type JS (M.PublicKeyCredentialOptions 'M.Create) = JS.PublicKeyCredentialCreationOptions

instance Convert (M.PublicKeyCredentialOptions 'M.Get) where
  type JS (M.PublicKeyCredentialOptions 'M.Get) = JS.PublicKeyCredentialRequestOptions

instance Convert (M.PublicKeyCredential 'M.Create) where
  type JS (M.PublicKeyCredential 'M.Create) = JS.PublicKeyCredential JS.AuthenticatorAttestationResponse

instance Convert (M.AuthenticatorResponse 'M.Create) where
  type JS (M.AuthenticatorResponse 'M.Create) = JS.AuthenticatorAttestationResponse

instance Convert (M.PublicKeyCredential 'M.Get) where
  type JS (M.PublicKeyCredential 'M.Get) = JS.PublicKeyCredential JS.AuthenticatorAssertionResponse

instance Convert (M.AuthenticatorResponse 'M.Get) where
  type JS (M.AuthenticatorResponse 'M.Get) = JS.AuthenticatorAssertionResponse

instance Convert M.AuthenticationExtensionsClientOutputs where
  type JS M.AuthenticationExtensionsClientOutputs = Map Text Aeson.Value

instance Convert (M.CollectedClientData t) where
  type JS (M.CollectedClientData t) = IDL.ArrayBuffer

instance Convert M.AttestationObject where
  type JS M.AttestationObject = IDL.ArrayBuffer

instance Convert M.AssertionSignature where
  type JS M.AssertionSignature = IDL.ArrayBuffer

instance Convert (M.AuthenticatorData 'M.Get) where
  type JS (M.AuthenticatorData 'M.Get) = IDL.ArrayBuffer
