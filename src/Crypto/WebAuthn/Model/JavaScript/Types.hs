{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.WebAuthn.Model.JavaScript.Types
  ( Convert (..),
  )
where

import qualified Crypto.WebAuthn.Cose.Registry as Cose
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Model.JavaScript as JS
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.Kind (Type)
import Data.Map (Map)
import Data.Text (Text)

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

instance Convert Cose.CoseSignAlg where
  type JS Cose.CoseSignAlg = JS.COSEAlgorithmIdentifier

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

instance Convert (M.PublicKeyCredential 'M.Create raw) where
  type JS (M.PublicKeyCredential 'M.Create raw) = JS.PublicKeyCredential JS.AuthenticatorAttestationResponse

instance Convert (M.AuthenticatorResponse 'M.Create raw) where
  type JS (M.AuthenticatorResponse 'M.Create raw) = JS.AuthenticatorAttestationResponse

instance Convert (M.PublicKeyCredential 'M.Get raw) where
  type JS (M.PublicKeyCredential 'M.Get raw) = JS.PublicKeyCredential JS.AuthenticatorAssertionResponse

instance Convert (M.AuthenticatorResponse 'M.Get raw) where
  type JS (M.AuthenticatorResponse 'M.Get raw) = JS.AuthenticatorAssertionResponse

instance Convert M.AuthenticationExtensionsClientOutputs where
  type JS M.AuthenticationExtensionsClientOutputs = Map Text Aeson.Value

instance Convert (M.CollectedClientData t 'True) where
  type JS (M.CollectedClientData t 'True) = IDL.ArrayBuffer

instance Convert (M.AttestationObject raw) where
  type JS (M.AttestationObject raw) = IDL.ArrayBuffer

instance Convert M.AssertionSignature where
  type JS M.AssertionSignature = IDL.ArrayBuffer

instance Convert (M.AuthenticatorData 'M.Get raw) where
  type JS (M.AuthenticatorData 'M.Get raw) = IDL.ArrayBuffer
