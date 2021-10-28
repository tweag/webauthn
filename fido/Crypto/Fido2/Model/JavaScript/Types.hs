{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Model.JavaScript.Types
  ( Convert (..),
  )
where

import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import qualified Crypto.Fido2.PublicKey as PublicKey
import qualified Data.Aeson as Aeson
import Data.Map (Map)
import Data.Text (Text)

-- | @'Convert' hs@ indicates that the Haskell-specific type @hs@ has a more
-- general JavaScript-specific type associated with it, which can be accessed with 'JS'.
class Convert hs where
  type JS hs :: *

instance Convert hs => Convert (Maybe hs) where
  type JS (Maybe hs) = Maybe (JS hs)

instance Convert a => Convert [a] where
  type JS [a] = [JS a]

instance Convert M.RpId where
  type JS M.RpId = JS.DOMString

instance Convert M.RelyingPartyName where
  type JS M.RelyingPartyName = JS.DOMString

instance Convert M.PublicKeyCredentialRpEntity where
  type JS M.PublicKeyCredentialRpEntity = JS.PublicKeyCredentialRpEntity

instance Convert M.UserHandle where
  type JS M.UserHandle = JS.BufferSource

instance Convert M.UserAccountDisplayName where
  type JS M.UserAccountDisplayName = JS.DOMString

instance Convert M.UserAccountName where
  type JS M.UserAccountName = JS.DOMString

instance Convert M.PublicKeyCredentialUserEntity where
  type JS M.PublicKeyCredentialUserEntity = JS.PublicKeyCredentialUserEntity

instance Convert M.Challenge where
  type JS M.Challenge = JS.BufferSource

instance Convert M.PublicKeyCredentialType where
  type JS M.PublicKeyCredentialType = JS.DOMString

instance Convert PublicKey.COSEAlgorithmIdentifier where
  type JS PublicKey.COSEAlgorithmIdentifier = JS.COSEAlgorithmIdentifier

instance Convert M.PublicKeyCredentialParameters where
  type JS M.PublicKeyCredentialParameters = JS.PublicKeyCredentialParameters

instance Convert M.Timeout where
  type JS M.Timeout = JS.UnsignedLong

instance Convert M.CredentialId where
  type JS M.CredentialId = JS.BufferSource

instance Convert M.AuthenticatorTransport where
  type JS M.AuthenticatorTransport = JS.DOMString

instance Convert M.PublicKeyCredentialDescriptor where
  type JS M.PublicKeyCredentialDescriptor = JS.PublicKeyCredentialDescriptor

instance Convert M.AuthenticatorAttachment where
  type JS M.AuthenticatorAttachment = JS.DOMString

instance Convert M.ResidentKeyRequirement where
  type JS M.ResidentKeyRequirement = JS.DOMString

instance Convert M.UserVerificationRequirement where
  type JS M.UserVerificationRequirement = JS.DOMString

instance Convert M.AuthenticatorSelectionCriteria where
  type JS M.AuthenticatorSelectionCriteria = JS.AuthenticatorSelectionCriteria

instance Convert M.AttestationConveyancePreference where
  type JS M.AttestationConveyancePreference = JS.DOMString

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
  type JS (M.CollectedClientData t) = JS.ArrayBuffer

instance Convert M.AttestationObject where
  type JS M.AttestationObject = JS.ArrayBuffer

instance Convert M.AssertionSignature where
  type JS M.AssertionSignature = JS.ArrayBuffer

instance Convert (M.AuthenticatorData 'M.Get) where
  type JS (M.AuthenticatorData 'M.Get) = JS.ArrayBuffer
