{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.WebAuthn.Model.WebIDL.Internal.Convert
  ( Convert (..),
  )
where

import qualified Crypto.WebAuthn.Cose.Registry as Cose
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Crypto.WebAuthn.Model.WebIDL.Types as IDL
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
  type JS M.PublicKeyCredentialRpEntity = IDL.PublicKeyCredentialRpEntity

instance Convert M.UserHandle where
  type JS M.UserHandle = IDL.BufferSource

instance Convert M.UserAccountDisplayName where
  type JS M.UserAccountDisplayName = IDL.DOMString

instance Convert M.UserAccountName where
  type JS M.UserAccountName = IDL.DOMString

instance Convert M.PublicKeyCredentialUserEntity where
  type JS M.PublicKeyCredentialUserEntity = IDL.PublicKeyCredentialUserEntity

instance Convert M.Challenge where
  type JS M.Challenge = IDL.BufferSource

instance Convert M.PublicKeyCredentialType where
  type JS M.PublicKeyCredentialType = IDL.DOMString

instance Convert Cose.CoseSignAlg where
  type JS Cose.CoseSignAlg = IDL.COSEAlgorithmIdentifier

instance Convert [M.PublicKeyCredentialParameters] where
  type JS [M.PublicKeyCredentialParameters] = [IDL.PublicKeyCredentialParameters]

instance Convert M.Timeout where
  type JS M.Timeout = IDL.UnsignedLong

instance Convert M.CredentialId where
  type JS M.CredentialId = IDL.BufferSource

instance Convert [M.AuthenticatorTransport] where
  type JS [M.AuthenticatorTransport] = [IDL.DOMString]

instance Convert M.PublicKeyCredentialDescriptor where
  type JS M.PublicKeyCredentialDescriptor = IDL.PublicKeyCredentialDescriptor

instance Convert [M.PublicKeyCredentialDescriptor] where
  type JS [M.PublicKeyCredentialDescriptor] = Maybe [IDL.PublicKeyCredentialDescriptor]

instance Convert M.AuthenticatorAttachment where
  type JS M.AuthenticatorAttachment = IDL.DOMString

instance Convert M.ResidentKeyRequirement where
  type JS M.ResidentKeyRequirement = Maybe IDL.DOMString

instance Convert M.UserVerificationRequirement where
  type JS M.UserVerificationRequirement = Maybe IDL.DOMString

instance Convert M.AuthenticatorSelectionCriteria where
  type JS M.AuthenticatorSelectionCriteria = IDL.AuthenticatorSelectionCriteria

instance Convert M.AttestationConveyancePreference where
  type JS M.AttestationConveyancePreference = Maybe IDL.DOMString

instance Convert M.AuthenticationExtensionsClientInputs where
  type JS M.AuthenticationExtensionsClientInputs = Map Text Aeson.Value

instance Convert (M.PublicKeyCredentialOptions 'M.Create) where
  type JS (M.PublicKeyCredentialOptions 'M.Create) = IDL.PublicKeyCredentialCreationOptions

instance Convert (M.PublicKeyCredentialOptions 'M.Get) where
  type JS (M.PublicKeyCredentialOptions 'M.Get) = IDL.PublicKeyCredentialRequestOptions

instance Convert (M.PublicKeyCredential 'M.Create raw) where
  type JS (M.PublicKeyCredential 'M.Create raw) = IDL.PublicKeyCredential IDL.AuthenticatorAttestationResponse

instance Convert (M.AuthenticatorResponse 'M.Create raw) where
  type JS (M.AuthenticatorResponse 'M.Create raw) = IDL.AuthenticatorAttestationResponse

instance Convert (M.PublicKeyCredential 'M.Get raw) where
  type JS (M.PublicKeyCredential 'M.Get raw) = IDL.PublicKeyCredential IDL.AuthenticatorAssertionResponse

instance Convert (M.AuthenticatorResponse 'M.Get raw) where
  type JS (M.AuthenticatorResponse 'M.Get raw) = IDL.AuthenticatorAssertionResponse

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
