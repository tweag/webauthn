{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeFamilies #-}

-- | Stability: internal
-- This module maps every Model type to a WebIDL type. As the name of the
-- module and typclass suggest, this is used to perform the conversion between
-- the WebIDL and Model representations.
module Crypto.WebAuthn.Model.WebIDL.Internal.Convert
  ( Convert (..),
  )
where

import qualified Crypto.WebAuthn.Cose.Algorithm as Cose
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Crypto.WebAuthn.Model.WebIDL.Types as IDL
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.Kind (Type)
import Data.Map (Map)
import Data.Text (Text)

-- | @'Convert' hs@ indicates that the Haskell-specific type @hs@ has a more
-- general JavaScript-specific type associated with it, which can be accessed with 'IDL'.
class Convert hs where
  type IDL hs :: Type

instance Convert hs => Convert (Maybe hs) where
  type IDL (Maybe hs) = Maybe (IDL hs)

instance Convert M.RpId where
  type IDL M.RpId = IDL.DOMString

instance Convert M.RelyingPartyName where
  type IDL M.RelyingPartyName = IDL.DOMString

instance Convert M.CredentialRpEntity where
  type IDL M.CredentialRpEntity = IDL.PublicKeyCredentialRpEntity

instance Convert M.UserHandle where
  type IDL M.UserHandle = IDL.BufferSource

instance Convert M.UserAccountDisplayName where
  type IDL M.UserAccountDisplayName = IDL.DOMString

instance Convert M.UserAccountName where
  type IDL M.UserAccountName = IDL.DOMString

instance Convert M.CredentialUserEntity where
  type IDL M.CredentialUserEntity = IDL.PublicKeyCredentialUserEntity

instance Convert M.Challenge where
  type IDL M.Challenge = IDL.BufferSource

instance Convert M.CredentialType where
  type IDL M.CredentialType = IDL.DOMString

instance Convert Cose.CoseSignAlg where
  type IDL Cose.CoseSignAlg = IDL.COSEAlgorithmIdentifier

instance Convert [M.CredentialParameters] where
  type IDL [M.CredentialParameters] = [IDL.PublicKeyCredentialParameters]

instance Convert M.Timeout where
  type IDL M.Timeout = IDL.UnsignedLong

instance Convert M.CredentialId where
  type IDL M.CredentialId = IDL.BufferSource

instance Convert [M.AuthenticatorTransport] where
  type IDL [M.AuthenticatorTransport] = [IDL.DOMString]

instance Convert M.CredentialDescriptor where
  type IDL M.CredentialDescriptor = IDL.PublicKeyCredentialDescriptor

instance Convert [M.CredentialDescriptor] where
  type IDL [M.CredentialDescriptor] = Maybe [IDL.PublicKeyCredentialDescriptor]

instance Convert M.AuthenticatorAttachment where
  type IDL M.AuthenticatorAttachment = IDL.DOMString

instance Convert M.ResidentKeyRequirement where
  type IDL M.ResidentKeyRequirement = Maybe IDL.DOMString

instance Convert M.UserVerificationRequirement where
  type IDL M.UserVerificationRequirement = Maybe IDL.DOMString

instance Convert M.AuthenticatorSelectionCriteria where
  type IDL M.AuthenticatorSelectionCriteria = IDL.AuthenticatorSelectionCriteria

instance Convert M.AttestationConveyancePreference where
  type IDL M.AttestationConveyancePreference = Maybe IDL.DOMString

instance Convert M.AuthenticationExtensionsClientInputs where
  type IDL M.AuthenticationExtensionsClientInputs = Map Text Aeson.Value

instance Convert (M.CredentialOptions 'K.Registration) where
  type IDL (M.CredentialOptions 'K.Registration) = IDL.PublicKeyCredentialCreationOptions

instance Convert (M.CredentialOptions 'K.Authentication) where
  type IDL (M.CredentialOptions 'K.Authentication) = IDL.PublicKeyCredentialRequestOptions

instance Convert (M.Credential 'K.Registration raw) where
  type IDL (M.Credential 'K.Registration raw) = IDL.PublicKeyCredential IDL.AuthenticatorAttestationResponse

instance Convert (M.AuthenticatorResponse 'K.Registration raw) where
  type IDL (M.AuthenticatorResponse 'K.Registration raw) = IDL.AuthenticatorAttestationResponse

instance Convert (M.Credential 'K.Authentication raw) where
  type IDL (M.Credential 'K.Authentication raw) = IDL.PublicKeyCredential IDL.AuthenticatorAssertionResponse

instance Convert (M.AuthenticatorResponse 'K.Authentication raw) where
  type IDL (M.AuthenticatorResponse 'K.Authentication raw) = IDL.AuthenticatorAssertionResponse

instance Convert M.AuthenticationExtensionsClientOutputs where
  type IDL M.AuthenticationExtensionsClientOutputs = Map Text Aeson.Value

instance Convert (M.CollectedClientData c 'True) where
  type IDL (M.CollectedClientData c 'True) = IDL.ArrayBuffer

instance Convert (M.AttestationObject 'True) where
  type IDL (M.AttestationObject 'True) = IDL.ArrayBuffer

instance Convert M.AssertionSignature where
  type IDL M.AssertionSignature = IDL.ArrayBuffer

instance Convert (M.AuthenticatorData 'K.Authentication raw) where
  type IDL (M.AuthenticatorData 'K.Authentication raw) = IDL.ArrayBuffer
