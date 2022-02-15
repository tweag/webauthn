{-# OPTIONS_GHC -Wno-missing-import-lists #-}

-- | Stability: experimental
-- A set of types representing credential options ('CredentialOptions')
-- and their resulting credentials responses ('Credential').
--
-- Also includes a set of functions for indirectly encoding credential
-- options to JSON ('encodeCredentialOptionsRegistration',
-- 'encodeCredentialOptionsAuthentication') and indirectly decoding
-- credential responses from JSON ('decodeCredentialRegistration',
-- 'decodeCredentialAuthentication'), using the same encoding as
-- [webauthn-json](https://github.com/github/webauthn-json) which can be
-- used on the JavaScript side.
--
-- The types in this module form one way the library represents the WebAuthn
-- types, another are the internal WebIDL modules, which is a lower-level, more
-- one-to-one mapping. As a user of the library, you will most likely use the
-- representation in this module over the one in the WebIDL modules.
--
-- This module is reexported by the "Crypto.WebAuthn" module, which is the
-- preferred way of using it.
module Crypto.WebAuthn.Model
  ( module Crypto.WebAuthn.Model.Defaults,
    module Crypto.WebAuthn.Model.Identifier,
    module Crypto.WebAuthn.Model.Kinds,
    module Crypto.WebAuthn.Model.Types,
    module Crypto.WebAuthn.Model.WebIDL,
    module Crypto.WebAuthn.Cose.SignAlg,
    module Crypto.WebAuthn.Cose.PublicKeyWithSignAlg,
    module Crypto.WebAuthn.Cose.PublicKey,
  )
where

import Crypto.WebAuthn.Cose.PublicKey
import Crypto.WebAuthn.Cose.PublicKeyWithSignAlg
import Crypto.WebAuthn.Cose.SignAlg
import Crypto.WebAuthn.Model.Defaults
import Crypto.WebAuthn.Model.Identifier
import Crypto.WebAuthn.Model.Kinds
import Crypto.WebAuthn.Model.Types
import Crypto.WebAuthn.Model.WebIDL
