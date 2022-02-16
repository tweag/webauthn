{-# OPTIONS_GHC -Wno-missing-import-lists #-}

-- | Stability: experimental
-- This module ncludes everything needed to encode\/decode WebAuthn types
-- between serializations and Haskell types defined in "Crypto.WebAuthn.Model".
module Crypto.WebAuthn.Encoding
  ( -- * webauthn-json serialization

    -- This module includes encoding and decoding functions for messages
    -- exchanged with the
    -- [webauthn-json](https://github.com/github/webauthn-json) JavaScript
    -- library.
    module Crypto.WebAuthn.Encoding.WebAuthnJson,

    -- * Binary fields

    -- WebAuthn defines several structures that employ a binary serialization,
    -- such as
    -- [clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
    -- or [authenticator
    -- data](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata).
    -- This module exposes functions for encoding/decoding such fields, using
    -- types from "Crypto.WebAuthn.Model". This is useful for defining
    -- serializations alternative to the webauthn-json one.
    module Crypto.WebAuthn.Encoding.Binary,

    -- * Enum strings

    -- WebAuthn also defines several enumerations, which can be translated
    -- to\/from their respective Haskell types in "Crypto.WebAuthn.Model" using
    -- this module. This is useful for defining serializations alternative to
    -- the webauthn-json one.
    module Crypto.WebAuthn.Encoding.Strings,
  )
where

import Crypto.WebAuthn.Encoding.Binary
import Crypto.WebAuthn.Encoding.Strings
import Crypto.WebAuthn.Encoding.WebAuthnJson
