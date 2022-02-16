-- | Stability: experimental
-- | This module defines some types from the [Web IDL](https://webidl.spec.whatwg.org/) specification
module Crypto.WebAuthn.WebIDL
  ( DOMString,
    USVString,
    UnsignedLongLong,
    UnsignedLong,
    Long,
    UnsignedShort,
    Octet,
    Boolean,
    Crypto.WebAuthn.WebIDL.Double,
  )
where

import Data.Int (Int32)
import Data.Text (Text)
import Data.Word (Word16, Word32, Word64, Word8)

-- | [(spec)](https://webidl.spec.whatwg.org/#idl-DOMString)
-- The `[DOMString](https://webidl.spec.whatwg.org/#idl-DOMString)` type
-- corresponds to the set of all possible sequences of
-- [code units](https://webidl.spec.whatwg.org/#dfn-code-unit). Such sequences
-- are commonly interpreted as UTF-16 encoded strings
-- [RFC2781](https://webidl.spec.whatwg.org/#biblio-rfc2781) although this is not required.
-- TODO: This implementation doesn't allow invalid UTF-16 codepoints, which
-- probably makes it not work regarding <https://www.w3.org/TR/webauthn-2/#sctn-strings>
-- Write a test case that doesn't work and find a better representation.
type DOMString = Text

-- | [(spec)](https://webidl.spec.whatwg.org/#idl-USVString)
-- The `[USVString](https://webidl.spec.whatwg.org/#idl-USVString)` type
-- corresponds to the set of all possible sequences of
-- [Unicode scalar values](http://www.unicode.org/glossary/#unicode_scalar_value),
-- which are all of the Unicode code points apart from the surrogate code points.
-- TODO: This implementation allows for surrogate code points. Figure out if
-- this can violate the spec in any way.
type USVString = Text

-- | [(spec)](https://webidl.spec.whatwg.org/#idl-unsigned-long)
type UnsignedLong = Word32

-- | [(spec)](https://webidl.spec.whatwg.org/#idl-unsigned-long)
type UnsignedLongLong = Word64

-- | [(spec)](https://webidl.spec.whatwg.org/#idl-long)
type Long = Int32

-- | [(spec)](https://webidl.spec.whatwg.org/#idl-unsigned-short)
type UnsignedShort = Word16

-- | [(spec)](https://webidl.spec.whatwg.org/#idl-octet)
type Octet = Word8

-- | [(spec)](https://webidl.spec.whatwg.org/#idl-boolean)
type Boolean = Bool

-- | [(spec)](https://webidl.spec.whatwg.org/#idl-double)
type Double = Prelude.Double
