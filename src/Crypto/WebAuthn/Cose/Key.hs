{-# LANGUAGE RecordWildCards #-}

-- | This module contains a partial implementation of the
-- [COSE_Key](https://datatracker.ietf.org/doc/html/rfc8152#section-7) format,
-- limited to what is needed for Webauthn, and in a structured way.
module Crypto.WebAuthn.Cose.Key
  ( -- * COSE public Key
    CosePublicKey (..),
    keySignAlg,

    -- * COSE Elliptic Curves
    CoseCurveEdDSA (..),
    CoseCurveECDSA (..),
  )
where

import Codec.CBOR.Decoding (Decoder, TokenType (TypeBool, TypeBytes), decodeBytesCanonical, decodeMapLenCanonical, peekTokenType)
import Codec.CBOR.Encoding (Encoding, encodeBytes, encodeMapLen)
import Codec.Serialise (Serialise (decode, encode))
import Control.Monad (unless)
import Crypto.Number.Serialize (i2osp, os2ip)
import qualified Crypto.WebAuthn.Cose.Registry as R
import Crypto.WebAuthn.Internal.ToJSONOrphans ()
import Data.Aeson (ToJSON)
import qualified Data.ByteString as BS
import GHC.Generics (Generic)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#credentialpublickey)
-- A structured representation of a [COSE_Key](https://datatracker.ietf.org/doc/html/rfc8152#section-7)
-- limited to what is know to be necessary for Webauthn public keys for the
-- [credentialPublicKey](https://www.w3.org/TR/webauthn-2/#credentialpublickey) field.
-- Constructors represent signature algorithms.
data CosePublicKey
  = -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-2.2)
    -- EdDSA Signature Algorithm
    --
    -- [RFC8032](https://datatracker.ietf.org/doc/html/rfc8032) describes the
    -- elliptic curve signature scheme Edwards-curve
    -- Digital Signature Algorithm (EdDSA). In that document, the signature
    -- algorithm is instantiated using parameters for edwards25519 and
    -- edwards448 curves. The document additionally describes two variants
    -- of the EdDSA algorithm: Pure EdDSA, where no hash function is applied
    -- to the content before signing, and HashEdDSA, where a hash function
    -- is applied to the content before signing and the result of that hash
    -- function is signed. For EdDSA, the content to be signed (either the
    -- message or the pre-hash value) is processed twice inside of the
    -- signature algorithm. For use with COSE, only the pure EdDSA version
    -- is used.
    --
    -- Security considerations are [here](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-2.2.1)
    CosePublicKeyEdDSA
      { -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.2)
        -- The elliptic curve to use
        eddsaCurve :: CoseCurveEdDSA,
        -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.2)
        -- This contains the public key bytes
        eddsaX :: BS.ByteString
      }
  | -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-2.1)
    -- ECDSA Signature Algorithm
    --
    -- This document defines ECDSA to work only with the curves P-256,
    -- P-384, and P-521. Future documents may define it to work with other
    -- curves and points in the future.
    --
    -- In order to promote interoperability, it is suggested that SHA-256 be
    -- used only with curve P-256, SHA-384 be used only with curve P-384,
    -- and SHA-512 be used with curve P-521. This is aligned with the recommendation in
    -- [Section 4 of RFC5480](https://datatracker.ietf.org/doc/html/rfc5480#section-4).
    --
    -- Security considerations are [here](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-2.1.1)
    CosePublicKeyECDSA
      { -- | The hash function to use
        ecdsaHash :: R.CoseHashAlgECDSA,
        -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1.1)
        -- The elliptic curve to use
        ecdsaCurve :: CoseCurveECDSA,
        -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1.1)
        -- This contains the x-coordinate for the EC point. The integer is
        -- converted to a byte string as defined in [SEC1]. Leading zero
        -- octets MUST be preserved.
        ecdsaX :: BS.ByteString,
        -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1.1)
        -- This contains the value of the
        -- y-coordinate for the EC point. When encoding the value y, the
        -- integer is converted to an byte string (as defined in
        -- [SEC1](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#ref-SEC1))
        -- and encoded as a CBOR bstr. Leading zero octets MUST be
        -- preserved.
        ecdsaY :: BS.ByteString
      }
  | -- | [(spec)](https://www.rfc-editor.org/rfc/rfc8812.html#section-2)
    -- [RSASSA-PKCS1-v1_5](https://www.rfc-editor.org/rfc/rfc8017#section-8.2) Signature Algorithm
    --
    -- A key of size 2048 bits or larger MUST be used with these algorithms.
    -- Security considerations are [here](https://www.rfc-editor.org/rfc/rfc8812.html#section-5)
    CosePublicKeyRSA
      { -- | The hash function to use
        rsaHash :: R.CoseHashAlgRSA,
        -- | [(spec)](https://www.rfc-editor.org/rfc/rfc8230.html#section-4)
        -- The RSA modulus n is a product of u distinct odd primes
        -- r_i, i = 1, 2, ..., u, where u >= 2
        rsaN :: Integer,
        -- | [(spec)](https://www.rfc-editor.org/rfc/rfc8230.html#section-4)
        -- The RSA public exponent e is an integer between 3 and n - 1 satisfying
        -- GCD(e,\\lambda(n)) = 1, where \\lambda(n) = LCM(r_1 - 1, ..., r_u - 1)
        rsaE :: Integer
      }
  deriving (Eq, Show, Generic, ToJSON)

-- | CBOR encoding as a [COSE_Key](https://tools.ietf.org/html/rfc8152#section-7)
-- using the [CTAP2 canonical CBOR encoding form](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form)
instance Serialise CosePublicKey where
  encode key = case key of
    CosePublicKeyEdDSA {..} ->
      common R.CoseKeyTypeOKP
        <> encode R.CoseKeyTypeParameterOKPCrv
        <> encode (fromCurveEdDSA eddsaCurve)
        <> encode R.CoseKeyTypeParameterOKPX
        <> encodeBytes eddsaX
    CosePublicKeyECDSA {..} ->
      common R.CoseKeyTypeEC2
        <> encode R.CoseKeyTypeParameterEC2Crv
        <> encode (fromCurveECDSA ecdsaCurve)
        -- https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1.1
        -- > Leading zero octets MUST be preserved.
        <> encode R.CoseKeyTypeParameterEC2X
        <> encodeBytes ecdsaX
        <> encode R.CoseKeyTypeParameterEC2Y
        <> encodeBytes ecdsaY
    CosePublicKeyRSA {..} ->
      common R.CoseKeyTypeRSA
        -- https://www.rfc-editor.org/rfc/rfc8230.html#section-4
        -- > The octet sequence MUST utilize the minimum
        -- number of octets needed to represent the value.
        <> encode R.CoseKeyTypeParameterRSAN
        <> encodeBytes (i2osp rsaN)
        <> encode R.CoseKeyTypeParameterRSAE
        <> encodeBytes (i2osp rsaE)
    where
      alg = keySignAlg key
      common :: R.CoseKeyType -> Encoding
      common kty =
        encodeMapLen (R.parameterCount kty)
          <> encode R.CoseKeyCommonParameterKty
          <> encode kty
          <> encode R.CoseKeyCommonParameterAlg
          <> encode alg

  -- NOTE: CBOR itself doesn't give an ordering of map keys, but the CTAP2 canonical CBOR encoding form does:
  -- > The keys in every map must be sorted lowest value to highest. The sorting rules are:
  -- >
  -- > * If the major types are different, the one with the lower value in numerical order sorts earlier.
  -- > * If two keys have different lengths, the shorter one sorts earlier;
  -- > * If two keys have the same length, the one with the lower value in (byte-wise) lexical order sorts earlier.
  --
  -- This has the effect that numeric keys are sorted like 1, 2, 3, ..., -1, -2, -3, ...
  -- Which aligns very nicely with the fact that common parameters use positive
  -- values and can therefore be decoded first, while key type specific
  -- parameters use negative values
  decode = do
    n <- fromIntegral <$> decodeMapLenCanonical
    -- https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-struct-15#section-7.1
    -- This parameter MUST be present in a key object.
    decodeExpected R.CoseKeyCommonParameterKty
    kty <- decode
    -- https://www.w3.org/TR/webauthn-2/#credentialpublickey
    -- The COSE_Key-encoded credential public key MUST contain the "alg"
    -- parameter and MUST NOT contain any other OPTIONAL parameters.
    decodeExpected R.CoseKeyCommonParameterAlg
    alg <- decode

    decodeKey n kty alg
    where
      decodeKey :: Word -> R.CoseKeyType -> R.CoseSignAlg -> Decoder s CosePublicKey
      decodeKey n kty alg = case alg of
        R.CoseSignAlgEdDSA -> decodeEdDSAKey
        R.CoseSignAlgECDSA hash -> decodeECDSAKey hash
        R.CoseSignAlgRSA hash -> decodeRSAKey hash
        where
          -- [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-struct-15#section-7.1)
          -- Implementations MUST verify that the key type is appropriate for
          -- the algorithm being processed.
          checkKty :: R.CoseKeyType -> Decoder s ()
          checkKty expectedKty = do
            unless (expectedKty == kty) $
              fail $
                "Expected COSE key type "
                  <> show expectedKty
                  <> " for COSE algorithm "
                  <> show alg
                  <> " but got COSE key type "
                  <> show kty
                  <> " instead"
            unless (R.parameterCount kty == n) $
              fail $
                "Expected CBOR map to contain "
                  <> show (R.parameterCount kty)
                  <> " parameters for COSE key type "
                  <> show kty
                  <> " but got "
                  <> show n
                  <> " parameters instead"

          decodeEdDSAKey :: Decoder s CosePublicKey
          decodeEdDSAKey = do
            -- https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-2.2
            -- > The 'kty' field MUST be present, and it MUST be 'OKP' (Octet Key Pair).
            checkKty R.CoseKeyTypeOKP
            -- https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.2
            decodeExpected R.CoseKeyTypeParameterOKPCrv
            eddsaCurve <- toCurveEdDSA <$> decode
            decodeExpected R.CoseKeyTypeParameterOKPX
            eddsaX <- decodeBytesCanonical
            pure $ CosePublicKeyEdDSA {..}

          decodeECDSAKey :: R.CoseHashAlgECDSA -> Decoder s CosePublicKey
          decodeECDSAKey ecdsaHash = do
            -- https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-2.1
            -- > The 'kty' field MUST be present, and it MUST be 'EC2'.
            checkKty R.CoseKeyTypeEC2
            -- https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1.1
            decodeExpected R.CoseKeyTypeParameterEC2Crv
            ecdsaCurve <- toCurveECDSA <$> decode
            decodeExpected R.CoseKeyTypeParameterEC2X
            ecdsaX <- decodeBytesCanonical
            decodeExpected R.CoseKeyTypeParameterEC2Y
            ecdsaY <-
              peekTokenType >>= \case
                TypeBytes -> decodeBytesCanonical
                -- TODO: Implement this
                TypeBool -> fail "Compressed EC2 y coordinate not yet supported"
                typ -> fail $ "Unexpected type in EC2 y parameter: " <> show typ
            pure $ CosePublicKeyECDSA {..}

          decodeRSAKey :: R.CoseHashAlgRSA -> Decoder s CosePublicKey
          decodeRSAKey rsaHash = do
            -- https://www.rfc-editor.org/rfc/rfc8812.html#section-2
            -- > Implementations need to check that the key type is 'RSA' when creating or verifying a signature.
            checkKty R.CoseKeyTypeRSA
            -- https://www.rfc-editor.org/rfc/rfc8230.html#section-4
            decodeExpected R.CoseKeyTypeParameterRSAN
            rsaN <- os2ip <$> decodeBytesCanonical
            decodeExpected R.CoseKeyTypeParameterRSAE
            rsaE <- os2ip <$> decodeBytesCanonical
            pure $ CosePublicKeyRSA {..}

-- | Decode a value and ensure it's the same as the value that was given
decodeExpected :: (Show a, Eq a, Serialise a) => a -> Decoder s ()
decodeExpected expected = do
  actual <- decode
  unless (expected == actual) $
    fail $ "Expected " <> show expected <> " but got " <> show actual

-- | The COSE signing algorithm corresponding to a COSE public key
keySignAlg :: CosePublicKey -> R.CoseSignAlg
keySignAlg CosePublicKeyEdDSA {} = R.CoseSignAlgEdDSA
keySignAlg CosePublicKeyECDSA {..} = R.CoseSignAlgECDSA ecdsaHash
keySignAlg CosePublicKeyRSA {..} = R.CoseSignAlgRSA rsaHash

-- | COSE elliptic curves that can be used with EdDSA
data CoseCurveEdDSA
  = -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1)
    -- Ed25519 for use w/ EdDSA only
    CoseCurveEd25519
  deriving (Eq, Show, Enum, Bounded, Generic, ToJSON)

fromCurveEdDSA :: CoseCurveEdDSA -> R.CoseEllipticCurveOKP
fromCurveEdDSA CoseCurveEd25519 = R.CoseEllipticCurveEd25519

toCurveEdDSA :: R.CoseEllipticCurveOKP -> CoseCurveEdDSA
toCurveEdDSA R.CoseEllipticCurveEd25519 = CoseCurveEd25519

-- | COSE elliptic curves that can be used with ECDSA
data CoseCurveECDSA
  = -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1)
    -- NIST P-256 also known as secp256r1
    CoseCurveP256
  | -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1)
    -- NIST P-384 also known as secp384r1
    CoseCurveP384
  | -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1)
    -- NIST P-521 also known as secp521r1
    CoseCurveP521
  deriving (Eq, Show, Enum, Bounded, Generic, ToJSON)

fromCurveECDSA :: CoseCurveECDSA -> R.CoseEllipticCurveEC2
fromCurveECDSA CoseCurveP256 = R.CoseEllipticCurveEC2P256
fromCurveECDSA CoseCurveP384 = R.CoseEllipticCurveEC2P384
fromCurveECDSA CoseCurveP521 = R.CoseEllipticCurveEC2P521

toCurveECDSA :: R.CoseEllipticCurveEC2 -> CoseCurveECDSA
toCurveECDSA R.CoseEllipticCurveEC2P256 = CoseCurveP256
toCurveECDSA R.CoseEllipticCurveEC2P384 = CoseCurveP384
toCurveECDSA R.CoseEllipticCurveEC2P521 = CoseCurveP521
