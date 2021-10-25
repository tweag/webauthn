{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE ExplicitNamespaces #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Include
module Crypto.Fido2.PublicKey
  ( COSEAlgorithmIdentifier (..),
    PublicKey (..),
    verify,
    decodePublicKey,
  )
where

import qualified Codec.CBOR.Decoding as CBOR
import Control.Monad (unless, when)
import Crypto.Error (CryptoFailable (CryptoFailed, CryptoPassed))
import Crypto.Hash (HashAlgorithm)
import qualified Crypto.Hash.Algorithms as Hash
import Crypto.Number.Serialize (os2ip)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Prim as ASN1
import Data.ByteString (ByteString)
import Data.Typeable (Typeable)
import Type.Reflection (eqTypeRep, typeOf, type (:~~:) (HRefl))

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier)
-- A 'COSEAlgorithmIdentifier''s value is a number identifying a cryptographic algorithm.
-- The algorithm identifiers SHOULD be values registered in the IANA COSE Algorithms
-- registry [IANA-COSE-ALGS-REG](https://www.w3.org/TR/webauthn-2/#biblio-iana-cose-algs-reg),
-- for instance, -7 for "ES256" and -257 for "RS256".
data COSEAlgorithmIdentifier
  = COSEAlgorithmIdentifierES256
  | COSEAlgorithmIdentifierES384
  | COSEAlgorithmIdentifierES512
  | COSEAlgorithmIdentifierEdDSA
  deriving (Eq, Show, Bounded, Enum, Ord)

data PublicKey
  = ECDSAPublicKey SomeHashAlgorithm ECDSA.PublicKey
  | Ed25519PublicKey Ed25519.PublicKey
  deriving (Eq, Show)

data SomeHashAlgorithm = forall hash. (Show hash, Typeable hash, HashAlgorithm hash) => SomeHashAlgorithm hash

deriving instance Show SomeHashAlgorithm

instance Eq SomeHashAlgorithm where
  SomeHashAlgorithm lHash == SomeHashAlgorithm rHash =
    case eqTypeRep (typeOf lHash) (typeOf rHash) of
      Just HRefl -> True
      Nothing -> False

data KeyType = OKP | ECC

data MapKey = Kty | Alg | Crv | X | Y deriving (Show, Eq)

data CurveIdentifier = P256 | P384 | P521
  deriving (Eq)

decodePublicKey :: CBOR.Decoder s PublicKey
decodePublicKey = do
  decodeMapKey Kty
  kty <- decodeKeyType
  case kty of
    OKP -> decodeEd25519PublicKey
    ECC -> decodeECDSAPublicKey
  where
    decodeEd25519PublicKey :: CBOR.Decoder s PublicKey
    decodeEd25519PublicKey = do
      decodeMapKey Alg
      alg <- decodeCOSEAlgorithmIdentifier
      when (alg /= COSEAlgorithmIdentifierEdDSA) $ fail "Unsupported `alg`"
      decodeMapKey Crv
      crv <- CBOR.decodeIntCanonical
      decodeMapKey X
      x <- CBOR.decodeBytesCanonical
      case crv of
        6 ->
          -- TODO: left?
          case Ed25519.publicKey x of
            CryptoFailed e -> fail (show e)
            CryptoPassed a -> pure $ Ed25519PublicKey a
        _ -> fail "Unsupported `crv`"

    decodeECDSAPublicKey :: CBOR.Decoder s PublicKey
    decodeECDSAPublicKey = do
      decodeMapKey Alg
      alg <- decodeCOSEAlgorithmIdentifier
      hash <- case alg of
        COSEAlgorithmIdentifierES256 -> pure $ SomeHashAlgorithm Hash.SHA256
        COSEAlgorithmIdentifierES384 -> pure $ SomeHashAlgorithm Hash.SHA384
        COSEAlgorithmIdentifierES512 -> pure $ SomeHashAlgorithm Hash.SHA512
        _ -> fail "Unsupported `alg`"
      decodeMapKey Crv
      curveIdentifier <- decodeCurveIdentifier
      curveIdentifier' <- curveForAlg alg
      let curve = toCurve curveIdentifier
      when (curveIdentifier /= curveIdentifier') $ fail "Curve must match alg. See <section>"
      decodeMapKey X
      -- Extracting the x and y values of the point is counterproductive for the Fido-U2F attestation
      -- However, since it is still useful otherwise we do perform it.
      -- During Fifo-U2F attestation, the value is converted back into a ByteArray representation.
      x <- os2ip <$> CBOR.decodeBytesCanonical
      decodeMapKey Y
      tokenType <- CBOR.peekTokenType
      y <- case tokenType of
        -- TODO(arianvp): Implement compressed curve. Waiting for
        -- https://github.com/haskell-crypto/cryptonite/issues/302
        CBOR.TypeBool -> fail "Compressed format not supported _yet_ See Issue number X"
        -- direct coordinate
        CBOR.TypeBytes -> os2ip <$> CBOR.decodeBytesCanonical
        _ -> fail "Unexpected token type"
      let point = ECC.Point x y
      unless (ECC.isPointValid curve point) $ fail "point not on curve"
      pure $ ECDSAPublicKey hash (ECDSA.PublicKey curve point)

    mapKeyToInt :: MapKey -> Int
    mapKeyToInt key = case key of
      Kty -> 1
      Alg -> 3
      Crv -> -1
      X -> -2
      Y -> -3

    decodeKeyType :: CBOR.Decoder s KeyType
    decodeKeyType = do
      kty <- CBOR.decodeIntCanonical
      case kty of
        1 -> pure OKP
        2 -> pure ECC
        x -> fail $ "unexpected kty: " ++ show x

    curveForAlg :: MonadFail f => COSEAlgorithmIdentifier -> f CurveIdentifier
    curveForAlg COSEAlgorithmIdentifierES256 = pure P256
    curveForAlg COSEAlgorithmIdentifierES384 = pure P384
    curveForAlg COSEAlgorithmIdentifierES512 = pure P521
    curveForAlg _ = fail "No associated curve identifier"

    toCurve :: CurveIdentifier -> ECC.Curve
    toCurve P256 = ECC.getCurveByName ECC.SEC_p256r1
    toCurve P384 = ECC.getCurveByName ECC.SEC_p384r1
    toCurve P521 = ECC.getCurveByName ECC.SEC_p521r1

    decodeCurveIdentifier :: CBOR.Decoder s CurveIdentifier
    decodeCurveIdentifier = do
      crv <- CBOR.decodeIntCanonical
      case crv of
        1 -> pure P256
        2 -> pure P384
        3 -> pure P521
        _ -> fail "Unsupported `crv`"

    decodeMapKey :: MapKey -> CBOR.Decoder s ()
    decodeMapKey key = do
      key' <- CBOR.decodeIntCanonical
      when (mapKeyToInt key /= key') $ fail $ "Expected " ++ show key

    -- All CBOR is encoded using
    -- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#ctap2-canonical-cbor-encoding-form

    --
    -- a signature decoding uniquely belongs to an algorithm identifier. how do we
    -- encode this correspondence?
    decodeCOSEAlgorithmIdentifier :: CBOR.Decoder s COSEAlgorithmIdentifier
    decodeCOSEAlgorithmIdentifier =
      toAlg =<< CBOR.decodeIntCanonical

    toAlg :: (Eq a, Num a, MonadFail f) => a -> f COSEAlgorithmIdentifier
    toAlg (-7) = pure COSEAlgorithmIdentifierES256
    toAlg (-35) = pure COSEAlgorithmIdentifierES384
    toAlg (-36) = pure COSEAlgorithmIdentifierES512
    toAlg (-8) = pure COSEAlgorithmIdentifierEdDSA
    toAlg _ = fail "Unsupported `alg`"

-- | Decodes a signature for a specific public key's type
-- Signatures are a bit weird in Webauthn.  For ES256 and RS256 they're ASN.1
-- and for EdDSA they're COSE
decodeECDSASignature :: ByteString -> Maybe ECDSA.Signature
decodeECDSASignature sigbs =
  case ASN1.decodeASN1' ASN1.BER sigbs of
    Left _ -> Nothing
    Right [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence] ->
      Just (ECDSA.Signature r s)
    Right _ -> Nothing

verify :: PublicKey -> ByteString -> ByteString -> Bool
verify (ECDSAPublicKey (SomeHashAlgorithm hash) key) msg sig = case decodeECDSASignature sig of
  Nothing -> False
  Just sig -> ECDSA.verify hash key sig msg
verify (Ed25519PublicKey key) msg sig =
  case Ed25519.signature sig of
    CryptoPassed sig -> Ed25519.verify key msg sig
    CryptoFailed _ -> False
