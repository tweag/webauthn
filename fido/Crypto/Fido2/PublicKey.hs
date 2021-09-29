{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Include
module Crypto.Fido2.PublicKey
  ( COSEAlgorithmIdentifier (..),
    ECDSAIdentifier (..),
    EdDSAKey (..),
    ECDSAKey (..),
    CurveIdentifier (..),
    PublicKey (..),
    toCurve,
    verify,
    curveForAlg,
    toAlg,
    keyAlgorithm,
    toPublicKey,
  )
where

import Codec.CBOR.Decoding (Decoder)
import qualified Codec.CBOR.Decoding as CBOR
import Codec.CBOR.Encoding (Encoding)
import qualified Codec.CBOR.Encoding as CBOR
import Codec.Serialise.Class (Serialise, decode, encode)
import Control.Monad (unless, when)
import Crypto.Error (CryptoFailable (CryptoFailed, CryptoPassed))
import qualified Crypto.Hash.Algorithms as Hash
import Crypto.Number.Serialize (i2osp, os2ip)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import Crypto.PubKey.ECC.Types (getCurveByName)
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Prim as ASN1
import Data.Aeson.Types (ToJSON (toJSON))
import qualified Data.Aeson.Types as Aeson
import qualified Data.ByteArray as ByteArray
import Data.ByteString (ByteString)
import Data.X509 (PubKey (PubKeyEC, PubKeyEd25519), PubKeyEC (pubkeyEC_pub))
import Data.X509.EC (ecPubKeyCurveName, unserializePoint)

data ECDSAIdentifier
  = ES256
  | ES384
  | ES512
  deriving (Show, Eq)

data COSEAlgorithmIdentifier
  = ECDSAIdentifier ECDSAIdentifier
  | EdDSA
  deriving (Show, Eq)

instance Serialise COSEAlgorithmIdentifier where
  encode = encodeCOSEAlgorithmIdentifier
  decode = decodeCOSEAlgorithmIdentifier

-- All CBOR is encoded using
-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#ctap2-canonical-cbor-encoding-form

--
-- a signature decoding uniquely belongs to an algorithm identifier. how do we
-- encode this correspondence?
decodeCOSEAlgorithmIdentifier :: Decoder s COSEAlgorithmIdentifier
decodeCOSEAlgorithmIdentifier =
  toAlg =<< CBOR.decodeIntCanonical

toAlg :: (Eq a, Num a, MonadFail f) => a -> f COSEAlgorithmIdentifier
toAlg (-7) = pure $ ECDSAIdentifier ES256
toAlg (-35) = pure $ ECDSAIdentifier ES384
toAlg (-36) = pure $ ECDSAIdentifier ES512
toAlg (-8) = pure EdDSA
toAlg _ = fail "Unsupported `alg`"

instance ToJSON COSEAlgorithmIdentifier where
  toJSON (ECDSAIdentifier ES256) = Aeson.Number (-7)
  toJSON (ECDSAIdentifier ES384) = Aeson.Number (-35)
  toJSON (ECDSAIdentifier ES512) = Aeson.Number (-36)
  toJSON EdDSA = Aeson.Number (-8)

newtype EdDSAKey = Ed25519 Ed25519.PublicKey
  deriving (Eq, Show)

-- Curves supported by us
data CurveIdentifier = P256 | P384 | P521 deriving (Eq, Show)

toCurve :: CurveIdentifier -> ECC.Curve
toCurve P256 = ECC.getCurveByName ECC.SEC_p256r1
toCurve P384 = ECC.getCurveByName ECC.SEC_p384r1
toCurve P521 = ECC.getCurveByName ECC.SEC_p521r1

fromCurveName :: ECC.CurveName -> CurveIdentifier
fromCurveName ECC.SEC_p256r1 = P256
fromCurveName ECC.SEC_p384r1 = P384
fromCurveName ECC.SEC_p521r1 = P521
fromCurveName _ = error "Unknown curve name"

data ECDSAKey = ECDSAKey ECDSAIdentifier ECC.Point deriving (Eq, Show)

data PublicKey
  = EdDSAPublicKey EdDSAKey
  | ECDSAPublicKey ECDSAKey
  deriving (Show, Eq)

keyAlgorithm :: PublicKey -> COSEAlgorithmIdentifier
keyAlgorithm (ECDSAPublicKey (ECDSAKey alg _)) = ECDSAIdentifier alg
keyAlgorithm (EdDSAPublicKey (Ed25519 _)) = EdDSA

data KeyType = OKP | ECC

instance Serialise KeyType where
  decode = decodeKeyType
  encode = encodeKeyType

decodeKeyType :: Decoder s KeyType
decodeKeyType = do
  kty <- CBOR.decodeIntCanonical
  case kty of
    1 -> pure OKP
    2 -> pure ECC
    x -> fail $ "unexpected kty: " ++ show x

encodeKeyType :: KeyType -> Encoding
encodeKeyType kty = CBOR.encodeInt $ case kty of
  OKP -> 1
  ECC -> 2

instance Serialise PublicKey where
  decode = decodePublicKey
  encode = encodePublicKey

-- | The credential public key encoded in COSE_Key format, as defined in Section 7
-- of [RFC8152], using the CTAP2 canonical CBOR encoding form. The
-- COSE_Key-encoded credential public key MUST contain the "alg" parameter and
-- MUST NOT contain any other OPTIONAL parameters. The "alg" parameter MUST
-- contain a COSEAlgorithmIdentifier value. The encoded credential public key
-- MUST also contain any additional REQUIRED parameters stipulated by the
-- relevant key type specification, i.e., REQUIRED for the key type "kty" and
-- algorithm "alg" (see Section 8 of [RFC8152]).
--
-- Furthermore: CBOR values are CTAP2 canonical encoded.
-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#ctap2-canonical-cbor-encoding-form
decodePublicKey :: Decoder s PublicKey
decodePublicKey = do
  _n <- CBOR.decodeMapLenCanonical
  decodeMapKey Kty
  kty <- decode
  case kty of
    OKP -> EdDSAPublicKey <$> decodeEdDSAKey
    ECC -> ECDSAPublicKey <$> decodeECDSAPublicKey

decodeEdDSAKey :: Decoder s EdDSAKey
decodeEdDSAKey = do
  decodeMapKey Alg
  alg <- decodeCOSEAlgorithmIdentifier
  when (alg /= EdDSA) $ fail "Unsupported `alg`"
  decodeMapKey Crv
  crv <- CBOR.decodeIntCanonical
  decodeMapKey X
  x <- CBOR.decodeBytesCanonical
  case crv of
    6 ->
      case Ed25519.publicKey x of
        CryptoFailed e -> fail (show e)
        CryptoPassed a -> pure $ Ed25519 a
    _ -> fail "Unsupported `crv`"

encodeCurveIdentifier :: CurveIdentifier -> Encoding
encodeCurveIdentifier crv = CBOR.encodeInt $ case crv of
  P256 -> 1
  P384 -> 2
  P521 -> 3

decodeCurveIdentifier :: Decoder s CurveIdentifier
decodeCurveIdentifier = do
  crv <- CBOR.decodeIntCanonical
  case crv of
    1 -> pure P256
    2 -> pure P384
    3 -> pure P521
    _ -> fail "Unsupported `crv`"

instance Serialise CurveIdentifier where
  encode = encodeCurveIdentifier
  decode = decodeCurveIdentifier

decodeECDSAPublicKey :: Decoder s ECDSAKey
decodeECDSAPublicKey = do
  decodeMapKey Alg
  alg <- decodeCOSEAlgorithmIdentifier
  alg' <- case alg of
    ECDSAIdentifier x -> pure x
    _ -> fail "Unsupported `alg`"
  decodeMapKey Crv
  curve <- decode
  when (curve /= curveForAlg alg') $ fail "Curve must match alg. See <section>"
  decodeMapKey X
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
  unless (ECC.isPointValid (toCurve curve) point) $ fail "point not on curve"
  pure $ ECDSAKey alg' (ECC.Point x y)

data MapKey = Kty | Alg | Crv | X | Y deriving (Show, Eq)

mapKeyToInt :: MapKey -> Int
mapKeyToInt key = case key of
  Kty -> 1
  Alg -> 3
  Crv -> -1
  X -> -2
  Y -> -3

encodeMapKey :: MapKey -> Encoding
encodeMapKey = CBOR.encodeInt . mapKeyToInt

decodeMapKey :: MapKey -> Decoder s ()
decodeMapKey key = do
  key' <- CBOR.decodeIntCanonical
  when (mapKeyToInt key /= key') $ fail $ "Expected " ++ show key

encodePublicKey :: PublicKey -> Encoding
encodePublicKey (ECDSAPublicKey (ECDSAKey alg point)) =
  CBOR.encodeMapLen 5
    <> encodeMapKey Kty
    <> encode ECC
    <> encodeMapKey Alg
    <> encode (ECDSAIdentifier alg)
    <> encodeMapKey Crv
    <> encode (curveForAlg alg)
    <> ( case point of
           ECC.Point x y ->
             encodeMapKey X
               <> CBOR.encodeBytes (i2osp x)
               <> encodeMapKey Y
               <> CBOR.encodeBytes (i2osp y)
           _ -> error "never happens"
       )
encodePublicKey (EdDSAPublicKey key) =
  CBOR.encodeMapLen 4
    <> encodeMapKey Kty
    <> encodeKeyType OKP
    <> encodeMapKey Alg
    <> encodeCOSEAlgorithmIdentifier EdDSA
    <> case key of
      Ed25519 key ->
        encodeMapKey Crv
          <> CBOR.encodeInt 6
          <> encodeMapKey X
          <> CBOR.encodeBytes (ByteArray.convert key)

encodeCOSEAlgorithmIdentifier :: COSEAlgorithmIdentifier -> Encoding
encodeCOSEAlgorithmIdentifier x = CBOR.encodeInt $ case x of
  ECDSAIdentifier ES256 -> (-7)
  ECDSAIdentifier ES384 -> (-35)
  ECDSAIdentifier ES512 -> (-36)
  EdDSA -> (-8)

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
verify key msg sig =
  case key of
    ECDSAPublicKey (ECDSAKey alg point) ->
      let key = ECDSA.PublicKey (toCurve (curveForAlg alg)) point
       in case decodeECDSASignature sig of
            Nothing -> False
            Just sig ->
              case alg of
                ES256 -> ECDSA.verify Hash.SHA256 key sig msg
                ES384 -> ECDSA.verify Hash.SHA384 key sig msg
                ES512 -> ECDSA.verify Hash.SHA512 key sig msg
    EdDSAPublicKey (Ed25519 key) ->
      case Ed25519.signature sig of
        CryptoPassed sig -> Ed25519.verify key msg sig
        CryptoFailed _ -> False

curveForAlg :: ECDSAIdentifier -> CurveIdentifier
curveForAlg ES256 = P256
curveForAlg ES384 = P384
curveForAlg ES512 = P521

algForCurve :: CurveIdentifier -> ECDSAIdentifier
algForCurve P256 = ES256
algForCurve P384 = ES384
algForCurve P521 = ES512

toPublicKey :: PubKey -> Maybe PublicKey
toPublicKey (PubKeyEd25519 key) = Just . EdDSAPublicKey $ Ed25519 key
toPublicKey (PubKeyEC key) = do
  curveName <- ecPubKeyCurveName key
  let ident = algForCurve $ fromCurveName curveName
      curve = getCurveByName curveName
  point <- unserializePoint curve (pubkeyEC_pub key)
  pure . ECDSAPublicKey $ ECDSAKey ident point
toPublicKey _ = Nothing
