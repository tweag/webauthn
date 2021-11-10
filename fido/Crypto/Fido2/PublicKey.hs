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
    decodeCOSEAlgorithmIdentifier,
    encodePublicKey,
    toAlg,
    toPublicKey,
    toCOSEAlgorithmIdentifier,
    toECDSAKey,
    fromAlg,
    toCurveName,
  )
where

import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Encoding as CBOR
import Control.Monad (unless, when)
import Crypto.Error (CryptoFailable (CryptoFailed, CryptoPassed))
import Crypto.Hash (HashAlgorithm)
import qualified Crypto.Hash.Algorithms as Hash
import Crypto.Number.Serialize (i2osp, os2ip)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Prim as ASN1
import qualified Data.ByteArray as ByteArray
import Data.ByteString (ByteString)
import qualified Data.X509 as X509
import qualified Data.X509.EC as X509

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
  = ES256PublicKey ECDSA.PublicKey
  | ES384PublicKey ECDSA.PublicKey
  | ES512PublicKey ECDSA.PublicKey
  | Ed25519PublicKey Ed25519.PublicKey
  deriving (Eq, Show)

data KeyType = OKP | ECC

data MapKey = Kty | Alg | Crv | X | Y deriving (Show, Eq)

data CurveIdentifier = P256 | P384 | P521
  deriving (Eq)

decodePublicKey :: CBOR.Decoder s PublicKey
decodePublicKey = do
  _n <- CBOR.decodeMapLenCanonical
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
      toECDSAKey alg (ECDSA.PublicKey curve point)

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

toCurveName :: COSEAlgorithmIdentifier -> ECC.CurveName
toCurveName COSEAlgorithmIdentifierES256 = ECC.SEC_p256r1
toCurveName COSEAlgorithmIdentifierES384 = ECC.SEC_p384r1
toCurveName COSEAlgorithmIdentifierES512 = ECC.SEC_p521r1
toCurveName _ = error "No known curve"
mapKeyToInt :: MapKey -> Int
mapKeyToInt key = case key of
  Kty -> 1
  Alg -> 3
  Crv -> -1
  X -> -2
  Y -> -3

-- All CBOR is encoded using
-- https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#ctap2-canonical-cbor-encoding-form

--
-- a signature decoding uniquely belongs to an algorithm identifier. how do we
-- encode this correspondence?
decodeCOSEAlgorithmIdentifier :: CBOR.Decoder s COSEAlgorithmIdentifier
decodeCOSEAlgorithmIdentifier =
  toAlg =<< CBOR.decodeIntCanonical

encodePublicKey :: PublicKey -> CBOR.Encoding
encodePublicKey pk@(ES256PublicKey ecdsaPk) = encodeECDSA (toCOSEAlgorithmIdentifier pk) ecdsaPk
encodePublicKey pk@(ES384PublicKey ecdsaPk) = encodeECDSA (toCOSEAlgorithmIdentifier pk) ecdsaPk
encodePublicKey pk@(ES512PublicKey ecdsaPk) = encodeECDSA (toCOSEAlgorithmIdentifier pk) ecdsaPk
encodePublicKey pk@(Ed25519PublicKey edPk) =
  CBOR.encodeMapLen 4
    <> encodeMapKey Kty
    <> encodeKeyType OKP
    <> encodeMapKey Alg
    <> encodeCOSEAlgorithm (toCOSEAlgorithmIdentifier pk)
    <> encodeMapKey Crv
    <> CBOR.encodeInt 6
    <> encodeMapKey X
    <> CBOR.encodeBytes (ByteArray.convert edPk)

encodeECDSA :: COSEAlgorithmIdentifier -> ECDSA.PublicKey -> CBOR.Encoding
encodeECDSA ident ECDSA.PublicKey {ECDSA.public_q = ECC.Point x y} =
  CBOR.encodeMapLen 5
    <> encodeMapKey Kty
    <> encodeKeyType ECC
    <> encodeMapKey Alg
    <> encodeCOSEAlgorithm ident
    <> encodeMapKey Crv
    <> encodeCurve ident
    <> encodeMapKey X
    <> CBOR.encodeBytes (i2osp x)
    <> encodeMapKey Y
    <> CBOR.encodeBytes (i2osp y)

encodeKeyType :: KeyType -> CBOR.Encoding
encodeKeyType OKP = CBOR.encodeInt 1
encodeKeyType ECC = CBOR.encodeInt 2

encodeMapKey :: MapKey -> CBOR.Encoding
encodeMapKey = CBOR.encodeInt . mapKeyToInt

encodeCOSEAlgorithm :: COSEAlgorithmIdentifier -> CBOR.Encoding
encodeCOSEAlgorithm COSEAlgorithmIdentifierES256 = CBOR.encodeInt (-7)
encodeCOSEAlgorithm COSEAlgorithmIdentifierES384 = CBOR.encodeInt (-35)
encodeCOSEAlgorithm COSEAlgorithmIdentifierES512 = CBOR.encodeInt (-36)
encodeCOSEAlgorithm COSEAlgorithmIdentifierEdDSA = CBOR.encodeInt (-8)

encodeCurve :: COSEAlgorithmIdentifier -> CBOR.Encoding
encodeCurve COSEAlgorithmIdentifierES256 = CBOR.encodeInt 1
encodeCurve COSEAlgorithmIdentifierES384 = CBOR.encodeInt 2
encodeCurve COSEAlgorithmIdentifierES512 = CBOR.encodeInt 3

toAlg :: (Eq a, Num a, MonadFail f) => a -> f COSEAlgorithmIdentifier
toAlg (-7) = pure COSEAlgorithmIdentifierES256
toAlg (-35) = pure COSEAlgorithmIdentifierES384
toAlg (-36) = pure COSEAlgorithmIdentifierES512
toAlg (-8) = pure COSEAlgorithmIdentifierEdDSA
toAlg _ = fail "Unsupported `alg`"

fromAlg :: Num a => COSEAlgorithmIdentifier -> a
fromAlg COSEAlgorithmIdentifierES256 = -7
fromAlg COSEAlgorithmIdentifierES384 = -35
fromAlg COSEAlgorithmIdentifierES512 = -36
fromAlg COSEAlgorithmIdentifierEdDSA = -8

toCOSEAlgorithmIdentifier :: PublicKey -> COSEAlgorithmIdentifier
toCOSEAlgorithmIdentifier (ES256PublicKey _) = COSEAlgorithmIdentifierES256
toCOSEAlgorithmIdentifier (ES384PublicKey _) = COSEAlgorithmIdentifierES384
toCOSEAlgorithmIdentifier (ES512PublicKey _) = COSEAlgorithmIdentifierES512
toCOSEAlgorithmIdentifier (Ed25519PublicKey _) = COSEAlgorithmIdentifierEdDSA

toPublicKey :: MonadFail f => COSEAlgorithmIdentifier -> X509.PubKey -> f PublicKey
toPublicKey COSEAlgorithmIdentifierEdDSA (X509.PubKeyEd25519 key) = pure $ Ed25519PublicKey key
toPublicKey alg (X509.PubKeyEC key) = do
  curveName <-
    maybe
      (fail "Non-recognized curve")
      pure
      (X509.ecPubKeyCurveName key)
  let curve = ECC.getCurveByName curveName
  point <-
    maybe
      (fail "Deserialization failed or point not on curve")
      pure
      (X509.unserializePoint curve (X509.pubkeyEC_pub key))
  let key = ECDSA.PublicKey curve point
  toECDSAKey alg key
toPublicKey alg pubkey =
  fail $
    "Unsupported combination of COSE alg "
      <> show alg
      <> " and X509 public key "
      <> show pubkey

toECDSAKey :: MonadFail f => COSEAlgorithmIdentifier -> ECDSA.PublicKey -> f PublicKey
toECDSAKey COSEAlgorithmIdentifierES256 = pure . ES256PublicKey
toECDSAKey COSEAlgorithmIdentifierES384 = pure . ES384PublicKey
toECDSAKey COSEAlgorithmIdentifierES512 = pure . ES512PublicKey
toECDSAKey _ = const $ fail "Not a ECDSA key identifier"

verify :: PublicKey -> ByteString -> ByteString -> Bool
verify (ES256PublicKey key) msg sig = verifyESKey Hash.SHA256 key sig msg
verify (ES384PublicKey key) msg sig = verifyESKey Hash.SHA384 key sig msg
verify (ES512PublicKey key) msg sig = verifyESKey Hash.SHA512 key sig msg
verify (Ed25519PublicKey key) msg sig =
  case Ed25519.signature sig of
    CryptoPassed sig -> Ed25519.verify key msg sig
    CryptoFailed _ -> False

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types)
verifyESKey :: HashAlgorithm hash => hash -> ECDSA.PublicKey -> ByteString -> ByteString -> Bool
verifyESKey hash key sig msg =
  case ASN1.decodeASN1' ASN1.BER sig of
    Left _ -> False
    Right [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence] ->
      ECDSA.verify hash key (ECDSA.Signature r s) msg
    Right _ -> False
