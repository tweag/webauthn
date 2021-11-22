{-# LANGUAGE RecordWildCards #-}

module Emulation.Client.PrivateKey
  ( PrivateKey (..),
    Signature (..),
    sign,
    toECDSAKey,
    toByteString,
    toCOSEAlgorithmIdentifier,
  )
where

import Crypto.Fido2.PublicKey
  ( COSEAlgorithmIdentifier
      ( COSEAlgorithmIdentifierES256,
        COSEAlgorithmIdentifierES384,
        COSEAlgorithmIdentifierES512,
        COSEAlgorithmIdentifierEdDSA
      ),
  )
import qualified Crypto.Fido2.PublicKey as PublicKey
import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import Crypto.Random (MonadRandom)
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Prim as ASN1
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)

data PrivateKey
  = ES256PrivateKey ECDSA.PrivateKey
  | ES384PrivateKey ECDSA.PrivateKey
  | ES512PrivateKey ECDSA.PrivateKey
  | Ed25519PrivateKey Ed25519.SecretKey
  deriving (Eq, Show)

data Signature
  = ESSignature ECDSA.Signature
  | Ed25519Signature Ed25519.Signature

toECDSAKey :: MonadFail f => PublicKey.COSEAlgorithmIdentifier -> ECDSA.PrivateKey -> f PrivateKey
toECDSAKey PublicKey.COSEAlgorithmIdentifierES256 = pure . ES256PrivateKey
toECDSAKey PublicKey.COSEAlgorithmIdentifierES384 = pure . ES384PrivateKey
toECDSAKey PublicKey.COSEAlgorithmIdentifierES512 = pure . ES512PrivateKey
toECDSAKey _ = const $ fail "Not a ECDSA key identifier"

sign :: MonadRandom m => PrivateKey -> ByteString -> m Signature
sign (ES256PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA256 msg
sign (ES384PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA384 msg
sign (ES512PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA512 msg
sign (Ed25519PrivateKey privateKey) msg = pure . Ed25519Signature $ Ed25519.sign privateKey (Ed25519.toPublic privateKey) msg

toByteString :: Signature -> ByteString
toByteString (ESSignature ECDSA.Signature {..}) = ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence, ASN1.IntVal sign_r, ASN1.IntVal sign_s, ASN1.End ASN1.Sequence]
toByteString (Ed25519Signature sig) = BA.convert sig

toCOSEAlgorithmIdentifier :: PrivateKey -> COSEAlgorithmIdentifier
toCOSEAlgorithmIdentifier (ES256PrivateKey _) = COSEAlgorithmIdentifierES256
toCOSEAlgorithmIdentifier (ES384PrivateKey _) = COSEAlgorithmIdentifierES384
toCOSEAlgorithmIdentifier (ES512PrivateKey _) = COSEAlgorithmIdentifierES512
toCOSEAlgorithmIdentifier (Ed25519PrivateKey _) = COSEAlgorithmIdentifierEdDSA
