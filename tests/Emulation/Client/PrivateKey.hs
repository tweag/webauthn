{-# LANGUAGE RecordWildCards #-}

module Emulation.Client.PrivateKey
  ( PrivateKey (..),
    Signature (..),
    sign,
    toECDSAKey,
    toByteString,
    toCOSEAlgorithmIdentifier,
    toRSAKey,
  )
where

import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import Crypto.Random (MonadRandom)
import qualified Crypto.WebAuthn.PublicKey as PublicKey
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Prim as ASN1
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

data PrivateKey
  = ES256PrivateKey ECDSA.PrivateKey
  | ES384PrivateKey ECDSA.PrivateKey
  | ES512PrivateKey ECDSA.PrivateKey
  | Ed25519PrivateKey Ed25519.SecretKey
  | RS1PrivateKey RSA.PrivateKey
  | RS256PrivateKey RSA.PrivateKey
  | RS384PrivateKey RSA.PrivateKey
  | RS512PrivateKey RSA.PrivateKey
  deriving (Eq, Show)

data Signature
  = ESSignature ECDSA.Signature
  | Ed25519Signature Ed25519.Signature
  | RSSignature BS.ByteString

toECDSAKey :: MonadFail f => PublicKey.COSEAlgorithmIdentifier -> ECDSA.PrivateKey -> f PrivateKey
toECDSAKey PublicKey.COSEAlgorithmIdentifierES256 = pure . ES256PrivateKey
toECDSAKey PublicKey.COSEAlgorithmIdentifierES384 = pure . ES384PrivateKey
toECDSAKey PublicKey.COSEAlgorithmIdentifierES512 = pure . ES512PrivateKey
toECDSAKey _ = const $ fail "Not an ECDSA key identifier"

toRSAKey :: MonadFail f => PublicKey.COSEAlgorithmIdentifier -> RSA.PrivateKey -> f PrivateKey
toRSAKey PublicKey.COSEAlgorithmIdentifierRS1 = pure . RS1PrivateKey
toRSAKey PublicKey.COSEAlgorithmIdentifierRS256 = pure . RS256PrivateKey
toRSAKey PublicKey.COSEAlgorithmIdentifierRS384 = pure . RS384PrivateKey
toRSAKey PublicKey.COSEAlgorithmIdentifierRS512 = pure . RS512PrivateKey
toRSAKey _ = const $ fail "Not an RSA key identifier"

sign :: MonadRandom m => PrivateKey -> ByteString -> m Signature
sign (ES256PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA256 msg
sign (ES384PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA384 msg
sign (ES512PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA512 msg
sign (Ed25519PrivateKey privateKey) msg = pure . Ed25519Signature $ Ed25519.sign privateKey (Ed25519.toPublic privateKey) msg
sign (RS1PrivateKey key) msg = RSSignature . either (error . show) id <$> RSA.signSafer (Just Hash.SHA1) key msg
sign (RS256PrivateKey key) msg = RSSignature . either (error . show) id <$> RSA.signSafer (Just Hash.SHA256) key msg
sign (RS384PrivateKey key) msg = RSSignature . either (error . show) id <$> RSA.signSafer (Just Hash.SHA384) key msg
sign (RS512PrivateKey key) msg = RSSignature . either (error . show) id <$> RSA.signSafer (Just Hash.SHA512) key msg

toByteString :: Signature -> ByteString
toByteString (ESSignature ECDSA.Signature {..}) = ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence, ASN1.IntVal sign_r, ASN1.IntVal sign_s, ASN1.End ASN1.Sequence]
toByteString (Ed25519Signature sig) = BA.convert sig
toByteString (RSSignature bs) = bs

toCOSEAlgorithmIdentifier :: PrivateKey -> PublicKey.COSEAlgorithmIdentifier
toCOSEAlgorithmIdentifier (ES256PrivateKey _) = PublicKey.COSEAlgorithmIdentifierES256
toCOSEAlgorithmIdentifier (ES384PrivateKey _) = PublicKey.COSEAlgorithmIdentifierES384
toCOSEAlgorithmIdentifier (ES512PrivateKey _) = PublicKey.COSEAlgorithmIdentifierES512
toCOSEAlgorithmIdentifier (Ed25519PrivateKey _) = PublicKey.COSEAlgorithmIdentifierEdDSA
toCOSEAlgorithmIdentifier (RS1PrivateKey _) = PublicKey.COSEAlgorithmIdentifierRS1
toCOSEAlgorithmIdentifier (RS256PrivateKey _) = PublicKey.COSEAlgorithmIdentifierRS256
toCOSEAlgorithmIdentifier (RS384PrivateKey _) = PublicKey.COSEAlgorithmIdentifierRS384
toCOSEAlgorithmIdentifier (RS512PrivateKey _) = PublicKey.COSEAlgorithmIdentifierRS512
