{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module Spec.Key
  ( PrivateKey (..),
    KeyPair (..),
    newKeyPair,
    sign,
    toX509,
  )
where

import Crypto.Error (CryptoFailable (CryptoFailed, CryptoPassed))
import Crypto.Number.Serialize (i2osp, i2ospOf_)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import Crypto.Random (MonadRandom)
import qualified Crypto.WebAuthn.Cose.Internal.Verify as Cose
import qualified Crypto.WebAuthn.Cose.PublicKey as Cose
import qualified Crypto.WebAuthn.Cose.PublicKeyWithSignAlg as Cose
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Prim as ASN1
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import Data.Either (fromRight)
import qualified Data.X509 as X509
import Test.QuickCheck.Instances.ByteString ()

data PrivateKey
  = PrivateKeyEdDSA
      { eddsaCurve :: Cose.CoseCurveEdDSA,
        eddsaBytes :: BS.ByteString
      }
  | PrivateKeyECDSA
      { ecdsaCurve :: Cose.CoseCurveECDSA,
        ecdsaD :: Integer
      }
  | PrivateKeyRSA
      { rsaN :: Integer,
        rsaE :: Integer,
        rsaD :: Integer
      }
  deriving (Eq, Show)

data KeyPair = KeyPair
  { cosePubKey :: Cose.CosePublicKey,
    privKey :: PrivateKey
  }
  deriving (Eq, Show)

newKeyPair :: (MonadRandom m) => Cose.CoseSignAlg -> m KeyPair
newKeyPair Cose.CoseSignAlgEdDSA = do
  privKey' <- Ed25519.generateSecretKey
  let privKey =
        PrivateKeyEdDSA
          { eddsaCurve = Cose.CoseCurveEd25519,
            eddsaBytes = convert privKey'
          }
      pubKey' = Ed25519.toPublic privKey'
      unchecked =
        Cose.PublicKeyEdDSA
          { eddsaCurve = Cose.CoseCurveEd25519,
            eddsaX = Cose.EdDSAKeyBytes $ convert pubKey'
          }
      pubKey = fromRight (error "unreachable") $ Cose.checkPublicKey unchecked
      cosePubKey = fromRight (error "unreachable") $ Cose.makePublicKeyWithSignAlg pubKey Cose.CoseSignAlgEdDSA
  pure KeyPair {..}
newKeyPair (Cose.CoseSignAlgECDSA hash) = do
  let coseCurve = case hash of
        Cose.CoseHashAlgECDSASHA256 -> Cose.CoseCurveP256
        Cose.CoseHashAlgECDSASHA384 -> Cose.CoseCurveP384
        Cose.CoseHashAlgECDSASHA512 -> Cose.CoseCurveP521
      curveName = Cose.toCryptCurveECDSA coseCurve
      curve = ECC.getCurveByName curveName
  (ECDSA.PublicKey {public_q = point}, ECDSA.PrivateKey {private_d = d}) <- ECC.generate curve
  let (x, y) = case point of
        ECC.Point x y -> (x, y)
        ECC.PointO -> error "newKeyPair: infinity point not supported"

      unchecked =
        Cose.PublicKeyECDSA
          { ecdsaCurve = coseCurve,
            ecdsaX = x,
            ecdsaY = y
          }
      privKey =
        PrivateKeyECDSA
          { ecdsaCurve = coseCurve,
            ecdsaD = d
          }
      pubKey = fromRight (error "unreachable") $ Cose.checkPublicKey unchecked
      cosePubKey = fromRight (error "unreachable") $ Cose.makePublicKeyWithSignAlg pubKey (Cose.CoseSignAlgECDSA hash)
  pure KeyPair {..}
newKeyPair (Cose.CoseSignAlgRSA hash) = do
  -- https://www.rfc-editor.org/rfc/rfc8812.html#section-2
  -- > A key of size 2048 bits or larger MUST be used with these algorithms.
  let publicSizeBytes = 2048 `div` 8
  (RSA.PublicKey {..}, RSA.PrivateKey {..}) <- RSA.generate publicSizeBytes 65537
  let unchecked =
        Cose.PublicKeyRSA
          { -- rsaHash = hash,
            rsaN = public_n,
            rsaE = public_e
          }
      privKey =
        PrivateKeyRSA
          { rsaN = public_n,
            rsaE = public_e,
            rsaD = private_d
          }
      pubKey = fromRight (error "unreachable") $ Cose.checkPublicKey unchecked
      cosePubKey = fromRight (error "unreachable") $ Cose.makePublicKeyWithSignAlg pubKey (Cose.CoseSignAlgRSA hash)
  pure KeyPair {..}

sign :: (MonadRandom m) => Cose.CoseSignAlg -> PrivateKey -> BS.ByteString -> m BS.ByteString
sign Cose.CoseSignAlgEdDSA PrivateKeyEdDSA {eddsaCurve = Cose.CoseCurveEd25519, ..} msg = do
  let privKey = case Ed25519.secretKey eddsaBytes of
        CryptoFailed err -> error $ show err
        CryptoPassed res -> res
      pubKey = Ed25519.toPublic privKey
  pure $ convert $ Ed25519.sign privKey pubKey msg
sign (Cose.CoseSignAlgECDSA (Cose.toCryptHashECDSA -> Cose.SomeHashAlgorithm hash)) PrivateKeyECDSA {..} msg = do
  let privKey =
        ECDSA.PrivateKey
          { private_curve = ECC.getCurveByName $ Cose.toCryptCurveECDSA ecdsaCurve,
            private_d = ecdsaD
          }
  ECDSA.Signature {..} <- ECDSA.sign privKey hash msg
  pure $ ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence, ASN1.IntVal sign_r, ASN1.IntVal sign_s, ASN1.End ASN1.Sequence]
sign (Cose.CoseSignAlgRSA (Cose.toCryptHashRSA -> Cose.SomeHashAlgorithmASN1 hash)) PrivateKeyRSA {..} msg = do
  let privKey =
        RSA.PrivateKey
          { private_pub =
              RSA.PublicKey
                { public_size = BS.length (i2osp rsaN),
                  public_n = rsaN,
                  public_e = rsaE
                },
            private_d = rsaD,
            private_p = 0,
            private_q = 0,
            private_dP = 0,
            private_dQ = 0,
            private_qinv = 0
          }
  sig <- RSA.signSafer (Just hash) privKey msg
  case sig of
    Left err -> error $ show err
    Right res -> pure res
sign signAlg privKey _ = error $ "sign: Combination of signature algorithm " <> show signAlg <> " and private key " <> show privKey <> " is not valid or supported"

toX509 :: Cose.UncheckedPublicKey -> X509.PubKey
toX509 Cose.PublicKeyEdDSA {eddsaCurve = Cose.CoseCurveEd25519, ..} =
  let key = case Ed25519.publicKey $ Cose.unEdDSAKeyBytes eddsaX of
        CryptoFailed err -> error $ "Failed to create a crypton Ed25519 public key of a bytestring with size " <> show (BS.length $ Cose.unEdDSAKeyBytes eddsaX) <> ": " <> show err
        CryptoPassed res -> res
   in X509.PubKeyEd25519 key
toX509 Cose.PublicKeyECDSA {..} =
  let curveName = Cose.toCryptCurveECDSA ecdsaCurve
      size = Cose.coordinateSizeECDSA ecdsaCurve
      serialisedPoint = X509.SerializedPoint $ BS.singleton 0x04 <> i2ospOf_ size ecdsaX <> i2ospOf_ size ecdsaY
      key = X509.PubKeyEC_Named curveName serialisedPoint
   in X509.PubKeyEC key
toX509 Cose.PublicKeyRSA {..} =
  let key =
        RSA.PublicKey
          { public_size = BS.length (i2osp rsaN),
            public_n = rsaN,
            public_e = rsaE
          }
   in X509.PubKeyRSA key
