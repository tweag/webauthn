{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

-- | Stability: internal
-- public keys and signature algorithms are represented with three
-- different types:
--
-- * 'Cose.CoseSignAlg', which is the signature algorithm used, equivalent to a
--   COSE Algorithm from the COSE registry
-- * 'Cose.CosePublicKey', which is a combination of a 'Cose.CoseSignAlg' along with
--   a public key that can be used with it. This is what the COSE_Key
--   CBOR structure decodes to
-- * 'Cose.PublicKey', only the public key part of 'Cose.CosePublicKey'
--
-- The following main operations are supported for these types:
--
-- * 'Cose.CosePublicKey' can be totally decomposed into a 'Cose.CoseSignAlg'
--   with 'Cose.signAlg' and a 'Cose.PublicKey' with 'Cose.publicKey'
-- * A 'Cose.PublicKey' can be created from an X.509 public key with 'fromX509'
-- * A 'Cose.CoseSignAlg' and a 'Cose.PublicKey' can be used to verify a signature
--   with 'verify'
module Crypto.WebAuthn.Cose.Internal.Verify
  ( -- * Public Key
    fromX509,

    -- * Signature verification
    Cose.Message (..),
    Cose.Signature (..),
    verify,

    -- * Hash Conversions to crypton types
    SomeHashAlgorithm (..),
    toCryptHashECDSA,
    SomeHashAlgorithmASN1 (..),
    toCryptHashRSA,
  )
where

import Crypto.Error (CryptoFailable (CryptoFailed, CryptoPassed))
import qualified Crypto.Hash as Hash
import Crypto.Number.Serialize (i2osp)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.WebAuthn.Cose.PublicKey as Cose
import qualified Crypto.WebAuthn.Cose.PublicKeyWithSignAlg as Cose
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Types as ASN1
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.EC as X509

-- | Turns a X.509 certificates 'X509.PubKey' into a 'Cose.PublicKey'
fromX509 :: X509.PubKey -> Either Text Cose.PublicKey
fromX509 (X509.PubKeyEd25519 key) =
  Cose.checkPublicKey $
    Cose.PublicKeyEdDSA
      Cose.EdDSAPublicKey
        { eddsaCurve = Cose.CoseCurveEd25519,
          eddsaX = Cose.EdDSAKeyBytes $ convert key
        }
fromX509 (X509.PubKeyEC X509.PubKeyEC_Named {..}) = do
  let curve = ECC.getCurveByName pubkeyEC_name
  ecdsaCurve <- Cose.fromCryptCurveECDSA pubkeyEC_name
  point <- case X509.unserializePoint curve pubkeyEC_pub of
    Nothing -> Left "Failed to unserialize ECDSA point in X509 certificate"
    Just res -> pure res
  unchecked <- case point of
    ECC.Point ecdsaX ecdsaY -> Right $ Cose.PublicKeyECDSA Cose.ECDSAPublicKey {..}
    ECC.PointO -> Left "The infinity point is not supported"
  Cose.checkPublicKey unchecked
fromX509 (X509.PubKeyRSA RSA.PublicKey {..}) =
  Cose.checkPublicKey $
    Cose.PublicKeyRSA
      Cose.RSAPublicKey
        { rsaN = public_n,
          rsaE = public_e
        }
fromX509 key = Left $ "X509 public key algorithm is not supported: " <> Text.pack (show (X509.pubkeyToAlg key))

-- | Verifies an asymmetric signature for a message using a
-- 'Cose.PublicKeyWithSignAlg' Returns an error if the signature algorithm
-- doesn't match. Also returns an error if the signature wasn't valid or for
-- other errors.
-- FIXME: https://w3c.github.io/webauthn/#sctn-signature-attestation-types kind of documents this, but not for all formats. This is notably not really related to COSE, but rather webauthn's own definitions. The spec should be made less ambiguous, file upstream issues and refactor this code
verify :: Cose.PublicKeyWithSignAlg -> Cose.Message -> Cose.Signature -> Either Text ()
verify
  Cose.PublicKeyWithSignAlg
    { publicKey = Cose.PublicKey (Cose.PublicKeyEdDSA Cose.EdDSAPublicKey {eddsaCurve = Cose.CoseCurveEd25519, ..}),
      signAlg = Cose.CoseSignAlgEdDSA
    }
  msg
  sig = do
    key <- case Ed25519.publicKey $ Cose.unEdDSAKeyBytes eddsaX of
      CryptoFailed err -> Left $ "Failed to create Ed25519 public key: " <> Text.pack (show err)
      CryptoPassed res -> pure res
    sig <- case Ed25519.signature (Cose.unSignature sig) of
      CryptoFailed err -> Left $ "Failed to create Ed25519 signature: " <> Text.pack (show err)
      CryptoPassed res -> pure res
    if Ed25519.verify key (Cose.unMessage msg) sig
      then Right ()
      else Left "EdDSA Signature invalid"
verify
  Cose.PublicKeyWithSignAlg
    { publicKey = Cose.PublicKey (Cose.PublicKeyECDSA Cose.ECDSAPublicKey {..}),
      signAlg = Cose.CoseSignAlgECDSA (toCryptHashECDSA -> SomeHashAlgorithm hash)
    }
  msg
  sig = do
    let curveName = Cose.toCryptCurveECDSA ecdsaCurve
        public_curve = ECC.getCurveByName curveName
        public_q = ECC.Point ecdsaX ecdsaY

    -- This check is already done in checkPublicKey
    -- unless (ECC.isPointValid public_curve public_q) $
    --  Left $ "ECDSA point is not valid for curve " <> Text.pack (show curveName) <> ": " <> Text.pack (show public_q)
    let key = ECDSA.PublicKey {..}

    -- https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
    -- > For COSEAlgorithmIdentifier -7 (ES256), and other ECDSA-based algorithms,
    -- the `sig` value MUST be encoded as an ASN.1 DER Ecdsa-Sig-Value, as defined
    -- in [RFC3279](https://www.w3.org/TR/webauthn-2/#biblio-rfc3279) section 2.2.3.
    sig <- case ASN1.decodeASN1' ASN1.DER (Cose.unSignature sig) of
      Left err -> Left $ "Failed to decode ECDSA DER value: " <> Text.pack (show err)
      -- Ecdsa-Sig-Value in https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3
      Right [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence] ->
        pure $ ECDSA.Signature r s
      Right asns -> Left $ "Unexpected ECDSA ASN.1 structure: " <> Text.pack (show asns)

    if ECDSA.verify hash key sig (Cose.unMessage msg)
      then Right ()
      else Left "ECDSA Signature invalid"
verify
  Cose.PublicKeyWithSignAlg
    { publicKey = Cose.PublicKey (Cose.PublicKeyRSA Cose.RSAPublicKey {..}),
      signAlg = Cose.CoseSignAlgRSA (toCryptHashRSA -> SomeHashAlgorithmASN1 hash)
    }
  msg
  sig = do
    let key =
          RSA.PublicKey
            { -- https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2
              -- > k is the length in octets of the RSA modulus n
              --
              -- > Length checking: If the length of the signature S is not k
              -- > octets, output "invalid signature" and stop.
              -- This is done by the RSA.verify call
              public_size = BS.length (i2osp rsaN),
              public_n = rsaN,
              public_e = rsaE
            }
    if RSA.verify (Just hash) key (Cose.unMessage msg) (Cose.unSignature sig)
      then Right ()
      else Left "RSA Signature invalid"
verify key _ _ = error $ "PublicKeyWithSignAlg invariant violated for public key " <> show key <> ". This should not occur unless the PublicKeyWithSignAlg module has a bug"

-- | Some crypton 'Hash.HashAlgorithm' type, used as a return value of 'toCryptHashECDSA'
data SomeHashAlgorithm = forall a. (Hash.HashAlgorithm a) => SomeHashAlgorithm a

-- | Returns the crypton 'SomeHashAlgorithm' corresponding to this hash algorithm
toCryptHashECDSA :: Cose.CoseHashAlgECDSA -> SomeHashAlgorithm
toCryptHashECDSA Cose.CoseHashAlgECDSASHA256 = SomeHashAlgorithm Hash.SHA256
toCryptHashECDSA Cose.CoseHashAlgECDSASHA384 = SomeHashAlgorithm Hash.SHA384
toCryptHashECDSA Cose.CoseHashAlgECDSASHA512 = SomeHashAlgorithm Hash.SHA512

-- | Some crypton 'RSA.HashAlgorithmASN1' type, used as a return value of 'toCryptHashRSA'
data SomeHashAlgorithmASN1 = forall a. (RSA.HashAlgorithmASN1 a) => SomeHashAlgorithmASN1 a

-- | Returns the crypton 'SomeHashAlgorithmASN1' corresponding to this hash algorithm
toCryptHashRSA :: Cose.CoseHashAlgRSA -> SomeHashAlgorithmASN1
toCryptHashRSA Cose.CoseHashAlgRSASHA1 = SomeHashAlgorithmASN1 Hash.SHA1
toCryptHashRSA Cose.CoseHashAlgRSASHA256 = SomeHashAlgorithmASN1 Hash.SHA256
toCryptHashRSA Cose.CoseHashAlgRSASHA384 = SomeHashAlgorithmASN1 Hash.SHA384
toCryptHashRSA Cose.CoseHashAlgRSASHA512 = SomeHashAlgorithmASN1 Hash.SHA512
