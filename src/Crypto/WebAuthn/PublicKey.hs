{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

-- | public keys and signature algorithms are represented with three
-- different types:
--
-- * 'Cose.CoseSignAlg', which is the signature algorithm used, equivalent to a
--   COSE Algorithm from the COSE registry
-- * 'Cose.CosePublicKey', which is a combination of a 'Cose.CoseSignAlg' along with
--   a public key that can be used with it. This is what the COSE_Key
--   CBOR structure decodes to
-- * 'PublicKey', only the public key part of 'Cose.CosePublicKey'
--
-- The following main operations are supported for these types:
--
-- * 'Cose.CosePublicKey' can be totally decomposed into a 'Cose.CoseSignAlg'
--   with 'Cose.keySignAlg' and a 'PublicKey' with 'fromCose'
-- * A 'PublicKey' can be created from an X.509 public key with 'fromX509'
-- * A 'Cose.CoseSignAlg' and a 'PublicKey' can be used to verify a signature
--   with 'verify'
module Crypto.WebAuthn.PublicKey
  ( -- * Public Key
    PublicKey (..),
    fromCose,
    fromX509,

    -- * Signature verification
    verify,

    -- * Hash Conversions to cryptonite types
    SomeHashAlgorithm (..),
    toCryptHashECDSA,
    SomeHashAlgorithmASN1 (..),
    toCryptHashRSA,

    -- * Conversions from/to cryptonite elliptic curves
    toCryptCurveECDSA,
    fromCryptCurveECDSA,
  )
where

import Crypto.Error (CryptoFailable (CryptoFailed, CryptoPassed))
import qualified Crypto.Hash as Hash
import Crypto.Number.Serialize (i2osp, i2ospOf, os2ip)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.WebAuthn.Cose.Key as Cose
import qualified Crypto.WebAuthn.Cose.Registry as Cose
import Crypto.WebAuthn.Internal.ToJSONOrphans ()
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Types as ASN1
import Data.Aeson (ToJSON)
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.EC as X509
import GHC.Generics (Generic)

-- | Same as 'Cose.CosePublicKey', but without signature algorithm parameters, i.e.
-- hash algorithms.
data PublicKey
  = -- | See 'Cose.CosePublicKeyEdDSA'
    PublicKeyEdDSA
      { -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.2)
        -- The elliptic curve to use
        eddsaCurve :: Cose.CoseCurveEdDSA,
        -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.2)
        -- This contains the public key bytes
        eddsaX :: BS.ByteString
      }
  | -- | See 'Cose.CosePublicKeyECDSA'
    PublicKeyECDSA
      { -- | [(spec)](https://datatracker.ietf.org/doc/html/draft-ietf-cose-rfc8152bis-algs-12#section-7.1.1)
        -- The elliptic curve to use
        ecdsaCurve :: Cose.CoseCurveECDSA,
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
  | -- | See 'Cose.CosePublicKeyRSA'
    PublicKeyRSA
      { -- | [(spec)](https://www.rfc-editor.org/rfc/rfc8230.html#section-4)
        -- The RSA modulus n is a product of u distinct odd primes
        -- r_i, i = 1, 2, ..., u, where u >= 2
        rsaN :: Integer,
        -- | [(spec)](https://www.rfc-editor.org/rfc/rfc8230.html#section-4)
        -- The RSA public exponent e is an integer between 3 and n - 1 satisfying
        -- GCD(e,\\lambda(n)) = 1, where \\lambda(n) = LCM(r_1 - 1, ..., r_u - 1)
        rsaE :: Integer
      }
  deriving (Eq, Show, Generic, ToJSON)

-- | Turns a 'Cose.CosePublicKey' into a 'PublicKey' by removing the hash functions
fromCose :: Cose.CosePublicKey -> PublicKey
fromCose Cose.CosePublicKeyEdDSA {..} = PublicKeyEdDSA {..}
fromCose Cose.CosePublicKeyECDSA {..} = PublicKeyECDSA {..}
fromCose Cose.CosePublicKeyRSA {..} = PublicKeyRSA {..}

-- | Turns a X.509 certificates 'X509.PubKey' into a 'PublicKey'
fromX509 :: X509.PubKey -> Maybe PublicKey
fromX509 (X509.PubKeyEd25519 key) =
  Just $
    PublicKeyEdDSA
      { eddsaCurve = Cose.CoseCurveEd25519,
        eddsaX = convert key
      }
fromX509 (X509.PubKeyEC X509.PubKeyEC_Named {..}) = do
  let curve = ECC.getCurveByName pubkeyEC_name
  ecdsaCurve <- fromCryptCurveECDSA pubkeyEC_name
  point <- X509.unserializePoint curve pubkeyEC_pub
  -- Round up to a full byte
  let byteSize = (ECC.curveSizeBits curve + 7) `div` 8
  case point of
    ECC.Point x y -> do
      ecdsaX <- i2ospOf byteSize x
      ecdsaY <- i2ospOf byteSize y
      Just $ PublicKeyECDSA {..}
    ECC.PointO -> Nothing
fromX509 (X509.PubKeyRSA RSA.PublicKey {..}) =
  Just
    PublicKeyRSA
      { rsaN = public_n,
        rsaE = public_e
      }
fromX509 _ = Nothing

-- | Verifies an asymmetric signature for a message using a 'Cose.CoseSignAlg'
-- and a 'PublicKey'. Returns an error if the signature algorithm doesn't
-- match. Also returns an error if the signature wasn't valid or for other
-- errors.
verify :: Cose.CoseSignAlg -> PublicKey -> BS.ByteString -> BS.ByteString -> Either String ()
verify Cose.CoseSignAlgEdDSA PublicKeyEdDSA {eddsaCurve = Cose.CoseCurveEd25519, ..} msg sig = do
  key <- case Ed25519.publicKey eddsaX of
    CryptoFailed err -> Left $ "Failed to create Ed25519 public key: " <> show err
    CryptoPassed res -> pure res
  sig <- case Ed25519.signature sig of
    CryptoFailed err -> Left $ "Failed to create Ed25519 signature: " <> show err
    CryptoPassed res -> pure res
  if Ed25519.verify key msg sig
    then Right ()
    else Left "EdDSA Signature invalid"
verify (Cose.CoseSignAlgECDSA (toCryptHashECDSA -> SomeHashAlgorithm hash)) PublicKeyECDSA {..} msg sig = do
  let key =
        ECDSA.PublicKey
          { public_curve = ECC.getCurveByName $ toCryptCurveECDSA ecdsaCurve,
            public_q = ECC.Point (os2ip ecdsaX) (os2ip ecdsaY)
          }

  -- https://www.w3.org/TR/webauthn-2/#sctn-signature-attestation-types
  -- > For COSEAlgorithmIdentifier -7 (ES256), and other ECDSA-based algorithms,
  -- the `sig` value MUST be encoded as an ASN.1 DER Ecdsa-Sig-Value, as defined
  -- in [RFC3279](https://www.w3.org/TR/webauthn-2/#biblio-rfc3279) section 2.2.3.
  sig <- case ASN1.decodeASN1' ASN1.DER sig of
    Left err -> Left $ "Failed to decode ECDSA DER value: " <> show err
    -- Ecdsa-Sig-Value in https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3
    Right [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence] ->
      pure $ ECDSA.Signature r s
    Right asns -> Left $ "Unexpected ECDSA ASN.1 structure: " <> show asns

  if ECDSA.verify hash key sig msg
    then Right ()
    else Left "ECDSA Signature invalid"
verify (Cose.CoseSignAlgRSA (toCryptHashRSA -> SomeHashAlgorithmASN1 hash)) PublicKeyRSA {..} msg sig = do
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
  if RSA.verify (Just hash) key msg sig
    then Right ()
    else Left "RSA Signature invalid"
verify sigAlg pubKey _ _ =
  Left $ "Unsupported combination of signature algorithm " <> show sigAlg <> " and public key " <> show pubKey

-- Some cryptonite 'Hash.HashAlgorithm' type, used as a return value of 'toCryptHashECDSA'
data SomeHashAlgorithm = forall a. Hash.HashAlgorithm a => SomeHashAlgorithm a

-- Returns the cryptonite 'SomeHashAlgorithm' corresponding to this hash algorithm
toCryptHashECDSA :: Cose.CoseHashAlgECDSA -> SomeHashAlgorithm
toCryptHashECDSA Cose.CoseHashAlgECDSASHA256 = SomeHashAlgorithm Hash.SHA256
toCryptHashECDSA Cose.CoseHashAlgECDSASHA384 = SomeHashAlgorithm Hash.SHA384
toCryptHashECDSA Cose.CoseHashAlgECDSASHA512 = SomeHashAlgorithm Hash.SHA512

-- Some cryptonite 'RSA.HashAlgorithmASN1' type, used as a return value of 'toCryptHashRSA'
data SomeHashAlgorithmASN1 = forall a. RSA.HashAlgorithmASN1 a => SomeHashAlgorithmASN1 a

-- Returns the cryptonite 'SomeHashAlgorithmASN1' corresponding to this hash algorithm
toCryptHashRSA :: Cose.CoseHashAlgRSA -> SomeHashAlgorithmASN1
toCryptHashRSA Cose.CoseHashAlgRSASHA1 = SomeHashAlgorithmASN1 Hash.SHA1
toCryptHashRSA Cose.CoseHashAlgRSASHA256 = SomeHashAlgorithmASN1 Hash.SHA256
toCryptHashRSA Cose.CoseHashAlgRSASHA384 = SomeHashAlgorithmASN1 Hash.SHA384
toCryptHashRSA Cose.CoseHashAlgRSASHA512 = SomeHashAlgorithmASN1 Hash.SHA512

-- | Converts a 'Cose.CoseCurveECDSA' to an 'ECC.CurveName'. The inverse
-- function is 'fromCryptCurveECDSA'
toCryptCurveECDSA :: Cose.CoseCurveECDSA -> ECC.CurveName
toCryptCurveECDSA Cose.CoseCurveP256 = ECC.SEC_p256r1
toCryptCurveECDSA Cose.CoseCurveP384 = ECC.SEC_p384r1
toCryptCurveECDSA Cose.CoseCurveP521 = ECC.SEC_p521r1

-- | Tries to converts a 'ECC.CurveName' to an 'Cose.CoseCurveECDSA'. The inverse
-- function is 'toCryptCurveECDSA'
fromCryptCurveECDSA :: ECC.CurveName -> Maybe Cose.CoseCurveECDSA
fromCryptCurveECDSA ECC.SEC_p256r1 = Just Cose.CoseCurveP256
fromCryptCurveECDSA ECC.SEC_p384r1 = Just Cose.CoseCurveP384
fromCryptCurveECDSA ECC.SEC_p521r1 = Just Cose.CoseCurveP521
fromCryptCurveECDSA _ = Nothing
