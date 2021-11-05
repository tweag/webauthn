module Client.PrivateKey
  ( PrivateKey (..),
    sign,
    toECDSAKey,
  )
where

import qualified Crypto.Fido2.PublicKey as PublicKey
import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import Crypto.Random (MonadRandom)
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

sign :: MonadRandom m => PublicKey.PublicKey -> PrivateKey -> ByteString -> m Signature
sign (PublicKey.ES256PublicKey _) (ES512PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA256 msg
sign (PublicKey.ES384PublicKey _) (ES512PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA384 msg
sign (PublicKey.ES512PublicKey _) (ES512PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA512 msg
sign (PublicKey.Ed25519PublicKey publicKey) (Ed25519PrivateKey privateKey) msg = pure . Ed25519Signature $ Ed25519.sign privateKey publicKey msg
sign _ _ _ = error "Unknown or incorrect private/public keypair"
