module Client.PrivateKey
  ( PrivateKey,
    sign,
  )
where

import Crypto.Fido2.PublicKey (PublicKey (ES256PublicKey, ES384PublicKey, ES512PublicKey, Ed25519PublicKey))
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

sign :: MonadRandom m => PublicKey -> PrivateKey -> ByteString -> m Signature
sign (ES256PublicKey _) (ES512PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA256 msg
sign (ES384PublicKey _) (ES512PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA384 msg
sign (ES512PublicKey _) (ES512PrivateKey key) msg = ESSignature <$> ECDSA.sign key Hash.SHA512 msg
sign (Ed25519PublicKey publicKey) (Ed25519PrivateKey privateKey) msg = pure . Ed25519Signature $ Ed25519.sign privateKey publicKey msg
sign _ _ _ = error "Unknown or incorrect private/public keypair"
