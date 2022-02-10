{-# LANGUAGE RecordWildCards #-}

module PublicKeySpec
  ( spec,
  )
where

import Codec.Serialise.Properties (serialiseIdentity)
import qualified Crypto.WebAuthn.Cose.Internal.Verify as Cose
import qualified Crypto.WebAuthn.Cose.PublicKeyWithSignAlg as Cose
import qualified Crypto.WebAuthn.Cose.PublicKey as Cose
import qualified Data.ByteString as BS
import qualified Spec.Key as Key
import Spec.Types ()
import Spec.Util (runSeededMonadRandom)
import Test.Hspec (SpecWith, it)
import Test.QuickCheck (Testable (property))
import Test.QuickCheck.Instances.ByteString ()

spec :: SpecWith ()
spec = do
  it "CosePublicKey roundtrip" $
    property (serialiseIdentity @Cose.CosePublicKey)

  it "PublicKey X509 roundtrip" $
    property prop_x509PublicKeyRoundtrip

  it "Created signatures can be validated" $
    property prop_signverify

prop_x509PublicKeyRoundtrip :: Cose.PublicKey -> Bool
prop_x509PublicKeyRoundtrip (Cose.PublicKey pubKey) =
  case Cose.fromX509 (Key.toX509 pubKey) of
    Right (Cose.PublicKey pubKey')
      | pubKey == pubKey' -> True
      | otherwise -> False
    Left _ -> False

prop_signverify :: Integer -> Key.KeyPair -> BS.ByteString -> Bool
prop_signverify seed Key.KeyPair {..} msg = do
  let signAlg = Cose.signAlg cosePubKey
      sig = runSeededMonadRandom seed $ Key.sign signAlg privKey msg
      valid = Cose.verify cosePubKey msg sig
   in case valid of
        Left _ -> False
        Right () -> True
