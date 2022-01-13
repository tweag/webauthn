{-# LANGUAGE RecordWildCards #-}

module PublicKeySpec
  ( spec,
  )
where

import Codec.Serialise.Properties (serialiseIdentity)
import qualified Crypto.WebAuthn.Cose.Key as Cose
import qualified Crypto.WebAuthn.PublicKey as PublicKey
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

prop_x509PublicKeyRoundtrip :: PublicKey.PublicKey -> Bool
prop_x509PublicKeyRoundtrip pubKey =
  case PublicKey.fromX509 (Key.toX509 pubKey) of
    Just pubKey'
      | pubKey == pubKey' -> True
      | otherwise -> False
    Nothing -> False

prop_signverify :: Integer -> Key.KeyPair -> BS.ByteString -> Bool
prop_signverify seed Key.KeyPair {..} msg = do
  let signAlg = Cose.keySignAlg pubKey
      sig = runSeededMonadRandom seed $ Key.sign signAlg privKey msg
      valid = PublicKey.verify signAlg (PublicKey.fromCose pubKey) msg sig
   in case valid of
        Left _ -> False
        Right () -> True
