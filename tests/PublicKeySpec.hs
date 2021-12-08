{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module PublicKeySpec
  ( spec,
  )
where

import qualified Codec.CBOR.Encoding as CBOR
import Codec.CBOR.Read (deserialiseFromBytes)
import qualified Codec.CBOR.Read as Read
import Codec.CBOR.Write (toLazyByteString)
import qualified Codec.CBOR.Write as Write
import Crypto.Hash (SHA384 (SHA384))
import Crypto.Hash.Algorithms (HashAlgorithm, SHA256 (SHA256), SHA512 (SHA512))
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.Random as Random
import Crypto.WebAuthn.PublicKey
  ( COSEAlgorithmIdentifier
      ( COSEAlgorithmIdentifierES256,
        COSEAlgorithmIdentifierES384,
        COSEAlgorithmIdentifierES512
      ),
    PublicKey
      ( ES256PublicKey,
        ES384PublicKey,
        ES512PublicKey,
        Ed25519PublicKey
      ),
    decodeCOSEAlgorithmIdentifier,
    decodePublicKey,
    encodePublicKey,
    toECDSAKey,
    verify,
  )
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.Prim as ASN1
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.Maybe (fromJust)
import Test.Hspec (SpecWith, describe, it, shouldSatisfy)
import Test.QuickCheck (Arbitrary, Gen, Property, arbitrary, arbitraryBoundedEnum, elements, oneof, property, (===))
import Test.QuickCheck.Instances.ByteString ()

instance Arbitrary COSEAlgorithmIdentifier where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary PublicKey where
  arbitrary =
    oneof
      [ ES256PublicKey <$> randomECDSAPublicKey ECC.SEC_p256r1,
        ES384PublicKey <$> randomECDSAPublicKey ECC.SEC_p384r1,
        ES512PublicKey <$> randomECDSAPublicKey ECC.SEC_p521r1,
        Ed25519PublicKey <$> arbitrary
      ]

newtype Ed25519KeyPair = Ed25519KeyPair (Ed25519.PublicKey, Ed25519.SecretKey) deriving (Eq, Show)

instance Arbitrary Ed25519.PublicKey where
  arbitrary = Ed25519.toPublic <$> arbitrary

instance Arbitrary Ed25519.SecretKey where
  arbitrary = do
    rng <- Random.drgNewSeed . Random.seedFromInteger <$> arbitrary
    let (a, _) = Random.withDRG rng Ed25519.generateSecretKey
    pure a

newtype ECDSAKeyPair = ECDSAKeyPair (ECDSA.PublicKey, ECDSA.PrivateKey) deriving (Eq, Show)

instance Arbitrary ECDSAKeyPair where
  arbitrary = ECDSAKeyPair <$> (randomECDSAKeyPair =<< arbitrary)

instance Arbitrary ECC.CurveName where
  arbitrary =
    elements
      [ ECC.SEC_p256r1,
        ECC.SEC_p384r1,
        ECC.SEC_p521r1
      ]

randomECDSAPublicKey :: ECC.CurveName -> Gen ECDSA.PublicKey
randomECDSAPublicKey curveName = fst <$> randomECDSAKeyPair curveName

randomECDSAKeyPair :: ECC.CurveName -> Gen (ECDSA.PublicKey, ECDSA.PrivateKey)
randomECDSAKeyPair curveName = do
  let curve = ECC.getCurveByName curveName
  rng <- Random.drgNewSeed . Random.seedFromInteger <$> arbitrary
  let ((public, private), _) = Random.withDRG rng (ECC.generate curve)
  pure (public, private)

spec :: SpecWith ()
spec = do
  describe "PublicKey" $ do
    describe "EdDSA" $ do
      it "accepts valid signatures" $
        property $
          \(secret :: Ed25519.SecretKey, bytes :: ByteString) ->
            let pub = Ed25519.toPublic secret
                sig = Ed25519.sign secret pub bytes
             in verify (Ed25519PublicKey pub) bytes (convert sig)
    describe "ECDSA" $ do
      it "accepts valid signatures ES256" $ ecdsaAcceptsValid COSEAlgorithmIdentifierES256 SHA256
      it "accepts valid signatures ES384" $ ecdsaAcceptsValid COSEAlgorithmIdentifierES384 SHA384
      it "accepts valid signatures ES512" $ ecdsaAcceptsValid COSEAlgorithmIdentifierES512 SHA512
      it "rejects invalid signatures ES256" $ ecdsaRejectsInvalid COSEAlgorithmIdentifierES256
      it "rejects invalid signatures ES384" $ ecdsaRejectsInvalid COSEAlgorithmIdentifierES384
      it "rejects invalid signatures ES512" $ ecdsaRejectsInvalid COSEAlgorithmIdentifierES512
      it "rejects invalid ASN.1 ES256" $ ecdsaRejectsInvalidASN COSEAlgorithmIdentifierES256
      it "rejects invalid ASN.1 ES384" $ ecdsaRejectsInvalidASN COSEAlgorithmIdentifierES384
      it "rejects invalid ASN.1 ES512" $ ecdsaRejectsInvalidASN COSEAlgorithmIdentifierES512
    it "encodes roundtrip" $ do
      property $
        \(key :: PublicKey) ->
          Right ("", key) === deserialiseFromBytes decodePublicKey (toLazyByteString $ encodePublicKey key)
  -- TODO: Find out how encoding changed
  -- Though COSE allows us to pick `alg` and `crv` independently, Webauthn wants us
  -- to let `alg` imply `crv`
  -- it "`alg` implies `crv`" $
  --   property $ \(key :: ECDSAKey, FlatTerm.toFlatTerm . Serialise.encode @CurveIdentifier -> [crv]) -> do
  --     -- in order to test this, we encode a public key where the alg and the crv do not match
  --     case FlatTerm.toFlatTerm . Serialise.encode . ECDSAPublicKey $ key of
  --       (map : ktyKey : ktyVal : algKey : algVal : crvKey : crvVal : xs) ->
  --         crvVal /= crv
  --           ==> let key' = map : ktyKey : ktyVal : algKey : algVal : crvKey : crv : xs
  --                   decoded = FlatTerm.fromFlatTerm (Serialise.decode @PublicKey) key'
  --                in case decoded of
  --                     Left x -> total x
  --       _ -> error "Didnt match shape"
  describe "COSEAlgorithmIdentifier" $ do
    it "fails to decode unspported COSEAlgorithmIdentifiers" $ do
      let bs = Write.toLazyByteString (CBOR.encodeInt (-300))
      Read.deserialiseFromBytes decodeCOSEAlgorithmIdentifier bs `shouldSatisfy` \case
        Left (Read.DeserialiseFailure _ "Unsupported `alg`") -> True
        _ -> False
  where
    ecdsaAcceptsValid :: HashAlgorithm hash => COSEAlgorithmIdentifier -> hash -> Property
    ecdsaAcceptsValid alg hash = property $
      \(ECDSAKeyPair (pub, priv) :: ECDSAKeyPair, bytes :: ByteString, seed :: Integer) ->
        let drg = Random.drgNewSeed . Random.seedFromInteger $ seed
            (ECDSA.Signature r s, _) = Random.withDRG drg $ ECDSA.sign priv hash bytes
         in verify (fromJust $ toECDSAKey alg pub) bytes (ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence])

    ecdsaRejectsInvalid :: COSEAlgorithmIdentifier -> Property
    ecdsaRejectsInvalid alg = property $
      \(ECDSAKeyPair (pub, _) :: ECDSAKeyPair, bytes :: ByteString, r, s) ->
        not $
          verify (fromJust $ toECDSAKey alg pub) bytes $
            ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence]

    ecdsaRejectsInvalidASN :: COSEAlgorithmIdentifier -> Property
    ecdsaRejectsInvalidASN alg =
      property $
        \(ECDSAKeyPair (pub, _) :: ECDSAKeyPair, bytes :: ByteString, r, s) ->
          not $
            verify (fromJust $ toECDSAKey alg pub) bytes $
              ASN1.encodeASN1' ASN1.DER [ASN1.Start ASN1.Sequence, ASN1.IntVal r, ASN1.IntVal s]
