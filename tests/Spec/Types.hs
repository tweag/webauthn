{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Spec.Types () where

import Crypto.Hash (hash)
import qualified Crypto.Random as Random
import qualified Crypto.WebAuthn.AttestationStatementFormat.None as None
import qualified Crypto.WebAuthn.Cose.PublicKey as Cose
import qualified Crypto.WebAuthn.Cose.PublicKeyWithSignAlg as Cose
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import qualified Crypto.WebAuthn.Model as M
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (fromJust)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Singletons (SingI, sing)
import Data.Text.Encoding (encodeUtf8)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Spec.Key as Key
import Spec.Util (runSeededMonadRandom)
import Test.QuickCheck
  ( Arbitrary (arbitrary),
    Gen,
    arbitraryBoundedEnum,
    elements,
    frequency,
    liftArbitrary,
    oneof,
    resize,
    shuffle,
    sublistOf,
  )
import Test.QuickCheck.Instances.Text ()

instance Arbitrary Key.KeyPair where
  arbitrary = do
    seed <- arbitrary
    runSeededMonadRandom seed . Key.newKeyPair <$> arbitrary

instance Arbitrary Cose.CoseSignAlg where
  arbitrary =
    oneof
      [ pure Cose.CoseSignAlgEdDSA,
        Cose.CoseSignAlgECDSA <$> arbitrary,
        Cose.CoseSignAlgRSA <$> arbitrary
      ]

instance Arbitrary Cose.PublicKey where
  arbitrary = Cose.publicKey <$> arbitrary

instance Arbitrary Cose.CosePublicKey where
  arbitrary = Key.cosePubKey <$> arbitrary

instance Arbitrary Cose.CoseCurveEdDSA where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary Cose.CoseCurveECDSA where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary Cose.CoseHashAlgECDSA where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary Cose.CoseHashAlgRSA where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.CredentialType where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.AuthenticatorTransport where
  arbitrary = elements knownAuthenticatorTransports

knownAuthenticatorTransports :: [M.AuthenticatorTransport]
knownAuthenticatorTransports =
  [ M.AuthenticatorTransportBLE,
    M.AuthenticatorTransportInternal,
    M.AuthenticatorTransportNFC,
    M.AuthenticatorTransportUSB
  ]

instance Arbitrary M.AuthenticatorAttachment where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.ResidentKeyRequirement where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.UserVerificationRequirement where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.AttestationConveyancePreference where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary (M.AuthenticatorResponse 'M.Registration 'False) where
  arbitrary = M.AuthenticatorResponseRegistration <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary M.AssertionSignature where
  arbitrary = M.AssertionSignature <$> arbitrary

instance Arbitrary (M.AuthenticatorResponse 'M.Authentication 'False) where
  arbitrary =
    M.AuthenticatorResponseAuthentication
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary (M.RawField 'False) where
  arbitrary = pure M.NoRaw

instance Arbitrary (M.CollectedClientData c 'False) where
  arbitrary = M.CollectedClientData <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary (M.AttestationObject 'False) where
  arbitrary = do
    aoAuthData <- arbitrary
    ArbitraryAttestationStatementFormat aoFmt <- arbitrary
    aoAttStmt <- arbitrary
    pure M.AttestationObject {..}

-- Like SomeAttestationStatementFormat, but with an Arbitrary constraint on the AttStmt
data ArbitraryAttestationStatementFormat
  = forall a.
    (Arbitrary (M.AttStmt a), M.AttestationStatementFormat a) =>
    ArbitraryAttestationStatementFormat a

instance Arbitrary ArbitraryAttestationStatementFormat where
  arbitrary =
    elements
      [ ArbitraryAttestationStatementFormat None.Format
      --ArbitraryAttestationStatementFormat Packed.Format,
      --ArbitraryAttestationStatementFormat FidoU2F.Format,
      --ArbitraryAttestationStatementFormat AndroidKey.Format
      ]

instance Arbitrary M.SignatureCounter where
  arbitrary = M.SignatureCounter <$> arbitrary

instance SingI c => Arbitrary (M.AuthenticatorData c 'False) where
  arbitrary = M.AuthenticatorData <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary M.Challenge where
  arbitrary = M.Challenge <$> arbitrary

instance Arbitrary M.Origin where
  arbitrary = M.Origin <$> arbitrary

instance Arbitrary M.RpIdHash where
  arbitrary = do
    rpId <- encodeUtf8 <$> arbitrary
    pure $ M.RpIdHash $ hash rpId

instance Arbitrary M.AuthenticatorDataFlags where
  arbitrary = M.AuthenticatorDataFlags <$> arbitrary <*> arbitrary

instance SingI c => Arbitrary (M.AttestedCredentialData c 'False) where
  arbitrary = case sing @c of
    M.SRegistration -> M.AttestedCredentialData <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    M.SAuthentication -> pure M.NoAttestedCredentialData

instance Arbitrary M.AAGUID where
  arbitrary =
    M.AAGUID
      <$> frequency
        [ (1, pure UUID.nil),
          (10, randomUUID <$> arbitrary)
        ]
    where
      randomUUID :: Integer -> UUID
      randomUUID seed = fromJust $ UUID.fromByteString $ LBS.fromStrict bytes
        where
          rng = Random.drgNewSeed $ Random.seedFromInteger seed
          (bytes, _) = Random.withDRG rng $ Random.getRandomBytes 16

instance Arbitrary M.CredentialId where
  arbitrary = M.CredentialId <$> arbitrary

instance Arbitrary M.AuthenticatorExtensionOutputs where
  arbitrary = pure M.AuthenticatorExtensionOutputs {}

instance Arbitrary M.RpId where
  arbitrary = M.RpId <$> arbitrary

instance Arbitrary M.RelyingPartyName where
  arbitrary = M.RelyingPartyName <$> arbitrary

instance Arbitrary M.CredentialRpEntity where
  arbitrary =
    M.CredentialRpEntity
      <$> arbitrary
      <*> arbitrary

instance Arbitrary M.UserHandle where
  arbitrary = M.UserHandle <$> arbitrary

instance Arbitrary M.UserAccountDisplayName where
  arbitrary = M.UserAccountDisplayName <$> arbitrary

instance Arbitrary M.UserAccountName where
  arbitrary = M.UserAccountName <$> arbitrary

instance Arbitrary M.CredentialUserEntity where
  arbitrary =
    M.CredentialUserEntity
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary M.Timeout where
  arbitrary = M.Timeout <$> arbitrary

instance Arbitrary M.CredentialDescriptor where
  arbitrary =
    M.CredentialDescriptor M.CredentialTypePublicKey
      <$> arbitrary
      <*> liftArbitrary (shuffledSubsetWith $ Set.fromList knownAuthenticatorTransports)

instance Arbitrary M.AuthenticatorSelectionCriteria where
  arbitrary =
    M.AuthenticatorSelectionCriteria
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary M.AuthenticationExtensionsClientInputs where
  arbitrary = pure M.AuthenticationExtensionsClientInputs

instance Arbitrary (M.CredentialOptions 'M.Registration) where
  arbitrary =
    M.CredentialOptionsRegistration
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> parameters
      <*> arbitrary
      <*> resize 4 arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary (M.CredentialOptions 'M.Authentication) where
  arbitrary =
    M.CredentialOptionsAuthentication
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> resize 4 arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary M.AuthenticationExtensionsClientOutputs where
  arbitrary = pure M.AuthenticationExtensionsClientOutputs

instance Arbitrary (M.Credential 'M.Registration 'False) where
  arbitrary =
    M.Credential
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary (M.Credential 'M.Authentication 'False) where
  arbitrary =
    M.Credential
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary

shuffledSubsetWith :: Ord a => Set a -> Gen [a]
shuffledSubsetWith set = subsetWith set >>= shuffle . Set.toList

subsetWith :: Ord a => Set a -> Gen (Set a)
subsetWith set = Set.fromList <$> sublistOf (Set.toList set)

parameters :: Gen [M.CredentialParameters]
parameters = do
  algs <- shuffledSubsetWith $ Set.fromList allCoseAlgs
  pure $ M.CredentialParameters M.CredentialTypePublicKey <$> algs

allCoseAlgs :: [Cose.CoseSignAlg]
allCoseAlgs =
  [ Cose.CoseSignAlgEdDSA,
    Cose.CoseSignAlgECDSA Cose.CoseHashAlgECDSASHA256,
    Cose.CoseSignAlgECDSA Cose.CoseHashAlgECDSASHA384,
    Cose.CoseSignAlgECDSA Cose.CoseHashAlgECDSASHA512,
    Cose.CoseSignAlgRSA Cose.CoseHashAlgRSASHA1,
    Cose.CoseSignAlgRSA Cose.CoseHashAlgRSASHA256,
    Cose.CoseSignAlgRSA Cose.CoseHashAlgRSASHA384,
    Cose.CoseSignAlgRSA Cose.CoseHashAlgRSASHA512
  ]
