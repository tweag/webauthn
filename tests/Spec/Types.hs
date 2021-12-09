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
import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.Model.WebauthnType (SWebauthnType (SCreate, SGet), SingI (sing))
import qualified Crypto.WebAuthn.Operations.Attestation.None as None
import qualified Data.ByteString.Lazy as LBS
import Data.Maybe (fromJust)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text.Encoding (encodeUtf8)
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified PublicKeySpec ()
import Test.QuickCheck (Arbitrary (arbitrary), Gen, arbitraryBoundedEnum, elements, frequency, liftArbitrary, resize, shuffle, sublistOf)
import Test.QuickCheck.Instances.Text ()

instance Arbitrary M.PublicKeyCredentialType where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.AuthenticatorTransport where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.AuthenticatorAttachment where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.ResidentKeyRequirement where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.UserVerificationRequirement where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary M.AttestationConveyancePreference where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary (M.AuthenticatorResponse 'M.Create 'False) where
  arbitrary = M.AuthenticatorAttestationResponse <$> arbitrary <*> arbitrary

instance Arbitrary M.AssertionSignature where
  arbitrary = M.AssertionSignature <$> arbitrary

instance Arbitrary (M.AuthenticatorResponse 'M.Get 'False) where
  arbitrary =
    M.AuthenticatorAssertionResponse
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary (M.RawField 'False) where
  arbitrary = pure M.NoRaw

instance Arbitrary (M.CollectedClientData t 'False) where
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

instance SingI t => Arbitrary (M.AuthenticatorData t 'False) where
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

instance SingI t => Arbitrary (M.AttestedCredentialData t 'False) where
  arbitrary = case sing @t of
    SCreate -> M.AttestedCredentialData <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary
    SGet -> pure M.NoAttestedCredentialData

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

instance Arbitrary M.PublicKeyCredentialRpEntity where
  arbitrary =
    M.PublicKeyCredentialRpEntity
      <$> arbitrary
      <*> arbitrary

instance Arbitrary M.UserHandle where
  arbitrary = M.UserHandle <$> arbitrary

instance Arbitrary M.UserAccountDisplayName where
  arbitrary = M.UserAccountDisplayName <$> arbitrary

instance Arbitrary M.UserAccountName where
  arbitrary = M.UserAccountName <$> arbitrary

instance Arbitrary M.PublicKeyCredentialUserEntity where
  arbitrary =
    M.PublicKeyCredentialUserEntity
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary M.Timeout where
  arbitrary = M.Timeout <$> arbitrary

instance Arbitrary M.PublicKeyCredentialDescriptor where
  arbitrary =
    M.PublicKeyCredentialDescriptor M.PublicKeyCredentialTypePublicKey
      <$> arbitrary
      <*> liftArbitrary shuffledSubset

instance Arbitrary M.AuthenticatorSelectionCriteria where
  arbitrary =
    M.AuthenticatorSelectionCriteria
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary M.AuthenticationExtensionsClientInputs where
  arbitrary = pure M.AuthenticationExtensionsClientInputs

instance Arbitrary (M.PublicKeyCredentialOptions 'M.Create) where
  arbitrary =
    M.PublicKeyCredentialCreationOptions
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> parameters
      <*> arbitrary
      <*> resize 4 arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary (M.PublicKeyCredentialOptions 'M.Get) where
  arbitrary =
    M.PublicKeyCredentialRequestOptions
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> resize 4 arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary M.AuthenticationExtensionsClientOutputs where
  arbitrary = pure M.AuthenticationExtensionsClientOutputs

instance Arbitrary (M.PublicKeyCredential 'M.Create 'False) where
  arbitrary =
    M.PublicKeyCredential
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary (M.PublicKeyCredential 'M.Get 'False) where
  arbitrary =
    M.PublicKeyCredential
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary

shuffledSubset :: (Ord a, Bounded a, Enum a) => Gen [a]
shuffledSubset = subset >>= shuffle . Set.toList

subset :: (Ord a, Bounded a, Enum a) => Gen (Set a)
subset = Set.fromList <$> sublistOf (Set.toList completeSet)

parameters :: Gen [M.PublicKeyCredentialParameters]
parameters = do
  algs <- shuffledSubset
  pure $ M.PublicKeyCredentialParameters M.PublicKeyCredentialTypePublicKey <$> algs

completeSet :: (Ord a, Bounded a, Enum a) => Set a
completeSet = Set.fromList [minBound .. maxBound]
