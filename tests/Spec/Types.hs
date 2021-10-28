{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Spec.Types () where

import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.Model.WebauthnType (SWebauthnType (SCreate, SGet), SingI (sing))
import qualified Crypto.Fido2.Operations.Attestation.None as None
import qualified PublicKeySpec ()
import Test.QuickCheck (Arbitrary (arbitrary), arbitraryBoundedEnum, elements)
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

instance Arbitrary (M.AuthenticatorResponse 'M.Create) where
  arbitrary = M.AuthenticatorAttestationResponse <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary (M.CollectedClientData t) where
  arbitrary = M.CollectedClientData <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary M.AttestationObject where
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
      ]

instance Arbitrary M.SignatureCounter where
  arbitrary = M.SignatureCounter <$> arbitrary

instance SingI t => Arbitrary (M.AuthenticatorData t) where
  arbitrary = M.AuthenticatorData <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary M.Challenge where
  arbitrary = M.Challenge <$> arbitrary

instance Arbitrary M.Origin where
  arbitrary = M.Origin <$> arbitrary

instance Arbitrary M.ClientDataHash where
  arbitrary = undefined

instance Arbitrary M.RpIdHash where
  arbitrary = undefined

instance Arbitrary M.AuthenticatorDataFlags where
  arbitrary = M.AuthenticatorDataFlags <$> arbitrary <*> arbitrary

instance SingI t => Arbitrary (M.AttestedCredentialData t) where
  arbitrary = case sing @t of
    SCreate -> M.AttestedCredentialData <$> arbitrary <*> arbitrary <*> arbitrary <*> undefined
    SGet -> pure M.NoAttestedCredentialData

instance Arbitrary M.AAGUID where
  arbitrary = M.AAGUID <$> arbitrary

instance Arbitrary M.CredentialId where
  arbitrary = M.CredentialId <$> arbitrary

instance Arbitrary M.AuthenticatorExtensionOutputs where
  arbitrary = pure M.AuthenticatorExtensionOutputs {}
