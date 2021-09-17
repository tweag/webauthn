{-# OPTIONS_GHC -Wno-orphans #-}

module Spec.Types () where

import qualified Crypto.Fido2.Attestation.Error as Fido2
import qualified Crypto.Fido2.Attestation.Error as Fido2AttestationError
import Crypto.Fido2.Protocol (AttestationFormat (FormatNone))
import qualified Crypto.Fido2.Protocol as Fido2
import Data.ByteString (ByteString)
import Data.Coerce (coerce)
import Data.Text (Text)
import qualified PublicKeySpec ()
import Test.QuickCheck.Arbitrary (Arbitrary (arbitrary))
import Test.QuickCheck.Gen (elements)
import Test.QuickCheck.Instances.Text ()

instance Arbitrary Fido2.AuthenticatorAttestationResponse where
  arbitrary = Fido2.AuthenticatorAttestationResponse <$> arbitrary <*> arbitrary

instance Arbitrary Fido2.ClientData where
  arbitrary =
    Fido2.ClientData
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> pure undefined -- TODO: How to generate sha256?

instance Arbitrary Fido2.AttestationObject where
  arbitrary = Fido2.AttestationObject <$> arbitrary <*> pure FormatNone

instance Arbitrary Fido2.AuthenticatorData where
  arbitrary =
    Fido2.AuthenticatorData undefined <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary Fido2AttestationError.Error where
  arbitrary =
    elements
      [ Fido2.InvalidWebauthnType,
        Fido2.ChallengeDidNotMatch,
        Fido2AttestationError.RpIdMismatch,
        Fido2AttestationError.UserNotPresent,
        Fido2AttestationError.UserNotVerified,
        Fido2.UnsupportedAttestationFormat,
        Fido2.InvalidAttestationStatement,
        Fido2.NoAttestedCredentialDataFound,
        Fido2.NotTrustworthy
      ]

instance Arbitrary Fido2.CredentialId where
  arbitrary = coerce (arbitrary @ByteString)

instance Arbitrary Fido2.RpId where
  arbitrary = coerce (arbitrary @Text)

instance Arbitrary Fido2.UserVerificationRequirement where
  arbitrary = elements [Fido2.UserVerificationDiscouraged, Fido2.UserVerificationPreferred, Fido2.UserVerificationRequired]

instance Arbitrary Fido2.AttestedCredentialData where
  arbitrary = Fido2.AttestedCredentialData <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary Fido2.WebauthnType where
  arbitrary = elements [Fido2.Get, Fido2.Create]

instance Arbitrary Fido2.Challenge where
  arbitrary = coerce (arbitrary @ByteString)

instance Arbitrary Fido2.Origin where
  arbitrary = coerce (arbitrary @Text)
