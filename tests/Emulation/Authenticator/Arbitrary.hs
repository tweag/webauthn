{-# OPTIONS_GHC -Wno-orphans #-}

module Emulation.Authenticator.Arbitrary () where

import qualified Data.Map as Map
import qualified Data.Set as Set
import Emulation.Authenticator
  ( Authenticator (AuthenticatorNone),
    AuthenticatorNonConformingBehaviour,
    AuthenticatorSignatureCounter (Global, PerCredential, Unsupported),
  )
import PublicKeySpec ()
import Spec.Types ()
import Test.QuickCheck
  ( Arbitrary (arbitrary),
    NonEmptyList (getNonEmpty),
    arbitraryBoundedEnum,
    oneof,
  )

instance Arbitrary AuthenticatorNonConformingBehaviour where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary AuthenticatorSignatureCounter where
  arbitrary =
    oneof
      [ pure Unsupported,
        -- We add one so the resulting number is never zero (which could be
        -- conflated with Unsupported if used in combination with the
        -- StaticCounter)
        Global . (+ 1) <$> arbitrary,
        pure $ PerCredential Map.empty
      ]

instance Arbitrary Authenticator where
  arbitrary =
    AuthenticatorNone
      <$> arbitrary
      <*> pure Map.empty
      <*> arbitrary
      -- An authenticator without any supported algorithms is useless to our tests
      <*> (Set.fromList . getNonEmpty <$> arbitrary)
      <*> arbitrary
      <*> arbitrary
