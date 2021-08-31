{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Util where

import qualified Codec.Serialise as Serialise
import qualified Codec.Serialise.Properties as Serialise.Properties
import Test.Hspec (SpecWith, it)
import Test.QuickCheck (Arbitrary, property)

roundtrips :: forall a. (Eq a, Show a, Serialise.Serialise a, Arbitrary a) => SpecWith ()
roundtrips = do
  it "serialiseIdentity" $
    property $ \(key :: a) ->
      Serialise.Properties.serialiseIdentity key
  it "flatTermIdentity" $
    property $ \(key :: a) ->
      Serialise.Properties.flatTermIdentity key
  it "hasValidFlatTerm" $
    property $ \(key :: a) ->
      Serialise.Properties.hasValidFlatTerm key
