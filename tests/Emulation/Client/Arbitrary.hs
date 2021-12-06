{-# OPTIONS_GHC -Wno-orphans #-}

module Emulation.Client.Arbitrary () where

import Emulation.Client
  ( UserAgentNonConformingBehaviour (RandomChallenge),
  )
import PublicKeySpec ()
import Test.QuickCheck
  ( Arbitrary (arbitrary),
  )
import Test.QuickCheck.Gen (elements)

instance Arbitrary UserAgentNonConformingBehaviour where
  arbitrary = elements [RandomChallenge]
