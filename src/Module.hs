{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE UndecidableInstances #-}

module Module where

import Data.Coerce (coerce)
import GHC.Generics
import Data.Aeson

data SomeType
  = SomeValue0
  | SomeValue1
  | SomeValue2
  | SomeValue3
  | SomeValue4
  | SomeValue5
  | SomeValue6
  | SomeValue7
  | SomeValue8
  | SomeValue9
  | SomeValue10
  | SomeValue11
  | SomeValue12
  | SomeValue13
  | SomeValue14
  | SomeValue15
  | SomeValue16
  | SomeValue17
  | SomeValue18
  | SomeValue19
  | SomeValue20
  | SomeValue21
  | SomeValue22
  | SomeValue23
  | SomeValue24
  | SomeValue25
  | SomeValue26
  | SomeValue27
  | SomeValue28
  | SomeValue29
  deriving Generic
  deriving FromJSON via CustomJSON

newtype CustomJSON = CustomJSON SomeType

instance GFromJSON Zero (Rep SomeType) => FromJSON CustomJSON where
  parseJSON value = CustomJSON <$> genericParseJSON defaultOptions value

-- This is only about 2 times as slow with aeson 2.x than with 1.x, and
-- doesn't need UndecidableInstances:
--instance FromJSON CustomJSON where
--  parseJSON value = CustomJSON <$> genericParseJSON defaultOptions value

