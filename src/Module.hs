{-# LANGUAGE DerivingVia, DataKinds, DeriveGeneric #-}
module Module where

import Data.Aeson
import Deriving.Aeson

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
  deriving ToJSON via CustomJSON '[] SomeType
