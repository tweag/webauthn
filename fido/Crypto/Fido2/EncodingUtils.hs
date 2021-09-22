module Crypto.Fido2.EncodingUtils (modifyTypeField) where

import Data.Char (toLower)
import Data.List (stripPrefix)

lowerFirst :: String -> String
lowerFirst [] = []
lowerFirst (x : xs) = toLower x : xs

modifyTypeField :: String -> String -> String
modifyTypeField prefix field = case stripPrefix prefix field of
  Nothing -> error $ "Field " <> field <> " doesn't have prefix " <> prefix
  Just stripped -> lowerFirst stripped
