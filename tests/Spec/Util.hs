module Spec.Util (decodeFile) where

import Data.Aeson (FromJSON)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as ByteString

decodeFile :: (FromJSON a, Show a) => FilePath -> IO a
decodeFile filePath = do
  loginBytes <- ByteString.readFile filePath
  case Aeson.eitherDecode' loginBytes of
    Left err -> error $ "Failed to decode: " <> show err
    Right value -> pure value
