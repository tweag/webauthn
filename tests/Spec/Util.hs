module Spec.Util (decodeFile, runSeededMonadRandom) where

import qualified Crypto.Random as Random
import Data.Aeson (FromJSON)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as ByteString

decodeFile :: (FromJSON a, Show a) => FilePath -> IO a
decodeFile filePath = do
  loginBytes <- ByteString.readFile filePath
  case Aeson.eitherDecode' loginBytes of
    Left err -> error $ "Failed to decode: " <> show err
    Right value -> pure value

runSeededMonadRandom :: Integer -> Random.MonadPseudoRandom Random.ChaChaDRG a -> a
runSeededMonadRandom seed f = do
  let rng = Random.drgNewSeed $ Random.seedFromInteger seed
   in fst $ Random.withDRG rng f
