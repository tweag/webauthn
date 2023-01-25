module Spec.Util (decodeFile, runSeededMonadRandom, timeZero, predeterminedDateTime) where

import qualified Crypto.Random as Random
import Data.Aeson (FromJSON)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as ByteString
import qualified Data.Hourglass as HG

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

-- | Attestation requires a specific time to be passed for the verification of the certificate chain.
-- For sake of reproducability we hardcode a time.
predeterminedDateTime :: HG.DateTime
predeterminedDateTime = HG.DateTime {HG.dtDate = HG.Date {HG.dateYear = 2023, HG.dateMonth = HG.January, HG.dateDay = 25}, HG.dtTime = timeZero}

-- | For most uses of DateTime in these tests, the time of day isn't relevant. This definition allows easier construction of these DateTimes.
timeZero :: HG.TimeOfDay
timeZero = HG.TimeOfDay {HG.todHour = HG.Hours 0, HG.todMin = HG.Minutes 0, HG.todSec = HG.Seconds 0, HG.todNSec = HG.NanoSeconds 0}
