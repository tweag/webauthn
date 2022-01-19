{-# OPTIONS_GHC -Wno-orphans #-}

-- | Stability: internal
--
-- This module contains orphan instances connecting different date libraries together:
--
-- * [time](https://hackage.haskell.org/package/time), a commonly used library
--   containing the 'UTCTime' type, which is a bit slow and inconvenient to use
-- * [monad-time](https://hackage.haskell.org/package/monad-time) which defines
--   the 'MonadTime' class which uses 'UTCTime'. monad-time is used by the
--   [jose](https://hackage.haskell.org/package/jose) library to get the time
-- * [hourglass](https://hackage.haskell.org/package/hourglass), an alternative
--   to the time library which is nicer to use. It is used by the
--   [x509-validation](https://hackage.haskell.org/package/x509-validation) library
-- * [Data.Fixed](https://hackage.haskell.org/package/base/docs/Data-Fixed.html)
--   in @base@, which is used as the underlying representation of 'Data.Time.NominalDiffTime'
--   in the @time@ library.
--
-- This module contains a 'Timeable' and 'Time' implementation for 'UTCTime',
-- and a 'MonadTime' implementation for any 'ReaderT' of a 'Timeable'
module Crypto.WebAuthn.Internal.DateOrphans () where

import Control.Monad.Reader (ReaderT, asks)
import Control.Monad.Time (MonadTime, currentTime)
import Data.Fixed (Fixed (MkFixed), HasResolution, Nano)
import Data.Hourglass (Elapsed (Elapsed), ElapsedP (ElapsedP), NanoSeconds (NanoSeconds), Seconds (Seconds), Time, Timeable, timeConvert, timeFromElapsedP, timeGetElapsedP)
import Data.Time (UTCTime, nominalDiffTimeToSeconds, secondsToNominalDiffTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime, utcTimeToPOSIXSeconds)

instance Timeable UTCTime where
  timeGetElapsedP utcTime =
    timeGetElapsedP $ nominalDiffTimeToSeconds $ utcTimeToPOSIXSeconds utcTime

instance Time UTCTime where
  timeFromElapsedP = posixSecondsToUTCTime . secondsToNominalDiffTime . realToFrac

instance HasResolution a => Timeable (Fixed a) where
  timeGetElapsedP value = ElapsedP seconds nanos
    where
      ns :: Nano
      ns = realToFrac value
      (s, MkFixed n) = properFraction ns
      seconds = Elapsed $ Seconds s
      nanos = NanoSeconds $ fromInteger n

instance (Timeable t, Monad m) => MonadTime (ReaderT t m) where
  currentTime = asks timeConvert
