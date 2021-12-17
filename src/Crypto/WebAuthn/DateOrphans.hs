{-# OPTIONS_GHC -Wno-orphans #-}

-- | This module contains orphan instances connecting three different date libraries together:
--
-- * [time](https://hackage.haskell.org/package/time), a commonly used library
--   containing the 'UTCTime' type, which is a bit slow and inconvenient to use
-- * [monad-time](https://hackage.haskell.org/package/monad-time) which defines
--   the 'MonadTime' class which uses 'UTCTime'. monad-time is used by the
--   [jose](https://hackage.haskell.org/package/jose) library to get the time
-- * [hourglass](https://hackage.haskell.org/package/hourglass), an alternative
--   to the time library which is nicer to use. It is used by the
--   [x509-validation](https://hackage.haskell.org/package/x509-validation) library
--
-- This module contains a 'Timeable' and 'Time' implementation for 'UTCTime',
-- and a 'MonadTime' implementation for any 'ReaderT' of a 'Timeable'
module Crypto.WebAuthn.DateOrphans () where

import Control.Monad.Reader (ReaderT, asks)
import Control.Monad.Time (MonadTime, currentTime)
import Data.Fixed (Fixed (MkFixed))
import Data.Hourglass (Elapsed (Elapsed), ElapsedP (ElapsedP), NanoSeconds (NanoSeconds), Seconds (Seconds), Time, Timeable, timeConvert, timeFromElapsedP, timeGetElapsedP)
import Data.Time (UTCTime, nominalDiffTimeToSeconds, secondsToNominalDiffTime)
import Data.Time.Clock.POSIX (posixSecondsToUTCTime, utcTimeToPOSIXSeconds)

instance Timeable UTCTime where
  timeGetElapsedP utcTime = ElapsedP seconds nanos
    where
      (s, MkFixed n) = properFraction $ nominalDiffTimeToSeconds $ utcTimeToPOSIXSeconds utcTime
      seconds = Elapsed $ Seconds s
      nanos = NanoSeconds $ fromInteger n

instance Time UTCTime where
  timeFromElapsedP = posixSecondsToUTCTime . secondsToNominalDiffTime . realToFrac

instance (Timeable t, Monad m) => MonadTime (ReaderT t m) where
  currentTime = asks timeConvert
