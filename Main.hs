{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Main where

import Control.Lens ((^?), _Just)
import Control.Monad.Except (ExceptT, MonadIO (liftIO), runExceptT)
import Crypto.JOSE.JWK.Store (VerificationKeyStore (getVerificationKeys))
import Crypto.JWT (CompactJWS, HasX5c (x5c), JWSHeader, JWTError, decodeCompact, fromX509Certificate, param, verifyJWS')
import qualified Data.ByteString.Lazy as LBS
import Data.List.NonEmpty (NonEmpty ((:|)))
import System.Environment (getArgs)

data Store = Store

instance VerificationKeyStore (ExceptT JWTError IO) (JWSHeader ()) LBS.ByteString Store where
  getVerificationKeys header _ _ = do
    let Just (x :| _) = header ^? x5c . _Just . param
    res <- fromX509Certificate x
    return [res]

main :: IO ()
main = do
  [path] <- getArgs
  Right payload <- runExceptT @JWTError $ do
    liftIO $ putStrLn $ "Reading " ++ path
    jws :: CompactJWS JWSHeader <- decodeCompact =<< liftIO (LBS.readFile path)
    liftIO $ putStrLn $ "Verifying.."
    verifyJWS' Store jws
  LBS.writeFile "output.json" payload
  putStrLn "Finished, wrote output to output.json"
