{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Main (main) where

import Data.Foldable (for_)
import Data.Aeson (FromJSON)
import System.FilePath ((</>))
import Test.Hspec (Spec, describe, it)
import GHC.Stack (HasCallStack)

import qualified Data.Aeson as Aeson
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import qualified System.Directory as Directory
import qualified Test.Hspec as Hspec

import qualified Crypto.Fido2.Protocol as Fido2

-- Load all files in the given directory, and ensure that all of them can be
-- decoded. The caller can pass in a function to run further checks on the
-- decoded value, but this is mainly there to ensure that `a` occurs after the
-- fat arrow.
canDecodeAll :: forall a. (FromJSON a, HasCallStack) => FilePath -> (a -> IO ()) -> Spec
canDecodeAll path inspect = do
  files <- Hspec.runIO $ Directory.listDirectory path
  for_ files $ \fname -> do
    it ("can decode " <> (path </> fname)) $ do
      bytes <- ByteString.readFile $ path </> fname
      case Aeson.eitherDecode' $ LazyByteString.fromStrict bytes of
        Left err -> fail err
        Right value -> inspect value

ignoreDecodedValue :: a -> IO ()
ignoreDecodedValue _ = pure ()

main :: IO ()
main = Hspec.hspec $ do

  describe "AuthenticatorAttestationResponse" $
    canDecodeAll
      @(Fido2.PublicKeyCredential Fido2.AuthenticatorAttestationResponse)
      "tests/fixtures/register-complete"
      ignoreDecodedValue

  describe "AuthenticatorAssertionResponse" $
    canDecodeAll
      @(Fido2.PublicKeyCredential Fido2.AuthenticatorAssertionResponse)
      "tests/fixtures/login-complete"
      ignoreDecodedValue

-- TODO: Restore this test.
-- tests :: TestTree
-- tests = Tasty.testGroup "Some tests"
--   [ Tasty.testCase "can decode request.json" $ do
--       x <- BS.readFile "./fixtures/request.json"
--       _
--   ]
