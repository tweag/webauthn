{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Main
  ( main,
  )
where

import qualified Crypto.Fido2.Assertion as Fido2
import qualified Crypto.Fido2.Attestation as Fido2
import qualified Crypto.Fido2.Protocol as Fido2
import Data.Aeson (FromJSON)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Either (isRight)
import Data.Foldable (for_)
import GHC.Stack (HasCallStack)
import qualified System.Directory as Directory
import System.FilePath ((</>))
import Test.Hspec (Spec, describe, it, shouldSatisfy)
import qualified Test.Hspec as Hspec

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
  describe "Attestation"
    $ it "tests whether the fixed register and login responses are matching"
    $ do
      Fido2.PublicKeyCredential {response} <-
        decodeFile
          @(Fido2.PublicKeyCredential Fido2.AuthenticatorAttestationResponse)
          "tests/fixtures/register-complete/01.json"
      loginReq <-
        decodeFile
          @(Fido2.PublicKeyCredential Fido2.AuthenticatorAssertionResponse)
          "tests/fixtures/login-complete/01.json"
      let Fido2.AuthenticatorAttestationResponse {clientData} = response
          Fido2.ClientData {challenge} = clientData
      let registerResult =
            Fido2.verifyAttestationResponse
              (Fido2.Origin "http://localhost:8080")
              (Fido2.RpId "localhost")
              challenge
              Fido2.UserVerificationPreferred
              response
      registerResult `shouldSatisfy` isRight
      let (Right Fido2.AttestedCredentialData {credentialId, credentialPublicKey}) = registerResult
      let signInResult =
            Fido2.verifyAssertionResponse
              Fido2.RelyingPartyConfig {origin = Fido2.Origin "http://localhost:8080", rpId = Fido2.RpId "localhost"}
              challenge
              [Fido2.Credential {id = credentialId, publicKey = credentialPublicKey}]
              Fido2.UserVerificationPreferred
              loginReq
      signInResult `shouldSatisfy` isRight

decodeFile :: FromJSON a => FilePath -> IO a
decodeFile filePath = do
  loginBytes <- ByteString.readFile filePath
  case Aeson.eitherDecode' $ LazyByteString.fromStrict loginBytes of
    Left err -> error $ "Failed to decode: " <> show err
    Right value -> pure value
-- TODO: Restore this test.
-- tests :: TestTree
-- tests = Tasty.testGroup "Some tests"
--   [ Tasty.testCase "can decode request.json" $ do
--       x <- BS.readFile "./fixtures/request.json"
--       _
--   ]
