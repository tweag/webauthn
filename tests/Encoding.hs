{-# LANGUAGE DataKinds #-}

module Encoding (spec) where

import Control.Monad.Reader (runReaderT)
import Crypto.WebAuthn.AttestationStatementFormat (allSupportedFormats)
import Crypto.WebAuthn.Encoding.Binary (encodeRawCredential)
import Crypto.WebAuthn.Encoding.Internal.WebAuthnJson (Decode (decode), Encode (encode))
import qualified Crypto.WebAuthn.Model as M
import Spec.Types ()
import Test.Hspec (Expectation, SpecWith, describe, expectationFailure, shouldBe)
import Test.Hspec.QuickCheck (prop)

spec :: SpecWith ()
spec = do
  describe "PublicKeyCredentialCreationOptions" $
    prop "can be roundtripped" prop_creationOptionsRoundtrip
  describe "PublicKeyCredentialRequestOptions" $
    prop "can be roundtripped" prop_requestOptionsRoundtrip
  describe "CreatedPublicKeyCredential" $
    prop "can be roundtripped" prop_createdCredentialRoundtrip
  describe "RequestedPublicKeyCredential" $
    prop "can be roundtripped" prop_requestedCredentialRoundtrip

prop_creationOptionsRoundtrip :: M.CredentialOptions 'M.Registration -> Expectation
prop_creationOptionsRoundtrip options = do
  let encoded = encode options
  case decode encoded of
    Right decoded -> decoded `shouldBe` options
    Left err -> expectationFailure $ show err

prop_requestOptionsRoundtrip :: M.CredentialOptions 'M.Authentication -> Expectation
prop_requestOptionsRoundtrip options = do
  let encoded = encode options
  case decode encoded of
    Right decoded -> decoded `shouldBe` options
    Left err -> expectationFailure $ show err

prop_createdCredentialRoundtrip :: M.Credential 'M.Registration 'False -> Expectation
prop_createdCredentialRoundtrip options = do
  let withRaw = encodeRawCredential options
      encoded = encode withRaw
  case runReaderT (decode encoded) allSupportedFormats of
    Right decoded -> do
      decoded `shouldBe` withRaw
    Left err -> expectationFailure $ show err

prop_requestedCredentialRoundtrip :: M.Credential 'M.Authentication 'False -> Expectation
prop_requestedCredentialRoundtrip options = do
  let withRaw = encodeRawCredential options
      encoded = encode withRaw
  case decode encoded of
    Right decoded -> do
      decoded `shouldBe` withRaw
    Left err -> expectationFailure $ show err
