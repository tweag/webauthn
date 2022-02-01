{-# LANGUAGE DataKinds #-}

module Encoding (spec) where

import Control.Monad.Except (runExcept)
import Control.Monad.Reader (runReaderT)
import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.Model.WebIDL.Internal.Binary.Encoding (encodeRawCredential)
import Crypto.WebAuthn.Model.WebIDL.Internal.Decoding (Decode (decode))
import Crypto.WebAuthn.Model.WebIDL.Internal.Encoding (Encode (encode))
import Crypto.WebAuthn.Registries (supportedRegistries)
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
  case runExcept $ runReaderT (decode encoded) supportedRegistries of
    Right decoded -> decoded `shouldBe` options
    Left err -> expectationFailure $ show err

prop_requestOptionsRoundtrip :: M.CredentialOptions 'M.Authentication -> Expectation
prop_requestOptionsRoundtrip options = do
  let encoded = encode options
  case runExcept $ runReaderT (decode encoded) supportedRegistries of
    Right decoded -> decoded `shouldBe` options
    Left err -> expectationFailure $ show err

prop_createdCredentialRoundtrip :: M.Credential 'M.Registration 'False -> Expectation
prop_createdCredentialRoundtrip options = do
  let withRaw = encodeRawCredential options
      encoded = encode withRaw
  case runExcept $ runReaderT (decode encoded) supportedRegistries of
    Right decoded -> do
      decoded `shouldBe` withRaw
    Left err -> expectationFailure $ show err

prop_requestedCredentialRoundtrip :: M.Credential 'M.Authentication 'False -> Expectation
prop_requestedCredentialRoundtrip options = do
  let withRaw = encodeRawCredential options
      encoded = encode withRaw
  case runExcept $ runReaderT (decode encoded) supportedRegistries of
    Right decoded -> do
      decoded `shouldBe` withRaw
    Left err -> expectationFailure $ show err
