{-# LANGUAGE DataKinds #-}

module Encoding (spec) where

import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.Model.Binary.Encoding (encodeRawPublicKeyCredential)
import Crypto.WebAuthn.Model.JavaScript.Decoding
  ( decodeCreatedPublicKeyCredential,
    decodePublicKeyCredentialCreationOptions,
    decodePublicKeyCredentialRequestOptions,
    decodeRequestedPublicKeyCredential,
  )
import Crypto.WebAuthn.Model.JavaScript.Encoding
  ( encodeCreatedPublicKeyCredential,
    encodePublicKeyCredentialCreationOptions,
    encodePublicKeyCredentialRequestOptions,
    encodeRequestedPublicKeyCredential,
  )
import Crypto.WebAuthn.Operations.Attestation (allSupportedFormats)
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

prop_creationOptionsRoundtrip :: M.PublicKeyCredentialOptions 'M.Create -> Expectation
prop_creationOptionsRoundtrip options = do
  let encoded = encodePublicKeyCredentialCreationOptions options
  case decodePublicKeyCredentialCreationOptions encoded of
    Right decoded -> decoded `shouldBe` options
    Left err -> expectationFailure $ show err

prop_requestOptionsRoundtrip :: M.PublicKeyCredentialOptions 'M.Get -> Expectation
prop_requestOptionsRoundtrip options = do
  let encoded = encodePublicKeyCredentialRequestOptions options
  case decodePublicKeyCredentialRequestOptions encoded of
    Right decoded -> decoded `shouldBe` options
    Left err -> expectationFailure $ show err

prop_createdCredentialRoundtrip :: M.PublicKeyCredential 'M.Create 'False -> Expectation
prop_createdCredentialRoundtrip options = do
  let withRaw = encodeRawPublicKeyCredential options
      encoded = encodeCreatedPublicKeyCredential withRaw
  case decodeCreatedPublicKeyCredential allSupportedFormats encoded of
    Right decoded -> do
      decoded `shouldBe` withRaw
    Left err -> expectationFailure $ show err

prop_requestedCredentialRoundtrip :: M.PublicKeyCredential 'M.Get 'False -> Expectation
prop_requestedCredentialRoundtrip options = do
  let withRaw = encodeRawPublicKeyCredential options
      encoded = encodeRequestedPublicKeyCredential withRaw
  case decodeRequestedPublicKeyCredential encoded of
    Right decoded -> do
      decoded `shouldBe` withRaw
    Left err -> expectationFailure $ show err
