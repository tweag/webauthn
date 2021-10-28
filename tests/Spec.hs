{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Main
  ( main,
  )
where

import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import qualified Crypto.Fido2.Model.JavaScript.Decoding as JS
import qualified Crypto.Fido2.Operations.Assertion as Fido2
import qualified Crypto.Fido2.Operations.Attestation as Fido2
import qualified Crypto.Fido2.Operations.Attestation.AndroidKey as AndroidKey
import qualified Crypto.Fido2.Operations.Attestation.FidoU2F as FidoU2F
import qualified Crypto.Fido2.Operations.Attestation.None as None
import qualified Crypto.Fido2.Operations.Common as Common
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (hash)
import Data.Aeson (FromJSON)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Either (isRight)
import Data.Foldable (for_)
import Data.Validation (toEither)
import GHC.Stack (HasCallStack)
import qualified MetadataSpec
import qualified PublicKeySpec
import Spec.Util (decodeFile)
import qualified System.Directory as Directory
import System.FilePath ((</>))
import Test.Hspec (Spec, describe, it, shouldSatisfy)
import qualified Test.Hspec as Hspec
import Test.QuickCheck.Instances.Text ()

-- Load all files in the given directory, and ensure that all of them can be
-- decoded. The caller can pass in a function to run further checks on the
-- decoded value, but this is mainly there to ensure that `a` occurs after the
-- fat arrow.
canDecodeAllToJSRepr :: forall a. (FromJSON a, HasCallStack) => FilePath -> (a -> IO ()) -> Spec
canDecodeAllToJSRepr path inspect = do
  files <- Hspec.runIO $ Directory.listDirectory path
  for_ files $ \fname ->
    it ("can decode " <> (path </> fname)) $ do
      bytes <- ByteString.readFile $ path </> fname
      case Aeson.eitherDecode' $ LazyByteString.fromStrict bytes of
        Left err -> fail err
        Right value -> inspect value

ignoreDecodedValue :: a -> IO ()
ignoreDecodedValue _ = pure ()

main :: IO ()
main = Hspec.hspec $ do
  describe "Decode test responses" $ do
    -- Check if all attestation responses can be decoded
    describe "attestation responses" $
      canDecodeAllToJSRepr
        @(JS.PublicKeyCredential JS.AuthenticatorAttestationResponse)
        "tests/responses/attestation/"
        ignoreDecodedValue
    -- Check if all assertion responses can be decoded
    describe "assertion responses" $
      canDecodeAllToJSRepr
        @(JS.PublicKeyCredential JS.AuthenticatorAssertionResponse)
        "tests/responses/assertion/"
        ignoreDecodedValue
  -- Test public key related tests
  describe "PublicKey" PublicKeySpec.spec
  describe
    "Metadata"
    MetadataSpec.spec
  describe "RegisterAndLogin" $
    it "tests whether the fixed register and login responses are matching" $
      do
        pkCredential <-
          JS.decodeCreatedPublicKeyCredential allSupportedAttestationStatementFormats
            <$> decodeFile
              "tests/responses/attestation/01-none.json"
        let registerResult = do
              toEither $
                Fido2.verifyAttestationResponse
                  (M.Origin "http://localhost:8080")
                  (rpIdHash "localhost")
                  defaultPublicKeyCredentialCreationOptions
                  (either (error . show) id pkCredential)
        registerResult `shouldSatisfy` isRight
        let (Right raw) = registerResult
            credentialEntry' = Common.decodeCredentialEntry raw
        credentialEntry' `shouldSatisfy` isRight
        let Right credentialEntry = credentialEntry'
        let Common.CredentialEntry {Common.ceCredentialId = ceCredentialId} = credentialEntry
        loginReq <-
          JS.decodeRequestedPublicKeyCredential
            <$> decodeFile
              @(JS.PublicKeyCredential JS.AuthenticatorAssertionResponse)
              "tests/responses/assertion/01-none.json"
        let Right M.PublicKeyCredential {M.pkcResponse = pkcResponse} = loginReq
            signInResult =
              toEither $
                Fido2.verifyAssertionResponse
                  (M.Origin "http://localhost:8080")
                  (rpIdHash "localhost")
                  (Just (M.UserHandle "UserId"))
                  credentialEntry
                  defaultPublicKeyCredentialRequestOptions
                  M.PublicKeyCredential
                    { pkcIdentifier = ceCredentialId,
                      pkcResponse = pkcResponse,
                      pkcClientExtensionResults = Nothing
                    }
        signInResult `shouldSatisfy` isRight

-- describe "Packed register" $
--   it "tests whether the fixed packed register has a valid attestation" $
--     do
--       Fido2.PublicKeyCredential {response} <-
--         decodeFile
--           @(Fido2.PublicKeyCredential Fido2.AuthenticatorAttestationResponse)
--           -- Test data used from fido2-net-lib (C) .NET Foundation and Contributors (MIT License)
--           "tests/responses/attestation/02-packed.json"
--       let Fido2.AuthenticatorAttestationResponse {clientData} = response
--           Fido2.ClientData {challenge} = clientData
--       let registerResult =
--             Fido2.verifyAttestationResponse
--               (Fido2.Origin "https://localhost:44329")
--               (Fido2.RpId "localhost")
--               challenge
--               Fido2.UserVerificationPreferred
--               response
--       registerResult `shouldSatisfy` isRight
-- describe "AndroidKey register" $
--   it "tests whether the fixed android key register has a valid attestation" $
--     do
--       Fido2.PublicKeyCredential {response} <-
--         decodeFile
--           @(Fido2.PublicKeyCredential Fido2.AuthenticatorAttestationResponse)
--           -- Test data used from fido2-net-lib (C) .NET Foundation and Contributors (MIT License)
--           "tests/responses/attestation/03-android-key.json"
--       let Fido2.AuthenticatorAttestationResponse {clientData} = response
--           Fido2.ClientData {challenge} = clientData
--       let registerResult =
--             Fido2.verifyAttestationResponse
--               (Fido2.Origin "https://localhost:44329")
--               (Fido2.RpId "localhost")
--               challenge
--               Fido2.UserVerificationPreferred
--               response
--       registerResult `shouldSatisfy` isRight
-- describe "U2F register" $
--   it "tests whether the fixed fido-u2f register has a valid attestation" $
--     do
--       Fido2.PublicKeyCredential {response} <-
--         decodeFile
--           @(Fido2.PublicKeyCredential Fido2.AuthenticatorAttestationResponse)
--           -- Test data used from fido2-net-lib (C) .NET Foundation and Contributors (MIT License)
--           "tests/responses/attestation/04-u2f.json"
--       let Fido2.AuthenticatorAttestationResponse {clientData} = response
--           Fido2.ClientData {challenge} = clientData
--       let registerResult =
--             Fido2.verifyAttestationResponse
--               (Fido2.Origin "https://localhost:44329")
--               (Fido2.RpId "localhost")
--               challenge
--               Fido2.UserVerificationPreferred
--               response
--       registerResult `shouldSatisfy` isRight

{- Disabled because we can't yet reproduce a login response for the register-complete/02.json
  let (Right Fido2.AttestedCredentialData {credentialId, credentialPublicKey}) = registerResult
  loginReq <-
    decodeFile
      @(Fido2.PublicKeyCredential Fido2.AuthenticatorAssertionResponse)
      "tests/fixtures/login-complete/02.json"
  let Fido2.PublicKeyCredential {response} = loginReq
  let Fido2.AuthenticatorAssertionResponse {clientData} = response
  let Fido2.ClientData {challenge} = clientData
  let signInResult =
        Fido2.verifyAssertionResponse
          Fido2.RelyingPartyConfig {origin = Fido2.Origin "https://localhost:44329", rpId = Fido2.RpId "localhost"}
          challenge
          [Fido2.Credential {id = credentialId, publicKey = credentialPublicKey}]
          Fido2.UserVerificationPreferred
          loginReq
  signInResult `shouldSatisfy` isRight
-}

defaultPublicKeyCredentialCreationOptions :: M.PublicKeyCredentialOptions 'M.Create
defaultPublicKeyCredentialCreationOptions =
  M.PublicKeyCredentialCreationOptions
    { M.pkcocRp =
        M.PublicKeyCredentialRpEntity
          { M.pkcreId = Just "localhost",
            M.pkcreName = "Tweag I/O Test Server"
          },
      M.pkcocUser =
        M.PublicKeyCredentialUserEntity
          { M.pkcueId = M.UserHandle "UserId",
            M.pkcueDisplayName = "UserDisplayName",
            M.pkcueName = "UserAccountName"
          },
      M.pkcocChallenge = M.Challenge "This is the Challenge",
      M.pkcocPubKeyCredParams =
        [ M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = PublicKey.COSEAlgorithmIdentifierES256
            }
        ],
      M.pkcocTimeout = Nothing,
      M.pkcocExcludeCredentials = Just [],
      M.pkcocAuthenticatorSelection = Nothing,
      M.pkcocAttestation = Nothing,
      M.pkcocExtensions = Nothing
    }

defaultPublicKeyCredentialRequestOptions :: M.PublicKeyCredentialOptions 'M.Get
defaultPublicKeyCredentialRequestOptions =
  M.PublicKeyCredentialRequestOptions
    { M.pkcogChallenge = M.Challenge "This is the Challenge",
      M.pkcogTimeout = Nothing,
      M.pkcogRpId = Just "localhost",
      M.pkcogAllowCredentials = Nothing,
      M.pkcogUserVerification = Nothing,
      M.pkcogExtensions = Nothing
    }

allSupportedAttestationStatementFormats :: M.SupportedAttestationStatementFormats
allSupportedAttestationStatementFormats =
  M.mkSupportedAttestationStatementFormats
    [ M.SomeAttestationStatementFormat None.Format,
      M.SomeAttestationStatementFormat AndroidKey.Format,
      M.SomeAttestationStatementFormat FidoU2F.Format
    ]

rpIdHash :: ByteString.ByteString -> M.RpIdHash
rpIdHash = M.RpIdHash . hash
