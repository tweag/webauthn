{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main
  ( main,
  )
where

import Crypto.Hash (hash)
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import qualified Crypto.WebAuthn.Encoding.WebAuthnJson as WJ
import qualified Crypto.WebAuthn.Metadata as Meta
import qualified Crypto.WebAuthn.Metadata.Service.Types as Service
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Operation as O
import Data.Aeson (FromJSON)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Either (isRight)
import Data.Foldable (for_)
import qualified Data.Hourglass as HG
import Data.List (intercalate)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import qualified Data.Text as Text
import Data.Text.Encoding (encodeUtf8)
import Data.These (These (That, These, This))
import Data.Validation (toEither)
import qualified Emulation
import qualified Encoding
import GHC.Stack (HasCallStack)
import qualified MetadataSpec
import qualified PublicKeySpec
import Spec.Util (decodeFile, predeterminedDateTime, timeZero)
import qualified System.Directory as Directory
import System.FilePath ((</>))
import Test.Hspec (Spec, describe, it, shouldSatisfy)
import qualified Test.Hspec as Hspec
import Test.QuickCheck.Instances.Text ()

-- | Load all files in the given directory, and ensure that all of them can be
-- decoded. The caller can pass in a function to run further checks on the
-- decoded value, but this is mainly there to ensure that `a` occurs after the
-- fat arrow.
canDecodeAllToJSRepr :: forall a. (FromJSON a, HasCallStack) => FilePath -> Spec
canDecodeAllToJSRepr path = do
  files <- Hspec.runIO $ Directory.listDirectory path
  for_ files $ \fname ->
    it ("can decode " <> (path </> fname)) $ do
      bytes <- ByteString.readFile $ path </> fname
      case Aeson.eitherDecode' @a $ LazyByteString.fromStrict bytes of
        Left err -> fail err
        Right _value -> pure ()

-- | During tests, we need access to the metadata to verify the attestation of the test registration message.
-- We use the blob we also use for metadata parsing tests.
registryFromBlobFile :: IO Service.MetadataServiceRegistry
registryFromBlobFile = do
  blobBytes <- BS.readFile "tests/golden-metadata/big/blob.jwt"
  case Meta.metadataBlobToRegistry blobBytes predeterminedDateTime of
    Left err -> error $ Text.unpack err
    Right (This err) -> error $ intercalate "," (Text.unpack <$> NE.toList err)
    Right (These err _res) -> error $ "Unexpected MDS parsing errors: " <> intercalate "," (Text.unpack <$> NE.toList err)
    Right (That res) -> pure res

-- | Given a JSON Message in a file, performs attestation.
-- The Boolean argument denotes if the attestation message can be verified using the metadata service.
-- This is because some of our tests cannot be verfied (for different reasons).
registerTestFromFile :: FilePath -> M.Origin -> M.RpId -> Bool -> Service.MetadataServiceRegistry -> HG.DateTime -> IO ()
registerTestFromFile fp origin rpId verifiable service now = do
  registerTestFromFile' fp origin rpId verifiable service now M.CredentialMediationRequirementOptional

-- | Same as 'registerTestFromFile', but allows to specifies the mediation requirement as conditional.
registerTestFromFileConditional :: FilePath -> M.Origin -> M.RpId -> Bool -> Service.MetadataServiceRegistry -> HG.DateTime -> IO ()
registerTestFromFileConditional fp origin rpId verifiable service now = do
  registerTestFromFile' fp origin rpId verifiable service now M.CredentialMediationRequirementConditional

registerTestFromFile' :: FilePath -> M.Origin -> M.RpId -> Bool -> Service.MetadataServiceRegistry -> HG.DateTime -> M.CredentialMediationRequirement -> IO ()
registerTestFromFile' fp origin rpId verifiable service now mediation = do
  pkCredential <-
    either (error . show) id . WJ.wjDecodeCredentialRegistration
      <$> decodeFile fp
  let options = defaultPublicKeyCredentialCreationOptions pkCredential
  let registerResult =
        toEither $
          O.verifyRegistrationResponse
            (NE.singleton origin)
            (M.RpIdHash . hash . encodeUtf8 . M.unRpId $ rpId)
            service
            now
            options
            mediation
            pkCredential
  registerResult `shouldSatisfy` isExpectedAttestationResponse pkCredential options verifiable

main :: IO ()
main = Hspec.hspec $ do
  registry <- Hspec.runIO registryFromBlobFile
  describe "Decode test responses" $ do
    -- Check if all attestation responses can be decoded
    describe "attestation responses" $
      canDecodeAllToJSRepr
        @WJ.WJCredentialRegistration
        "tests/responses/attestation/"
    -- Check if all assertion responses can be decoded
    describe "assertion responses" $
      canDecodeAllToJSRepr
        @WJ.WJCredentialAuthentication
        "tests/responses/assertion/"
  -- Test public key related tests
  describe "PublicKey" PublicKeySpec.spec
  describe
    "Metadata"
    MetadataSpec.spec
  describe
    "Emulation"
    Emulation.spec
  describe
    "Encoding"
    Encoding.spec
  -- We test assertion only for none attestation, this is because the type of attestation has no influence on assertion.
  describe "RegisterAndLogin" $ do
    it "tests whether the fixed register and login responses are matching" $
      do
        pkCredential <-
          either (error . show) id . WJ.wjDecodeCredentialRegistration
            <$> decodeFile
              "tests/responses/attestation/01-none.json"
        let options = defaultPublicKeyCredentialCreationOptions pkCredential
            registerResult =
              toEither $
                O.verifyRegistrationResponse
                  (NE.singleton $ M.Origin "http://localhost:8080")
                  (M.RpIdHash . hash $ ("localhost" :: ByteString.ByteString))
                  registry
                  predeterminedDateTime
                  options
                  M.CredentialMediationRequirementOptional
                  pkCredential
        registerResult `shouldSatisfy` isExpectedAttestationResponse pkCredential options False
        let Right O.RegistrationResult {O.rrEntry = credentialEntry} = registerResult
        loginReq <-
          either (error . show) id . WJ.wjDecodeCredentialAuthentication
            <$> decodeFile
              @WJ.WJCredentialAuthentication
              "tests/responses/assertion/01-none.json"
        let M.Credential {M.cResponse = cResponse} = loginReq
            signInResult =
              toEither $
                O.verifyAuthenticationResponse
                  (NE.singleton $ M.Origin "http://localhost:8080")
                  (M.RpIdHash . hash $ ("localhost" :: ByteString.ByteString))
                  (Just (M.UserHandle "UserId"))
                  credentialEntry
                  (defaultPublicKeyCredentialRequestOptions loginReq)
                  M.Credential
                    { M.cIdentifier = O.ceCredentialId credentialEntry,
                      M.cResponse = cResponse,
                      M.cClientExtensionResults = M.AuthenticationExtensionsClientOutputs Nothing
                    }
        signInResult `shouldSatisfy` isRight
    it "tests whether the fixed register and login responses are matching with empty user handle" $
      do
        pkCredential <-
          either (error . show) id . WJ.wjDecodeCredentialRegistration
            <$> decodeFile
              "tests/responses/attestation/01-none.json"
        let options = defaultPublicKeyCredentialCreationOptions pkCredential
            registerResult =
              toEither $
                O.verifyRegistrationResponse
                  (NE.singleton $ M.Origin "http://localhost:8080")
                  (M.RpIdHash . hash $ ("localhost" :: ByteString.ByteString))
                  registry
                  predeterminedDateTime
                  options
                  M.CredentialMediationRequirementOptional
                  pkCredential
        registerResult `shouldSatisfy` isExpectedAttestationResponse pkCredential options False
        let Right O.RegistrationResult {O.rrEntry = credentialEntry} = registerResult
        loginReq <-
          either (error . show) id . WJ.wjDecodeCredentialAuthentication
            <$> decodeFile
              @WJ.WJCredentialAuthentication
              "tests/responses/assertion/01-none-empty-user-handle.json"
        let M.Credential {M.cResponse = cResponse} = loginReq
            signInResult =
              toEither $
                O.verifyAuthenticationResponse
                  (NE.singleton $ M.Origin "http://localhost:8080")
                  (M.RpIdHash . hash $ ("localhost" :: ByteString.ByteString))
                  (Just (M.UserHandle "UserId"))
                  credentialEntry
                  (defaultPublicKeyCredentialRequestOptions loginReq)
                  M.Credential
                    { M.cIdentifier = O.ceCredentialId credentialEntry,
                      M.cResponse = cResponse,
                      M.cClientExtensionResults = M.AuthenticationExtensionsClientOutputs Nothing
                    }
        signInResult `shouldSatisfy` isRight
  describe "Packed register" $ do
    it "tests whether the fixed packed register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/packed-01.json"
        "https://localhost:44329"
        "localhost"
        -- This attestation response appears to be from a Feitian security key,
        -- however the returned AAGUID is not registered in the FIDO Metadata
        -- service, even though there are a lot of other Feitian keys there.
        -- While the chain of the attestation statement contains the root
        -- certificate, we can't find an official publication of any root
        -- certificate, therefore making this attestation questionable. Perhaps
        -- it is from an older Feitian model not supported anymore
        False
        registry
        predeterminedDateTime
    it "tests whether the fixed packed register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/packed-02.json"
        "http://localhost:5000"
        "localhost"
        True
        registry
        predeterminedDateTime
    it "tests whether the fixed packed register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/packed-03.json"
        "http://localhost:5000"
        "localhost"
        True
        registry
        predeterminedDateTime
    it "regression test for #150" $
      registerTestFromFile
        "tests/responses/attestation/regression-150.json"
        "https://webauthn.dev.tweag.io"
        "webauthn.dev.tweag.io"
        False
        registry
        predeterminedDateTime
    it "the response with transports information works" $
      registerTestFromFile
        "tests/responses/attestation/with-transports.json"
        "https://infinisil.webauthn.dev.tweag.io"
        "infinisil.webauthn.dev.tweag.io"
        True
        registry
        predeterminedDateTime
    it "the response without a aaguid extension works" $
      registerTestFromFile
        "tests/responses/attestation/without-aaguid.json"
        "https://mercury.com/"
        "mercury.com"
        -- Uses "Dynamic Softtoken CA", which is an unknown software CA. And
        -- thus not verifiable by this library, which, by default, requires
        -- hardware attestation.
        False
        registry
        HG.DateTime
          { dtDate = HG.Date {dateYear = 2023, dateMonth = HG.July, dateDay = 18},
            dtTime = HG.TimeOfDay {todHour = HG.Hours 21, todMin = HG.Minutes 7, todSec = HG.Seconds 6, todNSec = HG.NanoSeconds 0}
          }
  describe "AndroidKey register" $ do
    it "tests whether the fixed android key register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/android-key-01.json"
        "https://localhost:44329"
        "localhost"
        False -- Uses a fake certificate in the chain
        registry
        predeterminedDateTime
    it "tests whether the fixed android key register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/android-key-02.json"
        "https://dev.dontneeda.pw"
        "dev.dontneeda.pw"
        False -- Uses a fake certificate in the chain
        registry
        predeterminedDateTime
  describe "AndroidSafetyNet register" $ do
    it "tests whether the fixed android safetynet register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/android-safetynet-01.json"
        "https://devicemanagement-duo1.pwl.ngrok.io"
        "pwl.ngrok.io"
        True
        registry
        HG.DateTime
          { dtDate = HG.Date {dateYear = 2021, dateMonth = HG.September, dateDay = 3},
            dtTime = HG.TimeOfDay {todHour = HG.Hours 21, todMin = HG.Minutes 7, todSec = HG.Seconds 21, todNSec = HG.NanoSeconds 0}
          }
  describe "U2F register" $ do
    it "tests whether the fixed fido-u2f register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/u2f-01.json"
        "https://localhost:44329"
        "localhost"
        True
        registry
        predeterminedDateTime
    it "tests whether the fixed fido-u2f register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/u2f-02.json"
        "http://localhost:5000"
        "localhost"
        True
        registry
        predeterminedDateTime
    it "tests whether the fixed fido-u2f register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/u2f-03.json"
        "http://localhost:5000"
        "localhost"
        False -- Uses a FIDO test key
        registry
        predeterminedDateTime
    it "tests whether the fixed fido-u2f register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/u2f-04.json"
        "https://api-duo1.duo.test"
        "duo.test"
        True
        registry
        predeterminedDateTime
    it "tests whether the fixed fido-u2f register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/u2f-05.json"
        "https://api-duo1.duo.test"
        "duo.test"
        True
        registry
        predeterminedDateTime
  describe "Apple register" $ do
    it "tests whether the fixed apple register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/apple-01.json"
        "https://6cc3c9e7967a.ngrok.io"
        "6cc3c9e7967a.ngrok.io"
        True
        registry
        HG.DateTime {dtDate = HG.Date {dateYear = 2020, dateMonth = HG.October, dateDay = 8}, dtTime = timeZero}
    it "tests whether the fixed apple register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/apple-02.json"
        "https://dev2.dontneeda.pw:5000"
        "dev2.dontneeda.pw"
        True
        registry
        HG.DateTime {dtDate = HG.Date {dateYear = 2021, dateMonth = HG.September, dateDay = 1}, dtTime = timeZero}
  describe "TPM register" $ do
    it "tests whether the fixed TPM-SHA1 register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/tpm-rs1-01.json"
        "https://webauthntest.azurewebsites.net"
        "webauthntest.azurewebsites.net"
        True
        registry
        predeterminedDateTime
    it "tests whether the fixed TPM-SHA1 register has a valid attestation" $
      registerTestFromFile
        "tests/responses/attestation/tpm-es256-01.json"
        "https://localhost:44329"
        "localhost"
        False -- Uses a fake certificate in the chain
        registry
        predeterminedDateTime
  describe "Conditional create register" $ do
    it "tests whether conditional create registration bypases UP check" $
      registerTestFromFileConditional
        "tests/responses/attestation/conditional-create.json"
        "http://localhost:8080"
        "localhost"
        False -- Uses a fake certificate in the chain
        registry
        predeterminedDateTime

-- | Checks if the received attestation response if one we expect
isExpectedAttestationResponse :: M.Credential 'M.Registration 'True -> M.CredentialOptions 'M.Registration -> Bool -> Either (NonEmpty O.RegistrationError) O.RegistrationResult -> Bool
isExpectedAttestationResponse _ _ _ (Left _) = False -- We should never receive errors
isExpectedAttestationResponse M.Credential {..} M.CredentialOptionsRegistration {..} verifiable (Right O.RegistrationResult {..}) =
  rrEntry == expectedCredentialEntry
    && not verifiable
    || ( case rrAttestationStatement of
           O.SomeAttestationStatement _ O.VerifiedAuthenticator {} -> True
           _ -> False
       )
  where
    expectedCredentialEntry :: O.CredentialEntry
    expectedCredentialEntry =
      O.CredentialEntry
        { ceCredentialId = cIdentifier,
          ceUserHandle = M.cueId corUser,
          cePublicKeyBytes =
            M.PublicKeyBytes
              . M.unRaw
              . M.acdCredentialPublicKeyBytes
              . M.adAttestedCredentialData
              . M.aoAuthData
              $ M.arrAttestationObject cResponse,
          ceSignCounter = M.adSignCount . M.aoAuthData $ M.arrAttestationObject cResponse,
          ceTransports = M.arrTransports cResponse
        }

defaultPublicKeyCredentialCreationOptions :: M.Credential 'M.Registration raw -> M.CredentialOptions 'M.Registration
defaultPublicKeyCredentialCreationOptions c =
  M.CredentialOptionsRegistration
    { M.corRp =
        M.CredentialRpEntity
          { M.creId = Nothing,
            M.creName = "Tweag I/O Test Server"
          },
      M.corUser =
        M.CredentialUserEntity
          { M.cueId = M.UserHandle "UserId",
            M.cueDisplayName = "UserDisplayName",
            M.cueName = "UserAccountName"
          },
      M.corChallenge = M.ccdChallenge . M.arrClientData $ M.cResponse c,
      M.corPubKeyCredParams =
        [ M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmES256
            },
          M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmRS256
            },
          M.CredentialParameters
            { cpTyp = M.CredentialTypePublicKey,
              cpAlg = Cose.CoseAlgorithmEdDSA
            }
        ],
      M.corTimeout = Nothing,
      M.corExcludeCredentials = [],
      M.corAuthenticatorSelection = Nothing,
      M.corAttestation = M.AttestationConveyancePreferenceNone,
      M.corExtensions = Nothing
    }

defaultPublicKeyCredentialRequestOptions :: M.Credential 'M.Authentication raw -> M.CredentialOptions 'M.Authentication
defaultPublicKeyCredentialRequestOptions c =
  M.CredentialOptionsAuthentication
    { M.coaChallenge = M.ccdChallenge . M.araClientData $ M.cResponse c,
      M.coaTimeout = Nothing,
      M.coaRpId = Just "localhost",
      M.coaAllowCredentials = [],
      M.coaUserVerification = M.UserVerificationRequirementPreferred,
      M.coaExtensions = Nothing
    }
