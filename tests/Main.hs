{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main
  ( main,
  )
where

import Crypto.Hash (hash)
import qualified Crypto.WebAuthn.Metadata.Service.Processing as Service
import qualified Crypto.WebAuthn.Metadata.Service.Types as Service
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Model.JavaScript as JS
import qualified Crypto.WebAuthn.Model.JavaScript.Decoding as JS
import qualified Crypto.WebAuthn.Operations.Assertion as WebAuthn
import qualified Crypto.WebAuthn.Operations.Attestation as WebAuthn
import qualified Crypto.WebAuthn.Operations.Common as Common
import qualified Crypto.WebAuthn.PublicKey as PublicKey
import Data.Aeson (FromJSON)
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Either (isRight)
import Data.Foldable (for_)
import qualified Data.Hourglass as HG
import Data.List.NonEmpty (NonEmpty)
import Data.Text.Encoding (encodeUtf8)
import Data.Validation (toEither)
import qualified Emulation
import qualified Encoding
import GHC.Stack (HasCallStack)
import qualified MetadataSpec
import qualified PublicKeySpec
import Spec.Util (decodeFile)
import qualified System.Directory as Directory
import System.FilePath ((</>))
import System.Hourglass (dateCurrent)
import Test.Hspec (Spec, describe, it, shouldSatisfy)
import qualified Test.Hspec as Hspec
import Test.QuickCheck.Instances.Text ()

-- | Attestation requires a specific time to be passed for the verification of the certificate chain.
-- For sake of reproducability we hardcode a time.
predeterminedDateTime :: HG.DateTime
predeterminedDateTime = HG.DateTime {dtDate = HG.Date {dateYear = 2021, dateMonth = HG.December, dateDay = 22}, dtTime = timeZero}

-- | For most uses of DateTime in these tests, the time of day isn't relevant. This definition allows easier construction of these DateTimes.
timeZero :: HG.TimeOfDay
timeZero = HG.TimeOfDay {todHour = HG.Hours 0, todMin = HG.Minutes 0, todSec = HG.Seconds 0, todNSec = HG.NanoSeconds 0}

-- | Load all files in the given directory, and ensure that all of them can be
-- decoded. The caller can pass in a function to run further checks on the
-- decoded value, but this is mainly there to ensure that `a` occurs after the
-- fat arrow.
canDecodeAllToJSRepr :: (FromJSON a, HasCallStack) => FilePath -> (a -> IO ()) -> Spec
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

-- | During tests, we need access to the metadata to verify the attestation of the test registration message.
-- We use the blob we also use for metadata parsing tests.
registryFromBlobFile :: IO Service.MetadataServiceRegistry
registryFromBlobFile = do
  blobBytes <- BS.readFile "tests/golden-metadata/big/blob.jwt"
  now <- dateCurrent
  let rootCert = Service.fidoAllianceRootCertificate
  case Service.jwtToJson blobBytes rootCert now of
    Left err -> error $ show err
    Right value -> case Service.jsonToPayload value of
      Left err -> error $ show err
      Right result -> return $ Service.createMetadataRegistry $ Service.mpEntries result

-- | Given a JSON Message in a file, performs attestation.
-- The Boolean argument denotes if the attestation message can be verified using the metadata service.
-- This is because some of our tests cannot be verfied (for different reasons).
registerTestFromFile :: FilePath -> M.Origin -> M.RpId -> Bool -> Service.MetadataServiceRegistry -> HG.DateTime -> IO ()
registerTestFromFile fp origin rpId verifiable service now = do
  pkCredential <-
    either (error . show) id . JS.decodeCreatedPublicKeyCredential WebAuthn.allSupportedFormats
      <$> decodeFile fp
  let options = defaultPublicKeyCredentialCreationOptions pkCredential
  let registerResult =
        toEither $
          WebAuthn.verifyAttestationResponse
            origin
            (M.RpIdHash . hash . encodeUtf8 . M.unRpId $ rpId)
            service
            options
            pkCredential
            now
  registerResult `shouldSatisfy` isExpectedAttestationResponse pkCredential options verifiable

main :: IO ()
main = Hspec.hspec $ do
  registry <- Hspec.runIO registryFromBlobFile
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
  describe
    "Emulation"
    Emulation.spec
  describe
    "Encoding"
    Encoding.spec
  -- We test assertion only for none attestation, this is because the type of attestation has no influence on assertion.
  describe "RegisterAndLogin" $
    it "tests whether the fixed register and login responses are matching" $
      do
        pkCredential <-
          either (error . show) id . JS.decodeCreatedPublicKeyCredential WebAuthn.allSupportedFormats
            <$> decodeFile
              "tests/responses/attestation/01-none.json"
        let options = defaultPublicKeyCredentialCreationOptions pkCredential
            registerResult =
              toEither $
                WebAuthn.verifyAttestationResponse
                  (M.Origin "http://localhost:8080")
                  (M.RpIdHash . hash $ ("localhost" :: ByteString.ByteString))
                  registry
                  options
                  pkCredential
                  predeterminedDateTime
        registerResult `shouldSatisfy` isExpectedAttestationResponse pkCredential options False
        let Right WebAuthn.AttestationResult {WebAuthn.rEntry = credentialEntry} = registerResult
        loginReq <-
          either (error . show) id . JS.decodeRequestedPublicKeyCredential
            <$> decodeFile
              @(JS.PublicKeyCredential JS.AuthenticatorAssertionResponse)
              "tests/responses/assertion/01-none.json"
        let M.PublicKeyCredential {M.pkcResponse = pkcResponse} = loginReq
            signInResult =
              toEither $
                WebAuthn.verifyAssertionResponse
                  (M.Origin "http://localhost:8080")
                  (M.RpIdHash . hash $ ("localhost" :: ByteString.ByteString))
                  (Just (M.UserHandle "UserId"))
                  credentialEntry
                  (defaultPublicKeyCredentialRequestOptions loginReq)
                  M.PublicKeyCredential
                    { M.pkcIdentifier = Common.ceCredentialId credentialEntry,
                      M.pkcResponse = pkcResponse,
                      M.pkcClientExtensionResults = M.AuthenticationExtensionsClientOutputs {}
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
        "tests/responses/attestation/packed-02.json"
        "http://localhost:5000"
        "localhost"
        True
        registry
        predeterminedDateTime
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

-- | Checks if the received attestation response if one we expect
isExpectedAttestationResponse :: M.PublicKeyCredential 'M.Create 'True -> M.PublicKeyCredentialOptions 'M.Create -> Bool -> Either (NonEmpty WebAuthn.AttestationError) WebAuthn.AttestationResult -> Bool
isExpectedAttestationResponse _ _ _ (Left _) = False -- We should never receive errors
isExpectedAttestationResponse M.PublicKeyCredential {..} M.PublicKeyCredentialCreationOptions {..} verifiable (Right WebAuthn.AttestationResult {..}) =
  rEntry == expectedCredentialEntry
    && not verifiable
      || ( case rAttestationStatement of
             WebAuthn.SomeAttestationStatement _ WebAuthn.VerifiedAuthenticator {} -> True
             _ -> False
         )
  where
    expectedCredentialEntry :: Common.CredentialEntry
    expectedCredentialEntry =
      Common.CredentialEntry
        { ceCredentialId = pkcIdentifier,
          ceUserHandle = M.pkcueId pkcocUser,
          cePublicKeyBytes =
            M.PublicKeyBytes . M.unRaw
              . M.acdCredentialPublicKeyBytes
              . M.adAttestedCredentialData
              . M.aoAuthData
              $ M.arcAttestationObject pkcResponse,
          ceSignCounter = M.adSignCount . M.aoAuthData $ M.arcAttestationObject pkcResponse
        }

defaultPublicKeyCredentialCreationOptions :: M.PublicKeyCredential 'M.Create raw -> M.PublicKeyCredentialOptions 'M.Create
defaultPublicKeyCredentialCreationOptions pkc =
  M.PublicKeyCredentialCreationOptions
    { M.pkcocRp =
        M.PublicKeyCredentialRpEntity
          { M.pkcreId = Nothing,
            M.pkcreName = "Tweag I/O Test Server"
          },
      M.pkcocUser =
        M.PublicKeyCredentialUserEntity
          { M.pkcueId = M.UserHandle "UserId",
            M.pkcueDisplayName = "UserDisplayName",
            M.pkcueName = "UserAccountName"
          },
      M.pkcocChallenge = M.ccdChallenge . M.arcClientData $ M.pkcResponse pkc,
      M.pkcocPubKeyCredParams =
        [ M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = PublicKey.COSEAlgorithmIdentifierES256
            },
          M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = PublicKey.COSEAlgorithmIdentifierRS256
            }
        ],
      M.pkcocTimeout = Nothing,
      M.pkcocExcludeCredentials = [],
      M.pkcocAuthenticatorSelection = Nothing,
      M.pkcocAttestation = M.AttestationConveyancePreferenceNone,
      M.pkcocExtensions = Nothing
    }

defaultPublicKeyCredentialRequestOptions :: M.PublicKeyCredential 'M.Get raw -> M.PublicKeyCredentialOptions 'M.Get
defaultPublicKeyCredentialRequestOptions pkc =
  M.PublicKeyCredentialRequestOptions
    { M.pkcogChallenge = M.ccdChallenge . M.argClientData $ M.pkcResponse pkc,
      M.pkcogTimeout = Nothing,
      M.pkcogRpId = Just "localhost",
      M.pkcogAllowCredentials = [],
      M.pkcogUserVerification = M.UserVerificationRequirementPreferred,
      M.pkcogExtensions = Nothing
    }
