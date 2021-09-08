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

import qualified AttestationSpec
import Codec.CBOR.Term (Term (TInt))
import qualified Crypto.Fido2.Assertion as Fido2
import qualified Crypto.Fido2.Attestation as Fido2
import qualified Crypto.Fido2.Attestation.Error as Fido2
import qualified Crypto.Fido2.Attestation.Error as Fido2AttestationError
import qualified Crypto.Fido2.Protocol as Fido2
import qualified Crypto.Hash as Hash
import Data.Aeson (FromJSON)
import qualified Data.Aeson as Aeson
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import qualified Data.ByteString.Lazy as LazyByteString
import Data.Coerce (coerce)
import Data.Either (isRight)
import Data.Foldable (for_)
import Data.Maybe (isNothing, isJust)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import GHC.Stack (HasCallStack)
import qualified PublicKeySpec
import qualified System.Directory as Directory
import System.FilePath ((</>))
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)
import qualified Test.Hspec as Hspec
import Test.QuickCheck.Arbitrary (Arbitrary (arbitrary))
import Test.QuickCheck.Gen (elements, listOf, oneof)
import Test.QuickCheck.Instances.Text ()
import Test.QuickCheck.Property (property, total, (===), (==>))

-- Load all files in the given directory, and ensure that all of them can be
-- decoded. The caller can pass in a function to run further checks on the
-- decoded value, but this is mainly there to ensure that `a` occurs after the
-- fat arrow.
canDecodeAll :: forall a. (FromJSON a, HasCallStack) => FilePath -> (a -> IO ()) -> Spec
canDecodeAll path inspect = do
  files <- Hspec.runIO $ Directory.listDirectory path
  for_ files $ \fname ->
    it ("can decode " <> (path </> fname)) $ do
      bytes <- ByteString.readFile $ path </> fname
      case Aeson.eitherDecode' $ LazyByteString.fromStrict bytes of
        Left err -> fail err
        Right value -> inspect value

ignoreDecodedValue :: a -> IO ()
ignoreDecodedValue _ = pure ()

instance Arbitrary Fido2.AuthenticatorAttestationResponse where
  arbitrary = Fido2.AuthenticatorAttestationResponse <$> arbitrary <*> arbitrary

instance Arbitrary Fido2.ClientData where
  arbitrary =
    Fido2.ClientData
      <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> pure undefined -- TODO: How to generate sha256?

instance Arbitrary Fido2.AttestationObject where
  arbitrary = Fido2.AttestationObject <$> arbitrary <*> pure "none" <*> pure []

instance Arbitrary Fido2.AuthenticatorData where
  arbitrary =
    Fido2.AuthenticatorData undefined <$> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> arbitrary
      <*> arbitrary

instance Arbitrary Fido2AttestationError.Error where
  arbitrary =
    elements
      [ Fido2.InvalidWebauthnType,
        Fido2.ChallengeDidNotMatch,
        Fido2AttestationError.RpIdMismatch,
        Fido2AttestationError.UserNotPresent,
        Fido2AttestationError.UserNotVerified,
        Fido2.UnsupportedAttestationFormat,
        Fido2.InvalidAttestationStatement,
        Fido2.NoAttestedCredentialDataFound,
        Fido2.NotTrustworthy
      ]

instance Arbitrary Fido2.CredentialId where
  arbitrary = coerce (arbitrary @ByteString)

instance Arbitrary Fido2.RpId where
  arbitrary = coerce (arbitrary @Text)

instance Arbitrary Fido2.UserVerificationRequirement where
  arbitrary = elements [Fido2.UserVerificationDiscouraged, Fido2.UserVerificationPreferred, Fido2.UserVerificationRequired]

instance Arbitrary Fido2.AttestedCredentialData where
  arbitrary = Fido2.AttestedCredentialData <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary Fido2.WebauthnType where
  arbitrary = elements [Fido2.Get, Fido2.Create]

instance Arbitrary Fido2.Challenge where
  arbitrary = coerce (arbitrary @ByteString)

instance Arbitrary Fido2.Origin where
  arbitrary = coerce (arbitrary @Text)

newtype RandomAttStmt = RandomAttStmt [(Term, Term)] deriving (Show)

instance Arbitrary RandomAttStmt where
  arbitrary = RandomAttStmt <$> listOf ((,) <$> (TInt <$> arbitrary) <*> (TInt <$> arbitrary))

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
  describe "PublicKey" PublicKeySpec.spec
  describe "Attestation" $ do
    it "fails if type is wrong" $
      property $
        \(resp', clientData) ->
          let resp =
                (resp' :: Fido2.AuthenticatorAttestationResponse)
                  { Fido2.clientData = clientData {Fido2.typ = Fido2.Get}
                  }
           in case Fido2.verifyAttestationResponse undefined undefined undefined undefined resp of
                Left x -> x === Fido2.InvalidWebauthnType
    it "fails if challenges do not match" $
      property $
        \( coerce @ByteString -> c1,
           coerce @ByteString -> c2,
           clientData,
           origin,
           rp,
           req,
           resp'
           ) ->
            -- TODO: Do not expose Challenge; but use its MonadRandom instance ... ?
            c1 /= c2
              ==> let resp =
                        (resp' :: Fido2.AuthenticatorAttestationResponse)
                          { Fido2.clientData = clientData {Fido2.typ = Fido2.Create, Fido2.challenge = c1}
                          }
                   in case Fido2.verifyAttestationResponse origin rp c2 req resp of
                        Left x -> x === Fido2.ChallengeDidNotMatch
    it "fails if origins do not match" $
      property $
        \( c1 :: ByteString,
           coerce @Text -> origin1,
           coerce @Text -> origin2,
           resp' :: Fido2.AuthenticatorAttestationResponse,
           clientData :: Fido2.ClientData,
           rp,
           req
           ) ->
            origin1 /= origin2
              ==> let resp =
                        (resp' :: Fido2.AuthenticatorAttestationResponse)
                          { Fido2.clientData =
                              clientData
                                { Fido2.typ = Fido2.Create,
                                  Fido2.challenge = coerce c1,
                                  Fido2.origin = origin1
                                }
                          }
                   in case Fido2.verifyAttestationResponse origin2 rp (coerce c1) req resp of
                        Left x -> x === Fido2.OriginDidNotMatch
    it "fails if rpIds do not match" $
      property $
        \( coerce @Text -> rp1,
           coerce @Text -> rp2,
           coerce @ByteString -> challenge,
           coerce @Text -> origin,
           resp',
           clientData,
           attestationObject,
           authData
           ) ->
            rp1 /= rp2
              ==> let resp =
                        (resp' :: Fido2.AuthenticatorAttestationResponse)
                          { Fido2.clientData =
                              clientData
                                { Fido2.typ = Fido2.Create,
                                  Fido2.challenge = challenge,
                                  Fido2.origin = origin
                                },
                            Fido2.attestationObject =
                              attestationObject
                                { Fido2.authData =
                                    authData
                                      { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp2))
                                      }
                                }
                          }
                   in case Fido2.verifyAttestationResponse origin rp1 challenge undefined resp of
                        Left x -> x === Fido2AttestationError.RpIdMismatch
    it "fails if user not present" $
      property $
        \( coerce @Text -> rp,
           coerce @ByteString -> challenge,
           coerce @Text -> origin,
           resp',
           clientData,
           attestationObject,
           authData
           ) ->
            let resp =
                  (resp' :: Fido2.AuthenticatorAttestationResponse)
                    { Fido2.clientData =
                        clientData
                          { Fido2.typ = Fido2.Create,
                            Fido2.challenge = challenge,
                            Fido2.origin = origin
                          },
                      Fido2.attestationObject =
                        attestationObject
                          { Fido2.authData =
                              authData
                                { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp)),
                                  Fido2.userPresent = False
                                }
                          }
                    }
             in case Fido2.verifyAttestationResponse origin rp challenge undefined resp of
                  Left x -> x === Fido2AttestationError.UserNotPresent
    it "fails if userverification requirement doesnt match" $
      property $
        \( coerce @Text -> rp,
           coerce @ByteString -> challenge,
           coerce @Text -> origin,
           resp',
           clientData,
           attestationObject,
           authData
           ) ->
            let resp =
                  (resp' :: Fido2.AuthenticatorAttestationResponse)
                    { Fido2.clientData =
                        clientData
                          { Fido2.typ = Fido2.Create,
                            Fido2.challenge = challenge,
                            Fido2.origin = origin
                          },
                      Fido2.attestationObject =
                        attestationObject
                          { Fido2.authData =
                              authData
                                { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp)),
                                  Fido2.userPresent = True,
                                  Fido2.userVerified = False
                                }
                          }
                    }
             in case Fido2.verifyAttestationResponse origin rp challenge Fido2.UserVerificationRequired resp of
                  Left x -> x === Fido2AttestationError.UserNotVerified
    it "fails if no attested credential data" $
      property $
        \( coerce @Text -> rp,
           coerce @ByteString -> challenge,
           coerce @Text -> origin,
           resp',
           clientData,
           attestationObject,
           authData
           ) ->
            let resp =
                  (resp' :: Fido2.AuthenticatorAttestationResponse)
                    { Fido2.clientData =
                        clientData
                          { Fido2.typ = Fido2.Create,
                            Fido2.challenge = challenge,
                            Fido2.origin = origin
                          },
                      Fido2.attestationObject =
                        attestationObject
                          { Fido2.authData =
                              authData
                                { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp)),
                                  Fido2.userPresent = True,
                                  Fido2.attestedCredentialData = Nothing
                                }
                          }
                    }
             in case Fido2.verifyAttestationResponse origin rp challenge Fido2.UserVerificationPreferred resp of
                  Left x -> x === Fido2AttestationError.NoAttestedCredentialDataFound
    it "fails on unsupported attestation format" $
      property $
        \( coerce @Text -> rp,
           coerce @ByteString -> challenge,
           coerce @Text -> origin,
           resp',
           clientData,
           attestationObject,
           authData
           ) ->
            let resp =
                  (resp' :: Fido2.AuthenticatorAttestationResponse)
                    { Fido2.clientData =
                        clientData
                          { Fido2.typ = Fido2.Create,
                            Fido2.challenge = challenge,
                            Fido2.origin = origin
                          },
                      Fido2.attestationObject =
                        attestationObject
                          { Fido2.authData =
                              authData
                                { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp)),
                                  Fido2.userPresent = True,
                                  Fido2.attestedCredentialData = Nothing
                                },
                            Fido2.fmt = "unsupported"
                          }
                    }
             in case Fido2.verifyAttestationResponse origin rp challenge Fido2.UserVerificationPreferred resp of
                  Left x -> x === Fido2AttestationError.UnsupportedAttestationFormat
    it "fails on non-empty attStmt for none format" $
      property $
        \( coerce @Text -> rp,
           coerce @ByteString -> challenge,
           coerce @Text -> origin,
           resp',
           clientData,
           attestationObject,
           authData,
           coerce @RandomAttStmt -> attStmt,
           attData
           ) ->
            not (null attStmt) && isJust attData
              ==> let resp =
                        (resp' :: Fido2.AuthenticatorAttestationResponse)
                          { Fido2.clientData =
                              clientData
                                { Fido2.typ = Fido2.Create,
                                  Fido2.challenge = challenge,
                                  Fido2.origin = origin
                                },
                            Fido2.attestationObject =
                              attestationObject
                                { Fido2.authData =
                                    authData
                                      { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp)),
                                        Fido2.userPresent = True,
                                        Fido2.attestedCredentialData = attData
                                      },
                                  Fido2.fmt = "none",
                                  Fido2.attStmt = attStmt
                                }
                          }
                   in case Fido2.verifyAttestationResponse origin rp challenge Fido2.UserVerificationPreferred resp of
                        Left x -> x === Fido2AttestationError.InvalidAttestationStatement
    -- Kinda lame. We know that show is total as it's derived
    it "Can show Error" $ property $ \(err :: Fido2AttestationError.Error) -> total . show $ err
  describe "RegisterAndLogin" $
    it "tests whether the fixed register and login responses are matching" $
      do
        Fido2.PublicKeyCredential {response} <-
          decodeFile
            @(Fido2.PublicKeyCredential Fido2.AuthenticatorAttestationResponse)
            "tests/fixtures/register-complete/01.json"
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
        loginReq <-
          decodeFile
            @(Fido2.PublicKeyCredential Fido2.AuthenticatorAssertionResponse)
            "tests/fixtures/login-complete/01.json"
        let Fido2.PublicKeyCredential {response} = loginReq
        let Fido2.AuthenticatorAssertionResponse {clientData} = response
        let Fido2.ClientData {challenge} = clientData
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
