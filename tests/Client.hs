{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

-- | This modules provdes a way to emulate certain client behaviour for testing purposes. It DOES NOT implement the webauthn specification for two reasons:
-- 1. There is no need for it in our tests.
-- 2. It is much more convenient to implement both the client and authenticator in a single function, removing their communication.
module Client (clientAttestation, spec, clientAssertion) where

import qualified Client.PrivateKey as PrivateKey
import qualified Codec.CBOR.Write as CBOR
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import Crypto.Fido2.Model.JavaScript.Decoding
  ( decodeCreatedPublicKeyCredential,
    decodePublicKeyCredentialCreationOptions,
    decodePublicKeyCredentialRequestOptions,
    decodeRequestedPublicKeyCredential,
  )
import Crypto.Fido2.Model.JavaScript.Encoding
  ( encodeCreatedPublicKeyCredential,
    encodePublicKeyCredentialCreationOptions,
    encodePublicKeyCredentialRequestOptions,
    encodeRequestedPublicKeyCredential,
  )
import qualified Crypto.Fido2.Model.JavaScript.Types as JS
import Crypto.Fido2.Operations.Attestation (allSupportedFormats)
import qualified Crypto.Fido2.Operations.Attestation as Fido2
import qualified Crypto.Fido2.Operations.Attestation.None as None
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (Digest, SHA256, hash, hashlazy)
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import Crypto.Random (MonadRandom)
import qualified Crypto.Random as Random
import Data.Aeson (encode)
import Data.Binary.Put (runPut)
import qualified Data.Binary.Put as Put
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as Base64
import Data.ByteString.Lazy (toStrict)
import Data.Either (fromRight, isRight)
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Validation (toEither)
import Debug.Trace (trace, traceShowId)
import System.Random.Stateful (globalStdGen, uniformM)
import Test.Hspec (SpecWith, describe, it, shouldSatisfy)

-- | A stored credential.
-- TODO: Store the corresponding userId
data AuthenticatorCredential = AuthenticatorCredential
  { acCounter :: M.SignatureCounter,
    acId :: M.CredentialId,
    acPrivateKey :: PrivateKey.PrivateKey,
    acPublicKey :: PublicKey.PublicKey
  }
  deriving (Show)

-- | The datatype holding all information needed for attestation and assertion
data Authenticator = AuthenticatorNone
  { credentials :: [AuthenticatorCredential],
    supportedAlgorithms :: Set.Set PublicKey.COSEAlgorithmIdentifier,
    -- | If this credentialId is Just, it will be used as the next credentialId. If None, a random bytestring is generated instead.
    suggestedCredentialId :: Maybe BS.ByteString,
    -- | If True, an invalid signature is created during assertion.
    createFalseSignature :: Bool
  }
  deriving (Show)

-- | Emulates the client-side operation for attestation given an authenticator. MonadRandom is required during the geneation of the new credentials.
clientAttestation :: MonadRandom m => JS.PublicKeyCredentialCreationOptions -> Authenticator -> m (JS.CreatedPublicKeyCredential, Authenticator)
clientAttestation options authenticator@AuthenticatorNone {..} = do
  let M.PublicKeyCredentialCreationOptions {M.pkcocChallenge, M.pkcocRp, M.pkcocPubKeyCredParams} =
        fromRight (error "Test: could not decode creation options") $ decodePublicKeyCredentialCreationOptions options
      -- We have to encode the ClientData here because we need access to the ByteString representation to create the attestation response
      clientDataBS =
        encode
          JS.ClientDataJSON
            { JS.typ = "webauthn.create",
              JS.challenge = decodeUtf8 . Base64.encode $ M.unChallenge pkcocChallenge,
              JS.origin = "https://localhost:8080/",
              JS.crossOrigin = Nothing
            }
      rpIdHash = hash . encodeUtf8 . M.unRpId . fromMaybe (M.RpId "localhost") $ M.pkcreId pkcocRp
      credentialId = M.CredentialId "This is the credential"
      requestedAlgorithms = Set.fromList $ map M.pkcpAlg pkcocPubKeyCredParams
      acceptableAlgorithms = Set.intersection supportedAlgorithms requestedAlgorithms
      chosenAlgorithm = fromMaybe (error "No supported algoritms were accepted by the creation options") $ Set.lookupMin acceptableAlgorithms
  cred <- newCredential suggestedCredentialId chosenAlgorithm
  let response =
        encodeCreatedPublicKeyCredential
          M.PublicKeyCredential
            { M.pkcIdentifier = credentialId,
              M.pkcResponse =
                M.AuthenticatorAttestationResponse
                  { M.arcClientData =
                      M.CollectedClientData
                        { M.ccdChallenge = pkcocChallenge,
                          M.ccdOrigin = M.Origin "https://localhost:8080",
                          M.ccdCrossOrigin = Just True,
                          M.ccdHash = M.ClientDataHash $ hashlazy clientDataBS
                        },
                    M.arcAttestationObject =
                      M.AttestationObject
                        { M.aoAuthData = createAuthenticatorData rpIdHash cred credentialId,
                          M.aoFmt = None.Format,
                          M.aoAttStmt = ()
                        },
                    M.arcTransports = Set.fromList [M.AuthenticatorTransportUSB, M.AuthenticatorTransportBLE, M.AuthenticatorTransportNFC, M.AuthenticatorTransportInternal]
                  },
              M.pkcClientExtensionResults = M.AuthenticationExtensionsClientOutputs {}
            }
  pure (response, authenticator {credentials = cred : credentials})
  where
    createAuthenticatorData :: Digest SHA256 -> AuthenticatorCredential -> M.CredentialId -> M.AuthenticatorData 'M.Create
    createAuthenticatorData rpIdHash cred credentialId =
      M.AuthenticatorData
        { M.adRpIdHash = M.RpIdHash rpIdHash,
          M.adFlags =
            M.AuthenticatorDataFlags
              { adfUserPresent = True,
                adfUserVerified = True
              },
          M.adSignCount = acCounter cred,
          M.adAttestedCredentialData = attestedCredentialData,
          M.adExtensions = Nothing,
          M.adRawData =
            -- TODO: Use Put?
            BA.convert rpIdHash
              <> BS.singleton 0b01000101
              <> (toStrict . runPut $ Put.putWord32be . M.unSignatureCounter $ acCounter cred)
              <> encodeAttestedCredentialData attestedCredentialData
        }
      where
        attestedCredentialData =
          M.AttestedCredentialData
            { M.acdAaguid = M.AAGUID "0000000000000000",
              M.acdCredentialId = credentialId,
              M.acdCredentialPublicKey = acPublicKey cred, -- This is selfsigned
              M.acdCredentialPublicKeyBytes = M.PublicKeyBytes . CBOR.toStrictByteString . PublicKey.encodePublicKey $ acPublicKey cred
            }

        -- https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
        encodeAttestedCredentialData :: M.AttestedCredentialData 'M.Create -> BS.ByteString
        encodeAttestedCredentialData M.AttestedCredentialData {..} =
          M.unAAGUID acdAaguid
            <> (toStrict . runPut . Put.putWord16be . fromIntegral . BS.length $ M.unCredentialId acdCredentialId)
            <> M.unCredentialId credentialId
            <> M.unPublicKeyBytes acdCredentialPublicKeyBytes

-- | Performs assertion as per the client specification provided an
-- authenticator. MonadRandom is required for signing using Ed25519 which
-- requires a random number to be generated during signing. There exists
-- methods to not rely on a random number, but these have not been implemented
-- in the cryptonite library we rely on.
clientAssertion :: MonadRandom m => JS.PublicKeyCredentialRequestOptions -> Authenticator -> m JS.RequestedPublicKeyCredential
clientAssertion options AuthenticatorNone {credentials = (cred : _), ..} = do
  let Right M.PublicKeyCredentialRequestOptions {..} = decodePublicKeyCredentialRequestOptions options
      clientDataBS =
        encode
          JS.ClientDataJSON
            { JS.typ = "webauthn.get",
              JS.challenge = decodeUtf8 . Base64.encode $ M.unChallenge pkcogChallenge,
              JS.origin = "https://localhost:8080/",
              JS.crossOrigin = Nothing
            }
      rpIdHash = hash . encodeUtf8 . M.unRpId $ fromMaybe (M.RpId "localhost") pkcogRpId
      credentialId = M.CredentialId "This is the credential"
      authenticatorData = createAuthenticatorData rpIdHash cred
  signature <-
    if createFalseSignature
      then -- Simply hash a random ByteString to get the invalid signature
        BA.convert . (hash :: BS.ByteString -> Digest SHA256) <$> Random.getRandomBytes 16
      else
        PrivateKey.toByteString
          <$> PrivateKey.sign (acPublicKey cred) (acPrivateKey cred) (M.adRawData authenticatorData <> BA.convert (hashlazy clientDataBS :: Digest SHA256))

  pure $
    encodeRequestedPublicKeyCredential $
      traceShowId
        M.PublicKeyCredential
          { M.pkcIdentifier = credentialId,
            M.pkcResponse =
              M.AuthenticatorAssertionResponse
                { M.argClientData =
                    M.CollectedClientData
                      { M.ccdChallenge = pkcogChallenge,
                        M.ccdOrigin = M.Origin "https://localhost:8080",
                        M.ccdCrossOrigin = Just True,
                        M.ccdHash = M.ClientDataHash $ hashlazy clientDataBS
                      },
                  M.argAuthenticatorData = authenticatorData,
                  M.argSignature = M.AssertionSignature signature,
                  M.argUserHandle = Nothing
                },
            M.pkcClientExtensionResults = M.AuthenticationExtensionsClientOutputs {}
          }
  where
    createAuthenticatorData :: Digest SHA256 -> AuthenticatorCredential -> M.AuthenticatorData 'M.Get
    createAuthenticatorData rpIdHash cred =
      M.AuthenticatorData
        { M.adRpIdHash = M.RpIdHash rpIdHash,
          M.adFlags =
            M.AuthenticatorDataFlags
              { adfUserPresent = True,
                adfUserVerified = True
              },
          M.adSignCount = acCounter cred,
          M.adAttestedCredentialData = M.NoAttestedCredentialData,
          M.adExtensions = Nothing,
          M.adRawData =
            -- TODO: Use Put?
            BA.convert rpIdHash
              <> BS.singleton 0b00000101
              <> (toStrict . runPut $ Put.putWord32be . M.unSignatureCounter $ acCounter cred)
        }
clientAssertion _ _ = error "Should not happen"

-- | Creates a new credential based on the provided COSEAlgorithm. MondRandom is required to generate the random keys.
newCredential :: MonadRandom m => Maybe BS.ByteString -> PublicKey.COSEAlgorithmIdentifier -> m AuthenticatorCredential
newCredential credId PublicKey.COSEAlgorithmIdentifierES256 = newECDSACredential credId PublicKey.COSEAlgorithmIdentifierES256
newCredential credId PublicKey.COSEAlgorithmIdentifierES384 = newECDSACredential credId PublicKey.COSEAlgorithmIdentifierES384
newCredential credId PublicKey.COSEAlgorithmIdentifierES512 = newECDSACredential credId PublicKey.COSEAlgorithmIdentifierES512
newCredential credId PublicKey.COSEAlgorithmIdentifierEdDSA = do
  secret <- Ed25519.generateSecretKey
  let public = Ed25519.toPublic secret
  -- Generate a random Id if the provided credId is None, use it otherwise
  acId <- M.CredentialId <$> maybe (Random.getRandomBytes 16) pure credId
  pure $
    AuthenticatorCredential
      { acCounter = M.SignatureCounter 0,
        acId = acId,
        acPrivateKey = PrivateKey.Ed25519PrivateKey secret,
        acPublicKey = PublicKey.Ed25519PublicKey public
      }

newECDSACredential :: MonadRandom m => Maybe BS.ByteString -> PublicKey.COSEAlgorithmIdentifier -> m AuthenticatorCredential
newECDSACredential credId ident = do
  let curve = ECC.getCurveByName $ PublicKey.toCurveName ident
  (public, private) <- ECC.generate curve
  -- Generate a random Id if the provided credId is None, use it otherwise
  acId <- M.CredentialId <$> maybe (Random.getRandomBytes 16) pure credId
  pure $
    AuthenticatorCredential
      { acCounter = M.SignatureCounter 0,
        acId = acId,
        acPrivateKey = fromMaybe (error "Not a ECDSAKey") $ PrivateKey.toECDSAKey ident private,
        acPublicKey = fromMaybe (error "Not a ECDSAKey") $ PublicKey.toECDSAKey ident public
      }

spec :: SpecWith ()
spec = describe "None" $
  it "succeeds" $ do
    -- Generate new random input
    challenge <- uniformM globalStdGen
    userId <- uniformM globalStdGen
    -- Create dummy user
    let user =
          M.PublicKeyCredentialUserEntity
            { M.pkcueId = userId,
              M.pkcueDisplayName = M.UserAccountDisplayName "John Doe",
              M.pkcueName = M.UserAccountName "john-doe"
            }
    let options = defaultPkcco user challenge
    let noneAuthenticator =
          traceShowId
            AuthenticatorNone
              { credentials = [],
                supportedAlgorithms = Set.singleton PublicKey.COSEAlgorithmIdentifierES256,
                suggestedCredentialId = Nothing,
                createFalseSignature = True
              }
    -- Perform client Attestation emulation with a fresh authenticator
    (jsPkcCreate, authenticator) <- clientAttestation (encodePublicKeyCredentialCreationOptions options) noneAuthenticator
    let mPkcCreate = decodeCreatedPublicKeyCredential allSupportedFormats jsPkcCreate
    mPkcCreate `shouldSatisfy` isRight
    -- Verify the result
    let registerResult =
          toEither $
            Fido2.verifyAttestationResponse
              (M.Origin "https://localhost:8080")
              (M.RpIdHash $ hash ("localhost" :: BS.ByteString))
              options
              (fromRight (error "should not happend") mPkcCreate)
    registerResult `shouldSatisfy` isRight
    let options = defaultPkcro challenge
    -- Perform client assertion emulation with the same authenticator, this
    -- authenticator should now store the created credential
    jsPkcGet <- clientAssertion (encodePublicKeyCredentialRequestOptions options) (traceShowId authenticator)
    let mPkcGet = decodeRequestedPublicKeyCredential jsPkcGet
    mPkcGet `shouldSatisfy` isRight

-- | Create a default set of options for attestation. These options can be modified before using them in the tests
defaultPkcco :: M.PublicKeyCredentialUserEntity -> M.Challenge -> M.PublicKeyCredentialOptions 'M.Create
defaultPkcco userEntity challenge =
  M.PublicKeyCredentialCreationOptions
    { M.pkcocRp = M.PublicKeyCredentialRpEntity {M.pkcreId = Nothing, M.pkcreName = "ACME"},
      M.pkcocUser = userEntity,
      M.pkcocChallenge = challenge,
      -- Empty credentialparameters are not supported.
      M.pkcocPubKeyCredParams =
        [ M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = PublicKey.COSEAlgorithmIdentifierES256
            },
          M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = PublicKey.COSEAlgorithmIdentifierEdDSA
            }
        ],
      M.pkcocTimeout = Nothing,
      M.pkcocExcludeCredentials = [],
      M.pkcocAuthenticatorSelection =
        Just
          M.AuthenticatorSelectionCriteria
            { M.ascAuthenticatorAttachment = Nothing,
              M.ascResidentKey = M.ResidentKeyRequirementDiscouraged,
              M.ascUserVerification = M.UserVerificationRequirementPreferred
            },
      M.pkcocAttestation = M.AttestationConveyancePreferenceDirect,
      M.pkcocExtensions = Nothing
    }

-- | Create a default set of options for assertion. These options can be modified before using them in the tests
defaultPkcro :: M.Challenge -> M.PublicKeyCredentialOptions 'M.Get
defaultPkcro challenge =
  M.PublicKeyCredentialRequestOptions
    { M.pkcogChallenge = challenge,
      M.pkcogTimeout = Nothing,
      M.pkcogRpId = Just "localhost",
      M.pkcogAllowCredentials = [],
      M.pkcogUserVerification = M.UserVerificationRequirementPreferred,
      M.pkcogExtensions = Nothing
    }
