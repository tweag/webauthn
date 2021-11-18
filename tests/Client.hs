{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

-- | This modules provdes a way to emulate certain client behaviour for testing
-- purposes. It DOES NOT implement the webauthn specification for two reasons:
-- 1. There is no need for it in our tests.
-- 2. It is much more convenient to implement both the client and authenticator
-- in a single function, removing their communication.
module Client (clientAssertion, spec) where

import Authenticator
  ( Authenticator (AuthenticatorNone, aAAGUID, aCredentials, aSignatureCounter, aSupportedAlgorithms),
    AuthenticatorSignatureCounter (Global),
    authenticatorGetAssertion,
    authenticatorMakeCredential,
  )
import qualified Client.PrivateKey as PrivateKey
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import Crypto.Fido2.Model.JavaScript.Decoding
  ( decodeCreateCollectedClientData,
    decodeCreatedPublicKeyCredential,
    decodeGetCollectedClientData,
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
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (hash)
import Crypto.Random (MonadRandom)
import Data.Aeson (encode)
import qualified Data.ByteString.Base64.URL as Base64
import Data.ByteString.Lazy (toStrict)
import Data.Either (fromRight, isRight)
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Validation (toEither)
import Debug.Trace (traceShowId)
import System.Random.Stateful (globalStdGen, uniformM)
import Test.Hspec (SpecWith, describe, it, shouldSatisfy)

--- The RpId is derivable from the Origin, but we don't implement that.
-- See: https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain
data AnnotatedOrigin = AnnotatedOrigin
  { aoRpId :: M.RpId,
    aoOrigin :: M.Origin
  }

-- | Emulates the client-side operation for attestation given an authenticator.
-- MonadRandom is required during the geneation of the new credentials.
clientAttestation :: (MonadRandom m, MonadFail m) => JS.PublicKeyCredentialCreationOptions -> AnnotatedOrigin -> Authenticator -> m (JS.CreatedPublicKeyCredential, Authenticator)
clientAttestation options AnnotatedOrigin {..} authenticator = do
  let M.PublicKeyCredentialCreationOptions {..} =
        fromRight (error "Test: could not decode creation options") $ decodePublicKeyCredentialCreationOptions options
      -- We would ideally construct the M.CollectedClientData first, but this
      -- is impossible since we need the hash. As a workaround we construct
      -- the encoded version first by manually encoding the intermediate JSON
      -- representation, allowing us to construct the hash and the
      -- CollectedClientData from that.
      clientDataAB =
        JS.URLEncodedBase64 . toStrict $
          encode
            JS.ClientDataJSON
              { JS.typ = "webauthn.create",
                JS.challenge = decodeUtf8 . Base64.encode $ M.unChallenge pkcocChallenge,
                JS.origin = M.unOrigin aoOrigin,
                JS.crossOrigin = Nothing
              }
      clientDataHash = M.ClientDataHash . hash $ JS.unUrlEncodedBase64 clientDataAB
      clientData = fromRight (error "Test: could not decode encoded clientData") $ traceShowId $ decodeCreateCollectedClientData clientDataAB
  (attestationObject, authenticator') <-
    authenticatorMakeCredential
      authenticator
      clientDataHash
      -- Ensure the RpId is set by defaulting to the Client configured default if Nothing
      (pkcocRp {M.pkcreId = Just . fromMaybe aoRpId $ M.pkcreId pkcocRp})
      pkcocUser
      True
      True
      True
      pkcocPubKeyCredParams
      pkcocExcludeCredentials
      False
      pkcocExtensions
  let response =
        encodeCreatedPublicKeyCredential
          M.PublicKeyCredential
            { M.pkcIdentifier = M.acdCredentialId . M.adAttestedCredentialData $ M.aoAuthData attestationObject,
              M.pkcResponse =
                M.AuthenticatorAttestationResponse
                  { M.arcClientData = clientData,
                    M.arcAttestationObject = attestationObject,
                    M.arcTransports = Set.fromList [M.AuthenticatorTransportUSB, M.AuthenticatorTransportBLE, M.AuthenticatorTransportNFC, M.AuthenticatorTransportInternal]
                  },
              M.pkcClientExtensionResults = M.AuthenticationExtensionsClientOutputs {}
            }
  pure (response, authenticator')

-- | Performs assertion as per the client specification provided an
-- authenticator. MonadRandom is required for signing using Ed25519 which
-- requires a random number to be generated during signing. There exists
-- methods to not rely on a random number, but these have not been implemented
-- in the cryptonite library we rely on.
clientAssertion :: (MonadFail m, MonadRandom m) => JS.PublicKeyCredentialRequestOptions -> AnnotatedOrigin -> Authenticator -> m (JS.RequestedPublicKeyCredential, Authenticator)
clientAssertion options AnnotatedOrigin {..} authenticator = do
  let Right M.PublicKeyCredentialRequestOptions {..} = decodePublicKeyCredentialRequestOptions options
      allowCredentialDescriptorList = case pkcogAllowCredentials of
        [] -> Nothing
        xs -> Just xs
      -- We would ideally construct the M.CollectedClientData first, but this
      -- is impossible since we need the hash. As a workaround we construct
      -- the encoded version first by manually encoding the intermediate JSON
      -- representation, allowing us to construct the hash and the
      -- CollectedClientData from that.
      clientDataAB =
        JS.URLEncodedBase64 . toStrict $
          encode
            JS.ClientDataJSON
              { JS.typ = "webauthn.get",
                JS.challenge = decodeUtf8 . Base64.encode $ M.unChallenge pkcogChallenge,
                JS.origin = M.unOrigin aoOrigin,
                JS.crossOrigin = Nothing
              }
      clientDataHash = M.ClientDataHash . hash $ JS.unUrlEncodedBase64 clientDataAB
      clientData = fromRight (error "Test: could not decode encoded clientData") $ decodeGetCollectedClientData clientDataAB
  ((credentialId, authenticatorData, signature, userHandle), authenticator') <-
    authenticatorGetAssertion
      authenticator
      -- Ensure the RpId is set by defaulting to the Client configured default if Nothing
      (fromMaybe aoRpId pkcogRpId)
      clientDataHash
      allowCredentialDescriptorList
      True
      True
      pkcogExtensions
  let response =
        encodeRequestedPublicKeyCredential
          M.PublicKeyCredential
            { M.pkcIdentifier = credentialId,
              M.pkcResponse =
                M.AuthenticatorAssertionResponse
                  { M.argClientData = clientData,
                    M.argAuthenticatorData = authenticatorData,
                    M.argSignature = M.AssertionSignature $ PrivateKey.toByteString signature,
                    M.argUserHandle = userHandle
                  },
              M.pkcClientExtensionResults = M.AuthenticationExtensionsClientOutputs {}
            }
  pure (response, authenticator')

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
          AuthenticatorNone
            { aCredentials = Map.empty,
              aSupportedAlgorithms = Set.singleton PublicKey.COSEAlgorithmIdentifierEdDSA,
              aAAGUID = M.AAGUID "0000000000000000",
              aSignatureCounter = Global 0
            }
    let client =
          AnnotatedOrigin
            { aoRpId = M.RpId "localhost",
              aoOrigin = M.Origin "https://localhost:8080"
            }
    -- Perform client Attestation emulation with a fresh authenticator
    (jsPkcCreate, authenticator) <- clientAttestation (encodePublicKeyCredentialCreationOptions options) client noneAuthenticator
    let mPkcCreate = decodeCreatedPublicKeyCredential allSupportedFormats jsPkcCreate
    mPkcCreate `shouldSatisfy` isRight
    -- Verify the result
    let registerResult =
          toEither $
            Fido2.verifyAttestationResponse
              (aoOrigin client)
              (M.RpIdHash . hash . encodeUtf8 . M.unRpId $ aoRpId client)
              options
              (fromRight (error "should not happend") mPkcCreate)
    registerResult `shouldSatisfy` isRight
    let options = defaultPkcro challenge
    -- Perform client assertion emulation with the same authenticator, this
    -- authenticator should now store the created credential
    (jsPkcGet, _) <- clientAssertion (encodePublicKeyCredentialRequestOptions options) client authenticator
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
      -- We currently only support Client
      M.pkcogAllowCredentials = [],
      M.pkcogUserVerification = M.UserVerificationRequirementPreferred,
      M.pkcogExtensions = Nothing
    }
