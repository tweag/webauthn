{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

-- | This modules provdes a way to emulate certain client behaviour for testing
-- purposes. It DOES NOT implement the webauthn specification because there is
-- no need for it in our tests.
module Emulation.Client (clientAssertion, spec) where

import Control.Monad.Except (ExceptT (ExceptT), MonadError, MonadTrans (lift), runExceptT, throwError)
import Crypto.Fido2.Model (Challenge (Challenge))
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.Binary.Encoding as ME
import qualified Crypto.Fido2.Operations.Assertion as Fido2
import qualified Crypto.Fido2.Operations.Attestation as Fido2
import qualified Crypto.Fido2.Operations.Common as Fido2
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (hash)
import Crypto.Random (getRandomBytes)
import qualified Crypto.Random as Random
import qualified Data.List.NonEmpty as NE
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Text.Encoding (encodeUtf8)
import Data.Validation (toEither)
import Emulation.Authenticator
  ( Authenticator (AuthenticatorNone, aAuthenticatorDataFlags, aConformance, aSignatureCounter),
    AuthenticatorNonConformingBehaviour (RandomPrivateKey, RandomSignatureData, StaticCounter),
    AuthenticatorSignatureCounter (Unsupported),
    authenticatorGetAssertion,
    authenticatorMakeCredential,
  )
import Emulation.Authenticator.Arbitrary ()
import qualified Emulation.Client.PrivateKey as PrivateKey
import Test.Hspec (SpecWith, describe, it, shouldSatisfy)
import Test.QuickCheck (property)

-- | The annotated Origin is the origin with the derived (or provided) rpID. It
-- is a workaround for the fact that we do not derive the rpID from the origin.
-- See: https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain
data AnnotatedOrigin = AnnotatedOrigin
  { aoRpId :: M.RpId,
    aoOrigin :: M.Origin
  }

-- | Potential ways the UserAgent could not conform to the specification
data UserAgentNonConformingBehaviour
  = RandomChallenge
  deriving (Eq, Ord)

-- | The ways in which the UserAgent should not conform to the spec
type UserAgentConformance = Set.Set UserAgentNonConformingBehaviour

-- | Custom type to combine the MonadPseudoRandom with the Except monad. We
-- force the ChaChaDRG to ensure the App type is completely pure, and
-- evaluating the monad has no side effects.
newtype App a = App (ExceptT String (Random.MonadPseudoRandom Random.ChaChaDRG) a)
  deriving newtype (Functor, Applicative, Monad, MonadError String)

instance MonadFail App where
  fail = throwError

instance Random.MonadRandom App where
  getRandomBytes n = App $ lift $ getRandomBytes n

runApp :: Integer -> App a -> Either String a
runApp seed (App except) =
  let rng = Random.drgNewSeed $ Random.seedFromInteger seed
   in fst $ Random.withDRG rng $ runExceptT except

-- | Emulates the client-side operation for attestation given an authenticator.
-- MonadRandom is required during the generation of the new credentials, and
-- some non-conforming behaviour. MonadFail is used to fail when an error occurred
clientAttestation ::
  (Random.MonadRandom m, MonadFail m) =>
  M.PublicKeyCredentialOptions 'M.Create ->
  AnnotatedOrigin ->
  UserAgentConformance ->
  Authenticator ->
  m (M.PublicKeyCredential 'M.Create 'True, Authenticator)
clientAttestation M.PublicKeyCredentialCreationOptions {..} AnnotatedOrigin {..} conformance authenticator = do
  challenge <-
    if Set.member RandomChallenge conformance
      then Challenge <$> Random.getRandomBytes 16
      else pure pkcocChallenge
  let clientData =
        ME.encodeRawCollectedClientData
          M.CollectedClientData
            { ccdChallenge = challenge,
              ccdOrigin = aoOrigin,
              ccdCrossOrigin = False,
              ccdRawData = M.NoRaw
            }
      clientDataHash =
        M.ClientDataHash $ hash $ M.unRaw $ M.ccdRawData clientData
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
        M.PublicKeyCredential
          { M.pkcIdentifier = M.acdCredentialId . M.adAttestedCredentialData $ M.aoAuthData attestationObject,
            M.pkcResponse =
              M.AuthenticatorAttestationResponse
                { M.arcClientData = clientData,
                  M.arcAttestationObject = attestationObject
                },
            M.pkcClientExtensionResults = M.AuthenticationExtensionsClientOutputs {}
          }
  pure (response, authenticator')

-- | Performs assertion as per the client specification provided an
-- authenticator. MonadRandom is required for signing using Ed25519 which
-- requires a random number to be generated during signing. There exists
-- methods to not rely on a random number, but these have not been implemented
-- in the cryptonite library we rely on.
clientAssertion ::
  (MonadFail m, Random.MonadRandom m) =>
  M.PublicKeyCredentialOptions 'M.Get ->
  AnnotatedOrigin ->
  UserAgentConformance ->
  Authenticator ->
  m (M.PublicKeyCredential 'M.Get 'True, Authenticator)
clientAssertion M.PublicKeyCredentialRequestOptions {..} AnnotatedOrigin {..} conformance authenticator = do
  let allowCredentialDescriptorList = case pkcogAllowCredentials of
        [] -> Nothing
        xs -> Just xs
  challenge <-
    if Set.member RandomChallenge conformance
      then Challenge <$> Random.getRandomBytes 16
      else pure pkcogChallenge
  let clientData =
        ME.encodeRawCollectedClientData
          M.CollectedClientData
            { ccdChallenge = challenge,
              ccdOrigin = aoOrigin,
              ccdCrossOrigin = False,
              ccdRawData = M.NoRaw
            }
      clientDataHash = M.ClientDataHash $ hash $ M.unRaw $ M.ccdRawData clientData
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

-- | Performs attestation to generate a credential, and then uses that
-- credential to perform assertion.
register ::
  (Random.MonadRandom m, MonadFail m) =>
  AnnotatedOrigin ->
  UserAgentConformance ->
  Authenticator ->
  m (Either (NE.NonEmpty Fido2.AttestationError) Fido2.CredentialEntry, Authenticator, M.PublicKeyCredentialOptions 'M.Create)
register ao conformance authenticator = do
  -- Generate new random input
  assertionChallenge <- M.Challenge <$> Random.getRandomBytes 16
  userId <- M.UserHandle <$> Random.getRandomBytes 16
  -- Create dummy user
  let user =
        M.PublicKeyCredentialUserEntity
          { M.pkcueId = userId,
            M.pkcueDisplayName = M.UserAccountDisplayName "John Doe",
            M.pkcueName = M.UserAccountName "john-doe"
          }
  let options = defaultPkcoc user assertionChallenge
  -- Perform client Attestation emulation with a fresh authenticator
  (mPkcCreate, authenticator) <- clientAttestation options ao conformance authenticator
  -- Verify the result
  let registerResult =
        toEither $
          Fido2.verifyAttestationResponse
            (aoOrigin ao)
            (M.RpIdHash . hash . encodeUtf8 . M.unRpId $ aoRpId ao)
            options
            mPkcCreate
  pure (registerResult, authenticator, options)

login ::
  (Random.MonadRandom m, MonadFail m) =>
  AnnotatedOrigin ->
  UserAgentConformance ->
  Authenticator ->
  Fido2.CredentialEntry ->
  m (Either (NE.NonEmpty Fido2.AssertionError) Fido2.SignatureCounterResult)
login ao conformance authenticator ce@Fido2.CredentialEntry {..} = do
  attestationChallenge <- M.Challenge <$> Random.getRandomBytes 16
  let options = defaultPkcog attestationChallenge
  -- Perform client assertion emulation with the same authenticator, this
  -- authenticator should now store the created credential
  (mPkcGet, _) <- clientAssertion options ao conformance authenticator
  pure
    . toEither
    $ Fido2.verifyAssertionResponse
      (aoOrigin ao)
      (M.RpIdHash . hash . encodeUtf8 . M.unRpId $ aoRpId ao)
      (Just ceUserHandle)
      ce
      options
      mPkcGet

spec :: SpecWith ()
spec =
  describe "None" $
    it "succeeds" $
      property $ \seed authenticator -> do
        let annotatedOrigin =
              AnnotatedOrigin
                { aoRpId = M.RpId "localhost",
                  aoOrigin = M.Origin "https://localhost:8080"
                }
            userAgentConformance = Set.empty
        -- We are not currently interested in client or authenticator fails, we
        -- only wish to test our relying party implementation and are thus only
        -- interested in its errors.
        let Right (registerResult, authenticator', options) = runApp seed (register annotatedOrigin userAgentConformance authenticator)
        registerResult `shouldSatisfy` validAttestationResult authenticator options
        -- Only if attestation succeeded can we continue with assertion
        case registerResult of
          Right credentialEntry -> do
            let Right loginResult = runApp (seed + 1) (login annotatedOrigin userAgentConformance authenticator' credentialEntry)
            loginResult `shouldSatisfy` validAssertionResult authenticator
          _ -> pure ()

-- | Validates the result of attestation. Ensures that the proper errors are
-- resulted in if the authenticator exhibits nonconforming behaviour, and
-- checks if the correct result was given if the authenticator does not exhibit
-- any nonconforming behaviour.
validAttestationResult :: Authenticator -> M.PublicKeyCredentialOptions 'M.Create -> Either (NE.NonEmpty Fido2.AttestationError) Fido2.CredentialEntry -> Bool
-- A valid result can only happen if we exhibited no non-conforming behaviour
-- The userHandle must be the one specified by the options
validAttestationResult _ M.PublicKeyCredentialCreationOptions {..} (Right Fido2.CredentialEntry {..}) = ceUserHandle == M.pkcueId pkcocUser
-- If we did result in errors, we want every error to be validated by some
-- configuration issue (NOTE: We cannot currently exhibit non conforming
-- behaviour during attestation)
validAttestationResult AuthenticatorNone {..} _ (Left errors) = all isValidated errors
  where
    isValidated :: Fido2.AttestationError -> Bool
    isValidated (Fido2.AttestationChallengeMismatch _ _) = False
    isValidated (Fido2.AttestationOriginMismatch _ _) = False
    isValidated (Fido2.AttestationRpIdHashMismatch _ _) = False
    -- The User not being present must be a result of the authenticator not checking for a user being present
    isValidated Fido2.AttestationUserNotPresent = not $ M.adfUserPresent aAuthenticatorDataFlags
    -- The User not being valided must be a result of the authenticator not validating the user
    isValidated Fido2.AttestationUserNotVerified = not $ M.adfUserVerified aAuthenticatorDataFlags
    isValidated (Fido2.AttestationUndesiredPublicKeyAlgorithm _ _) = False
    isValidated (Fido2.AttestationFormatError _) = False

-- | Validates the result of assertion. Ensures that the proper errors are
-- resulted in if the authenticator exhibits nonconforming behaviour, and
-- checks if the correct result was given if the authenticator does not exhibit
-- any nonconforming behaviour.
validAssertionResult :: Authenticator -> Either (NE.NonEmpty Fido2.AssertionError) Fido2.SignatureCounterResult -> Bool
-- We can only result in a 0 signature counter if the authenticator doesn't
-- have a counter and is either conforming or only has a static counter
validAssertionResult AuthenticatorNone {..} (Right Fido2.SignatureCounterZero) =
  aSignatureCounter == Unsupported && (Set.null aConformance || aConformance == Set.singleton StaticCounter)
-- A valid response must only happen if we have no non-confirming behaviour
validAssertionResult AuthenticatorNone {..} (Right (Fido2.SignatureCounterUpdated _)) = Set.null aConformance
-- A potentially cloned counter must imply that we only exhibited the static
-- counter non-conforming behaviour
validAssertionResult AuthenticatorNone {..} (Right Fido2.SignatureCounterPotentiallyCloned) = Set.singleton StaticCounter == aConformance
-- If we did result in errors, we want every error to be validated by some
-- non-conforming behaviour or configuration issue
validAssertionResult AuthenticatorNone {..} (Left errors) = all isValidated errors
  where
    isValidated :: Fido2.AssertionError -> Bool
    isValidated (Fido2.AssertionDisallowedCredential _ _) = False
    isValidated (Fido2.AssertionIdentifiedUserHandleMismatch _ _) = False
    isValidated (Fido2.AssertionCredentialUserHandleMismatch _ _) = False
    isValidated Fido2.AssertionCannotVerifyUserHandle = False
    isValidated (Fido2.AssertionChallengeMismatch _ _) = False
    isValidated (Fido2.AssertionOriginMismatch _ _) = False
    isValidated (Fido2.AssertionRpIdHashMismatch _ _) = False
    -- The User not being present must be a result of the authenticator not checking for a user being present
    isValidated Fido2.AssertionUserNotPresent = not $ M.adfUserPresent aAuthenticatorDataFlags
    -- The User not being valided must be a result of the authenticator not validating the user
    isValidated Fido2.AssertionUserNotVerified = not $ M.adfUserVerified aAuthenticatorDataFlags
    -- The Signature being invalid can happen when the data was wrong or the wrong private key was used
    isValidated (Fido2.AssertionInvalidSignature _) = elem RandomSignatureData aConformance || elem RandomPrivateKey aConformance

-- | Create a default set of options for attestation. These options can be modified before using them in the tests
defaultPkcoc :: M.PublicKeyCredentialUserEntity -> M.Challenge -> M.PublicKeyCredentialOptions 'M.Create
defaultPkcoc userEntity challenge =
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
              M.pkcpAlg = PublicKey.COSEAlgorithmIdentifierES384
            },
          M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = PublicKey.COSEAlgorithmIdentifierES512
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
defaultPkcog :: M.Challenge -> M.PublicKeyCredentialOptions 'M.Get
defaultPkcog challenge =
  M.PublicKeyCredentialRequestOptions
    { M.pkcogChallenge = challenge,
      M.pkcogTimeout = Nothing,
      M.pkcogRpId = Just "localhost",
      -- We currently only support client-side discoverable credentials
      M.pkcogAllowCredentials = [],
      M.pkcogUserVerification = M.UserVerificationRequirementPreferred,
      M.pkcogExtensions = Nothing
    }
