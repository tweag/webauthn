{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}

module Emulation
  ( spec,
  )
where

import Control.Monad.Except (ExceptT (ExceptT), MonadError, MonadTrans (lift), runExceptT, throwError)
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Operations.Assertion as Fido2
import qualified Crypto.Fido2.Operations.Attestation as Fido2
import qualified Crypto.Fido2.Operations.Common as Fido2
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (hash)
import qualified Crypto.Random as Random
import qualified Data.List.NonEmpty as NE
import qualified Data.Set as Set
import Data.Text.Encoding (encodeUtf8)
import Data.Validation (toEither)
import Emulation.Authenticator
  ( Authenticator (AuthenticatorNone, aAuthenticatorDataFlags, aConformance, aSignatureCounter),
    AuthenticatorNonConformingBehaviour (RandomPrivateKey, RandomSignatureData, StaticCounter),
    AuthenticatorSignatureCounter (Unsupported),
  )
import Emulation.Authenticator.Arbitrary ()
import Emulation.Client (AnnotatedOrigin (AnnotatedOrigin, aoOrigin, aoRpId), UserAgentConformance, UserAgentNonConformingBehaviour (RandomChallenge), clientAssertion, clientAttestation)
import Emulation.Client.Arbitrary ()
import Test.Hspec (SpecWith, describe, it, shouldSatisfy)
import Test.QuickCheck (property)

-- | Custom type to combine the MonadPseudoRandom with the Except monad. We
-- force the ChaChaDRG to ensure the App type is completely pure, and
-- evaluating the monad has no side effects.
newtype App a = App (ExceptT String (Random.MonadPseudoRandom Random.ChaChaDRG) a)
  deriving newtype (Functor, Applicative, Monad, MonadError String)

instance MonadFail App where
  fail = throwError

instance Random.MonadRandom App where
  getRandomBytes n = App $ lift $ Random.getRandomBytes n

runApp :: Integer -> App a -> Either String a
runApp seed (App except) =
  let rng = Random.drgNewSeed $ Random.seedFromInteger seed
   in fst $ Random.withDRG rng $ runExceptT except

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
      property $ \seed authenticator userAgentConformance -> do
        let annotatedOrigin =
              AnnotatedOrigin
                { aoRpId = M.RpId "localhost",
                  aoOrigin = M.Origin "https://localhost:8080"
                }
        -- We are not currently interested in client or authenticator fails, we
        -- only wish to test our relying party implementation and are thus only
        -- interested in its errors.
        let Right (registerResult, authenticator', options) = runApp seed (register annotatedOrigin userAgentConformance authenticator)
        registerResult `shouldSatisfy` validAttestationResult authenticator userAgentConformance options
        -- Only if attestation succeeded can we continue with assertion
        case registerResult of
          Right credentialEntry -> do
            let Right loginResult = runApp (seed + 1) (login annotatedOrigin userAgentConformance authenticator' credentialEntry)
            loginResult `shouldSatisfy` validAssertionResult authenticator userAgentConformance
          _ -> pure ()

-- | Validates the result of attestation. Ensures that the proper errors are
-- resulted in if the authenticator exhibits nonconforming behaviour, and
-- checks if the correct result was given if the authenticator does not exhibit
-- any nonconforming behaviour.
validAttestationResult :: Authenticator -> UserAgentConformance -> M.PublicKeyCredentialOptions 'M.Create -> Either (NE.NonEmpty Fido2.AttestationError) Fido2.CredentialEntry -> Bool
-- A valid result can only happen if we exhibited no non-conforming behaviour
-- The userHandle must be the one specified by the options
validAttestationResult _ _ M.PublicKeyCredentialCreationOptions {..} (Right Fido2.CredentialEntry {..}) = ceUserHandle == M.pkcueId pkcocUser
-- If we did result in errors, we want every error to be validated by some
-- configuration issue (NOTE: We cannot currently exhibit non conforming
-- behaviour during attestation)
validAttestationResult AuthenticatorNone {..} uaConformance _ (Left errors) = all isValidated errors
  where
    isValidated :: Fido2.AttestationError -> Bool
    isValidated (Fido2.AttestationChallengeMismatch _ _) = RandomChallenge `elem` uaConformance
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
validAssertionResult :: Authenticator -> UserAgentConformance -> Either (NE.NonEmpty Fido2.AssertionError) Fido2.SignatureCounterResult -> Bool
-- We can only result in a 0 signature counter if the authenticator doesn't
-- have a counter and is either conforming or only has a static counter
validAssertionResult AuthenticatorNone {..} _ (Right Fido2.SignatureCounterZero) =
  aSignatureCounter == Unsupported && (Set.null aConformance || aConformance == Set.singleton StaticCounter)
-- A valid response must only happen if we have no non-confirming behaviour
validAssertionResult AuthenticatorNone {..} _ (Right (Fido2.SignatureCounterUpdated _)) = Set.null aConformance
-- A potentially cloned counter must imply that we only exhibited the static
-- counter non-conforming behaviour
validAssertionResult AuthenticatorNone {..} _ (Right Fido2.SignatureCounterPotentiallyCloned) = Set.singleton StaticCounter == aConformance
-- If we did result in errors, we want every error to be validated by some
-- non-conforming behaviour or configuration issue
validAssertionResult AuthenticatorNone {..} uaConformance (Left errors) = all isValidated errors
  where
    isValidated :: Fido2.AssertionError -> Bool
    isValidated (Fido2.AssertionDisallowedCredential _ _) = False
    isValidated (Fido2.AssertionIdentifiedUserHandleMismatch _ _) = False
    isValidated (Fido2.AssertionCredentialUserHandleMismatch _ _) = False
    isValidated Fido2.AssertionCannotVerifyUserHandle = False
    isValidated (Fido2.AssertionChallengeMismatch _ _) = RandomChallenge `elem` uaConformance
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
