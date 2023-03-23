{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}

module Emulation
  ( spec,
  )
where

import Control.Monad.Trans (MonadTrans (lift))
import Control.Monad.Except (ExceptT (ExceptT), MonadError, runExceptT, throwError)
import Crypto.Hash (hash)
import qualified Crypto.Random as Random
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import qualified Crypto.WebAuthn.Metadata.Service.Types as Meta
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Operation as O
import Data.Bifunctor (Bifunctor (second))
import Data.Hourglass (DateTime)
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
import Emulation.Client
  ( AnnotatedOrigin (AnnotatedOrigin, aoOrigin, aoRpId),
    UserAgentConformance,
    UserAgentNonConformingBehaviour (RandomChallenge),
    clientAssertion,
    clientAttestation,
  )
import Emulation.Client.Arbitrary ()
import Spec.Util (predeterminedDateTime)
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
  Meta.MetadataServiceRegistry ->
  DateTime ->
  m (Either (NE.NonEmpty O.RegistrationError) O.RegistrationResult, Authenticator, M.CredentialOptions 'M.Registration)
register ao conformance authenticator registry now = do
  -- Generate new random input
  assertionChallenge <- M.generateChallenge
  userId <- M.generateUserHandle
  -- Create dummy user
  let user =
        M.CredentialUserEntity
          { M.cueId = userId,
            M.cueDisplayName = M.UserAccountDisplayName "John Doe",
            M.cueName = M.UserAccountName "john-doe"
          }
  let options = defaultPkcoc user assertionChallenge
  -- Perform client Attestation emulation with a fresh authenticator
  (mPkcCreate, authenticator) <- clientAttestation options ao conformance authenticator
  -- Verify the result
  let registerResult =
        toEither $
          O.verifyRegistrationResponse
            (aoOrigin ao)
            (M.RpIdHash . hash . encodeUtf8 . M.unRpId $ aoRpId ao)
            registry
            now
            options
            mPkcCreate
  pure (registerResult, authenticator, options)

login ::
  (Random.MonadRandom m, MonadFail m) =>
  AnnotatedOrigin ->
  UserAgentConformance ->
  Authenticator ->
  O.CredentialEntry ->
  m (Either (NE.NonEmpty O.AuthenticationError) O.SignatureCounterResult)
login ao conformance authenticator ce@O.CredentialEntry {..} = do
  attestationChallenge <- M.generateChallenge
  let options = defaultCog attestationChallenge
  -- Perform client assertion emulation with the same authenticator, this
  -- authenticator should now store the created credential
  (mPkcGet, _) <- clientAssertion options ao conformance authenticator
  pure
    . second O.arSignatureCounterResult
    . toEither
    $ O.verifyAuthenticationResponse
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
        -- Since our emulator only supports None attestation the registry can be left empty.
        let registry = mempty
        -- We are not currently interested in client or authenticator fails, we
        -- only wish to test our relying party implementation and are thus only
        -- interested in its errors.
        let Right (registerResult, authenticator', options) = runApp seed (register annotatedOrigin userAgentConformance authenticator registry predeterminedDateTime)
        -- Since we only do None attestation, we only care about the resulting entry
        let registerResult' = second O.rrEntry registerResult
        registerResult' `shouldSatisfy` validAttestationResult authenticator userAgentConformance options
        -- Only if attestation succeeded can we continue with assertion
        case registerResult' of
          Right credentialEntry -> do
            let Right loginResult = runApp (seed + 1) (login annotatedOrigin userAgentConformance authenticator' credentialEntry)
            loginResult `shouldSatisfy` validAssertionResult authenticator userAgentConformance
          _ -> pure ()

-- | Validates the result of attestation. Ensures that the proper errors are
-- resulted in if the authenticator exhibits nonconforming behaviour, and
-- checks if the correct result was given if the authenticator does not exhibit
-- any nonconforming behaviour.
validAttestationResult :: Authenticator -> UserAgentConformance -> M.CredentialOptions 'M.Registration -> Either (NE.NonEmpty O.RegistrationError) O.CredentialEntry -> Bool
-- A valid result can only happen if we exhibited no non-conforming behaviour
-- The userHandle must be the one specified by the options
validAttestationResult _ _ M.CredentialOptionsRegistration {..} (Right O.CredentialEntry {..}) = ceUserHandle == M.cueId corUser
-- If we did result in errors, we want every error to be validated by some
-- configuration issue (NOTE: We cannot currently exhibit non conforming
-- behaviour during attestation)
validAttestationResult AuthenticatorNone {..} uaConformance _ (Left errors) = all isValidated errors
  where
    isValidated :: O.RegistrationError -> Bool
    isValidated (O.RegistrationChallengeMismatch _ _) = RandomChallenge `elem` uaConformance
    isValidated (O.RegistrationOriginMismatch _ _) = False
    isValidated (O.RegistrationRpIdHashMismatch _ _) = False
    -- The User not being present must be a result of the authenticator not checking for a user being present
    isValidated O.RegistrationUserNotPresent = not $ M.adfUserPresent aAuthenticatorDataFlags
    -- The User not being valided must be a result of the authenticator not validating the user
    isValidated O.RegistrationUserNotVerified = not $ M.adfUserVerified aAuthenticatorDataFlags
    isValidated (O.RegistrationPublicKeyAlgorithmDisallowed _ _) = False
    isValidated (O.RegistrationAttestationFormatError _ _) = False

-- | Validates the result of assertion. Ensures that the proper errors are
-- resulted in if the authenticator exhibits nonconforming behaviour, and
-- checks if the correct result was given if the authenticator does not exhibit
-- any nonconforming behaviour.
validAssertionResult :: Authenticator -> UserAgentConformance -> Either (NE.NonEmpty O.AuthenticationError) O.SignatureCounterResult -> Bool
-- We can only result in a 0 signature counter if the authenticator doesn't
-- have a counter and is either conforming or only has a static counter
validAssertionResult AuthenticatorNone {..} _ (Right O.SignatureCounterZero) =
  aSignatureCounter == Unsupported && (Set.null aConformance || aConformance == Set.singleton StaticCounter)
-- A valid response must only happen if we have no non-confirming behaviour
validAssertionResult AuthenticatorNone {..} _ (Right (O.SignatureCounterUpdated _)) = Set.null aConformance
-- A potentially cloned counter must imply that we only exhibited the static
-- counter non-conforming behaviour
validAssertionResult AuthenticatorNone {..} _ (Right O.SignatureCounterPotentiallyCloned) = Set.singleton StaticCounter == aConformance
-- If we did result in errors, we want every error to be validated by some
-- non-conforming behaviour or configuration issue
validAssertionResult AuthenticatorNone {..} uaConformance (Left errors) = all isValidated errors
  where
    isValidated :: O.AuthenticationError -> Bool
    isValidated (O.AuthenticationCredentialDisallowed _ _) = False
    isValidated (O.AuthenticationIdentifiedUserHandleMismatch _ _) = False
    isValidated (O.AuthenticationCredentialUserHandleMismatch _ _) = False
    isValidated O.AuthenticationCannotVerifyUserHandle = False
    isValidated (O.AuthenticationChallengeMismatch _ _) = RandomChallenge `elem` uaConformance
    isValidated (O.AuthenticationOriginMismatch _ _) = False
    isValidated (O.AuthenticationRpIdHashMismatch _ _) = False
    -- The User not being present must be a result of the authenticator not checking for a user being present
    isValidated O.AuthenticationUserNotPresent = not $ M.adfUserPresent aAuthenticatorDataFlags
    -- The User not being valided must be a result of the authenticator not validating the user
    isValidated O.AuthenticationUserNotVerified = not $ M.adfUserVerified aAuthenticatorDataFlags
    -- The Signature being invalid can happen when the data was wrong or the wrong private key was used
    isValidated (O.AuthenticationSignatureDecodingError _) = False
    isValidated O.AuthenticationSignatureInvalid {} = elem RandomSignatureData aConformance || elem RandomPrivateKey aConformance

-- | Create a default set of options for attestation. These options can be modified before using them in the tests
defaultPkcoc :: M.CredentialUserEntity -> M.Challenge -> M.CredentialOptions 'M.Registration
defaultPkcoc userEntity challenge =
  M.CredentialOptionsRegistration
    { M.corRp = M.CredentialRpEntity {M.creId = Nothing, M.creName = "ACME"},
      M.corUser = userEntity,
      M.corChallenge = challenge,
      -- Empty credentialparameters are not supported.
      M.corPubKeyCredParams =
        [ M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmES256
            },
          M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmES384
            },
          M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmES512
            },
          M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmEdDSA
            },
          M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmRS1
            },
          M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmRS256
            },
          M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmRS384
            },
          M.CredentialParameters
            { M.cpTyp = M.CredentialTypePublicKey,
              M.cpAlg = Cose.CoseAlgorithmRS512
            }
        ],
      M.corTimeout = Nothing,
      M.corExcludeCredentials = [],
      M.corAuthenticatorSelection =
        Just
          M.AuthenticatorSelectionCriteria
            { M.ascAuthenticatorAttachment = Nothing,
              M.ascResidentKey = M.ResidentKeyRequirementDiscouraged,
              M.ascUserVerification = M.UserVerificationRequirementPreferred
            },
      M.corAttestation = M.AttestationConveyancePreferenceDirect,
      M.corExtensions = Nothing
    }

-- | Create a default set of options for assertion. These options can be modified before using them in the tests
defaultCog :: M.Challenge -> M.CredentialOptions 'M.Authentication
defaultCog challenge =
  M.CredentialOptionsAuthentication
    { M.coaChallenge = challenge,
      M.coaTimeout = Nothing,
      M.coaRpId = Just "localhost",
      -- We currently only support client-side discoverable credentials
      M.coaAllowCredentials = [],
      M.coaUserVerification = M.UserVerificationRequirementPreferred,
      M.coaExtensions = Nothing
    }
