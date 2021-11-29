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
import qualified Crypto.Fido2.Model.JavaScript as JS
import Crypto.Fido2.Model.JavaScript.Decoding
  ( decodeCreateCollectedClientData,
    decodeGetCollectedClientData,
  )
import qualified Crypto.Fido2.Model.JavaScript.Types as JS
import qualified Crypto.Fido2.Operations.Assertion as Fido2
import qualified Crypto.Fido2.Operations.Attestation as Fido2
import qualified Crypto.Fido2.PublicKey as PublicKey
import qualified Crypto.Fido2.WebIDL as IDL
import Crypto.Hash (hash)
import Crypto.Random (getRandomBytes)
import qualified Crypto.Random as Random
import Data.Aeson (encode)
import qualified Data.ByteString.Base64.URL as Base64
import Data.ByteString.Lazy (toStrict)
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Validation (toEither)
import Emulation.Authenticator
  ( Authenticator
      ( AuthenticatorNone,
        aAAGUID,
        aAuthenticatorDataFlags,
        aConformance,
        aCredentials,
        aSignatureCounter,
        aSupportedAlgorithms
      ),
    AuthenticatorSignatureCounter (Global),
    authenticatorGetAssertion,
    authenticatorMakeCredential,
  )
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
  = -- | Set the Client data type to the wrong value during attestation
    WrongAttestationClientDataType
  | -- | Set the Client data type to the wrong value during assertion
    WrongAssertionClientDataType
  | -- | Generate a random challenge instead of the one provided by
    RandomChallenge
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
  m (M.PublicKeyCredential 'M.Create, Authenticator)
clientAttestation M.PublicKeyCredentialCreationOptions {..} AnnotatedOrigin {..} conformance authenticator = do
  let typ =
        if Set.member WrongAttestationClientDataType conformance
          then "webauthn.get"
          else "webauthn.create"
  challenge <-
    if Set.member RandomChallenge conformance
      then Challenge <$> Random.getRandomBytes 16
      else pure pkcocChallenge

  -- We would ideally construct the M.CollectedClientData first, but this
  -- is impossible since we need the hash. As a workaround we construct
  -- the encoded version first by manually encoding the intermediate JSON
  -- representation, allowing us to construct the hash and the
  -- CollectedClientData from that.
  let clientDataAB =
        IDL.URLEncodedBase64 . toStrict $
          encode
            JS.ClientDataJSON
              { JS.littype = typ,
                JS.challenge = decodeUtf8 . Base64.encode $ M.unChallenge challenge,
                JS.origin = M.unOrigin aoOrigin,
                JS.crossOrigin = Nothing
              }
      clientDataHash =
        M.ClientDataHash . hash $ IDL.unUrlEncodedBase64 clientDataAB
      clientData = either (error . ((++) "Test: could not decode encoded clientData: " . show)) id $ decodeCreateCollectedClientData clientDataAB
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
                  M.arcAttestationObject = attestationObject,
                  -- Currently ignored by the library
                  -- TODO: Policy
                  M.arcTransports = Set.empty
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
  m (M.PublicKeyCredential 'M.Get, Authenticator)
clientAssertion M.PublicKeyCredentialRequestOptions {..} AnnotatedOrigin {..} conformance authenticator = do
  let allowCredentialDescriptorList = case pkcogAllowCredentials of
        [] -> Nothing
        xs -> Just xs
      typ =
        if Set.member WrongAssertionClientDataType conformance
          then "webauthn.create"
          else "webauthn.get"
  challenge <-
    if Set.member RandomChallenge conformance
      then Challenge <$> Random.getRandomBytes 16
      else pure pkcogChallenge
  -- We would ideally construct the M.CollectedClientData first, but this
  -- is impossible since we need the hash. As a workaround we construct
  -- the encoded version first by manually encoding the intermediate JSON
  -- representation, allowing us to construct the hash and the
  -- CollectedClientData from that.
  let clientDataAB =
        IDL.URLEncodedBase64 . toStrict $
          encode
            JS.ClientDataJSON
              { JS.littype = typ,
                JS.challenge = decodeUtf8 . Base64.encode $ M.unChallenge challenge,
                JS.origin = M.unOrigin aoOrigin,
                JS.crossOrigin = Nothing
              }
      clientDataHash = M.ClientDataHash . hash $ IDL.unUrlEncodedBase64 clientDataAB
      clientData = either (error . ((++) "Test: could not decode encoded clientData: " . show)) id $ decodeGetCollectedClientData clientDataAB
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
attestationAndAssertion ::
  (Random.MonadRandom m, MonadFail m) =>
  AnnotatedOrigin ->
  UserAgentConformance ->
  Authenticator ->
  m Fido2.SignatureCounterResult
attestationAndAssertion ao conformance authenticator = do
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
  let Right credentialEntry = registerResult
  attestationChallenge <- M.Challenge <$> Random.getRandomBytes 16
  let options = defaultPkcog attestationChallenge
  -- Perform client assertion emulation with the same authenticator, this
  -- authenticator should now store the created credential
  (mPkcGet, _) <- clientAssertion options ao conformance authenticator
  let Right loginResult =
        toEither $
          Fido2.verifyAssertionResponse
            (aoOrigin ao)
            (M.RpIdHash . hash . encodeUtf8 . M.unRpId $ aoRpId ao)
            (Just userId)
            credentialEntry
            options
            mPkcGet
  pure loginResult

spec :: SpecWith ()
spec =
  describe "None" $
    it "succeeds" $
      property $ \seed ->
        let annotatedOrigin =
              AnnotatedOrigin
                { aoRpId = M.RpId "localhost",
                  aoOrigin = M.Origin "https://localhost:8080"
                }
            authenticatorConformance = Set.empty
            userAgentConformance = Set.empty
            noneAuthenticator =
              AuthenticatorNone
                { aAAGUID = M.AAGUID "0000000000000000",
                  aAuthenticatorDataFlags =
                    M.AuthenticatorDataFlags
                      { adfUserPresent = True,
                        adfUserVerified = True
                      },
                  aCredentials = Map.empty,
                  aSignatureCounter = Global 0,
                  aSupportedAlgorithms = Set.singleton PublicKey.COSEAlgorithmIdentifierEdDSA,
                  aConformance = authenticatorConformance
                }
            Right c = runApp seed $ attestationAndAssertion annotatedOrigin userAgentConformance noneAuthenticator
         in c `shouldSatisfy` \case
              Fido2.SignatureCounterZero -> True
              Fido2.SignatureCounterUpdated _ -> True
              Fido2.SignatureCounterPotentiallyCloned -> False

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
