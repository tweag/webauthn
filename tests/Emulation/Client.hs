{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}

-- | This modules provdes a way to emulate certain client behaviour for testing
-- purposes. It DOES NOT implement the webauthn specification because there is
-- no need for it in our tests.
module Emulation.Client
  ( AnnotatedOrigin (..),
    UserAgentNonConformingBehaviour (..),
    UserAgentConformance,
    clientAssertion,
    clientAttestation,
  )
where

import Crypto.Hash (hash)
import qualified Crypto.Random as Random
import Crypto.WebAuthn.Model (Challenge (Challenge))
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Model.Binary.Encoding as ME
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Emulation.Authenticator
  ( Authenticator,
    authenticatorGetAssertion,
    authenticatorMakeCredential,
  )
import Emulation.Authenticator.Arbitrary ()

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
  deriving (Eq, Ord, Show)

-- | The ways in which the UserAgent should not conform to the spec
type UserAgentConformance = Set.Set UserAgentNonConformingBehaviour

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
                  M.argSignature = M.AssertionSignature signature,
                  M.argUserHandle = userHandle
                },
            M.pkcClientExtensionResults = M.AuthenticationExtensionsClientOutputs {}
          }
  pure (response, authenticator')
