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
import qualified Crypto.WebAuthn.Encoding.Binary as ME
import qualified Crypto.WebAuthn.Model as M
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
  M.CredentialOptions 'M.Registration ->
  AnnotatedOrigin ->
  UserAgentConformance ->
  Authenticator ->
  m (M.Credential 'M.Registration 'True, Authenticator)
clientAttestation M.CredentialOptionsRegistration {..} AnnotatedOrigin {..} conformance authenticator = do
  challenge <-
    if Set.member RandomChallenge conformance
      then M.Challenge <$> Random.getRandomBytes 16
      else pure corChallenge
  let clientData =
        ME.encodeRawCollectedClientData
          M.CollectedClientData
            { ccdChallenge = challenge,
              ccdOrigin = aoOrigin,
              ccdCrossOrigin = Just False,
              ccdRawData = M.NoRaw
            }
      clientDataHash =
        M.ClientDataHash $ hash $ M.unRaw $ M.ccdRawData clientData
  (attestationObject, authenticator') <-
    authenticatorMakeCredential
      authenticator
      clientDataHash
      -- Ensure the RpId is set by defaulting to the Client configured default if Nothing
      (corRp {M.creId = Just . fromMaybe aoRpId $ M.creId corRp})
      corUser
      True
      True
      True
      corPubKeyCredParams
      corExcludeCredentials
      False
      corExtensions
  let response =
        M.Credential
          { M.cIdentifier = M.acdCredentialId . M.adAttestedCredentialData $ M.aoAuthData attestationObject,
            M.cResponse =
              M.AuthenticatorResponseRegistration
                { M.arrClientData = clientData,
                  M.arrAttestationObject = attestationObject,
                  M.arrTransports = []
                },
            M.cClientExtensionResults = M.AuthenticationExtensionsClientOutputs {aecoCredProps = Nothing}
          }
  pure (response, authenticator')

-- | Performs assertion as per the client specification provided an
-- authenticator. MonadRandom is required for signing using Ed25519 which
-- requires a random number to be generated during signing. There exists
-- methods to not rely on a random number, but these have not been implemented
-- in the crypton library we rely on.
clientAssertion ::
  (MonadFail m, Random.MonadRandom m) =>
  M.CredentialOptions 'M.Authentication ->
  AnnotatedOrigin ->
  UserAgentConformance ->
  Authenticator ->
  m (M.Credential 'M.Authentication 'True, Authenticator)
clientAssertion M.CredentialOptionsAuthentication {..} AnnotatedOrigin {..} conformance authenticator = do
  let allowCredentialDescriptorList = case coaAllowCredentials of
        [] -> Nothing
        xs -> Just xs
  challenge <-
    if Set.member RandomChallenge conformance
      then M.Challenge <$> Random.getRandomBytes 16
      else pure coaChallenge
  let clientData =
        ME.encodeRawCollectedClientData
          M.CollectedClientData
            { ccdChallenge = challenge,
              ccdOrigin = aoOrigin,
              ccdCrossOrigin = Just False,
              ccdRawData = M.NoRaw
            }
      clientDataHash = M.ClientDataHash $ hash $ M.unRaw $ M.ccdRawData clientData
  ((credentialId, authenticatorData, signature, userHandle), authenticator') <-
    authenticatorGetAssertion
      authenticator
      -- Ensure the RpId is set by defaulting to the Client configured default if Nothing
      (fromMaybe aoRpId coaRpId)
      clientDataHash
      allowCredentialDescriptorList
      True
      True
      coaExtensions
  let response =
        M.Credential
          { M.cIdentifier = credentialId,
            M.cResponse =
              M.AuthenticatorResponseAuthentication
                { M.araClientData = clientData,
                  M.araAuthenticatorData = authenticatorData,
                  M.araSignature = M.AssertionSignature signature,
                  M.araUserHandle = userHandle
                },
            M.cClientExtensionResults = M.AuthenticationExtensionsClientOutputs {aecoCredProps = Nothing}
          }
  pure (response, authenticator')
