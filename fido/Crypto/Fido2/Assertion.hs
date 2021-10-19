{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}

module Crypto.Fido2.Assertion
  ( verifyAssertionResponse,
    RelyingPartyConfig (..),
    Credential (..),
  )
where

import Control.Monad (unless, when)
import Crypto.Fido2.Error
  ( AssertionError (AssertionCommonError),
    CommonError
      ( ChallengeMismatch,
        CredentialMismatch,
        InvalidSignature,
        InvalidWebauthnType,
        RpIdHashMismatch,
        RpOriginMismatch,
        UserNotPresent,
        UserNotVerified
      ),
  )
import qualified Crypto.Fido2.Protocol as Fido2
import Crypto.Fido2.PublicKey (PublicKey)
import qualified Crypto.Hash as Hash
import qualified Data.List as List
import qualified Data.Text.Encoding as Text

-- | Domain type: combination of a user's ID and publickey. This should be eventually
-- extracted into some opinionated module that builds on top of the actual protocol types.
data Credential = Credential {id :: Fido2.CredentialId, publicKey :: PublicKey}

-- | Domain type: configuration for our relying party. Should eventually be moved to
-- some other opinionated module.
data RelyingPartyConfig = RelyingPartyConfig {origin :: Fido2.Origin, rpId :: Fido2.RpId}

-- | Verify that a 'Fido2.PublicKeyCredential' is valid for the given
-- 'RelyingPartyConfig', 'Fido2.Challenge', and list of 'Credential's known to be
-- associated with a given user.
--
-- Use this function when you want to authenticate a user where:
--
--  - You know the user you want to authenticate in advance.
--  - You know what the list of publickeys for a given user are.
--
-- This does not implement the following things from the specification:
--
--  - TLS token binding (spec step 10)
--  - Client extensions (spec step 14)
--  - Signature counting (spec step 17)
verifyAssertionResponse ::
  RelyingPartyConfig ->
  Fido2.Challenge ->
  [Credential] ->
  Fido2.UserVerificationRequirement ->
  Fido2.PublicKeyCredential Fido2.AuthenticatorAssertionResponse ->
  Either AssertionError ()
verifyAssertionResponse
  RelyingPartyConfig {origin, rpId}
  challenge
  userCredentials
  userVerificationRequirement
  Fido2.PublicKeyCredential {rawId, response, typ = _typ} = do
    -- Verify that the given credential is within the list of userCredentials.
    -- Spec 7.2 steps 1 and 3. (Step 2 has already been implemented by the caller).
    Credential {publicKey} <-
      maybe (Left $ AssertionCommonError CredentialMismatch) pure $
        List.find (\Credential {id} -> id == rawId) userCredentials
    -- 4. Let clientData, authenticatorData and signature denote the value of
    -- credential’s response's clientDataJSON, authenticatorData, and signature
    -- respectively.
    let Fido2.AuthenticatorAssertionResponse {clientData, authenticatorData, signature, userHandle = _userHandle} = response
    let Fido2.ClientData {typ, challenge = clientChallenge, origin = clientOrigin} = clientData
    -- 7. Verify that the value of C.type is the string webauthn.get.
    when (typ /= Fido2.Get) (Left $ AssertionCommonError InvalidWebauthnType)
    -- 8. Verify that the value of C.challenge matches the challenge that was sent to
    -- the authenticator in the PublicKeyCredentialRequestOptions passed to the
    -- get() call.
    -- TODO(duijf): Is this constant time? Should it be?
    -- NOTE(Erin): I took look at the .NET implementation that does not perform
    -- this check in O(1), but rather O(n). Nor does the specification mention
    -- constant time cryptography anywhere.
    when (challenge /= clientChallenge) (Left $ AssertionCommonError ChallengeMismatch)
    -- 9. Verify that the value of C.origin matches the Relying Party's origin.
    when (origin /= clientOrigin) (Left $ AssertionCommonError RpOriginMismatch)
    let Fido2.AuthenticatorData {userPresent, rpIdHash, userVerified} = authenticatorData
    -- 11. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
    -- expected by the Relying Party.
    when (Hash.hash (Text.encodeUtf8 . Fido2.unRpId $ rpId) /= rpIdHash) . Left $ AssertionCommonError RpIdHashMismatch
    -- 12. Verify that the User Present bit of the flags in authData is set.
    unless userPresent . Left $ AssertionCommonError UserNotPresent
    -- 13. If user verification is required for this assertion, verify that the User
    -- Verified bit of the flags in authData is set.
    when (userVerificationRequirement == Fido2.UserVerificationRequired && not userVerified) . Left $ AssertionCommonError UserNotVerified
    -- 15. Let hash be the result of computing a hash over the clientData using SHA-256.
    -- 16. Using the credential public key looked up in step 3, verify that sig is a
    -- valid signature over the binary concatenation of authData and hash.
    let Fido2.URLEncodedBase64 sig = signature
    let verifyResult = Fido2.verify publicKey authenticatorData clientData sig
    unless verifyResult (Left . AssertionCommonError $ InvalidSignature)
