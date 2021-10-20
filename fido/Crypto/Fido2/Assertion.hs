{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}

module Crypto.Fido2.Assertion
  ( verifyAssertionResponse,
    VerificationError (..),
  )
where

import Control.Monad (unless, when)
import Control.Monad.Except (MonadError, throwError)
import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.PublicKey (PublicKey)
import qualified Crypto.Fido2.PublicKey as PublicKey
import Data.ByteArray (convert)
import qualified Data.ByteString as BS

data VerificationError
  = VerificationErrorDisallowedCredential (M.PublicKeyCredential 'M.Get)
  | VerificationErrorAuthenticatedUserHandleMismatch M.UserHandle M.UserHandle
  | VerificationErrorCredentialUserHandleMismatch M.UserHandle M.UserHandle
  | VerificationErrorCannotVerifyUserHandle
  | VerificationErrorChallengeMismatch M.Challenge M.Challenge
  | VerificationErrorOriginMismatch M.Origin M.Origin
  | VerificationErrorRpIdHashMismatch M.RpIdHash M.RpIdHash
  | VerificationErrorUserNotPresent
  | VerificationErrorUserNotVerified
  | VerificationErrorInvalidSignature PublicKey BS.ByteString M.AssertionSignature

verifyAssertionResponse ::
  MonadError VerificationError m =>
  M.Origin ->
  M.RpIdHash ->
  -- | The user handle, in case the user is authenticated already
  Maybe M.UserHandle ->
  -- | For a credential id, the corresponding user handle, public key and stored sign count
  (M.CredentialId -> m (M.UserHandle, PublicKey, M.SignatureCounter)) ->
  M.PublicKeyCredentialOptions 'M.Get ->
  M.PublicKeyCredential 'M.Get ->
  m Bool
verifyAssertionResponse origin rpIdHash mauthenticatedUser lookupCredential options credential = do
  -- Implemented by caller
  -- 1. Let options be a new PublicKeyCredentialRequestOptions structure
  -- configured to the Relying Party's needs for the ceremony.
  -- If options.allowCredentials is present, the transports member of each
  -- item SHOULD be set to the value returned by
  -- credential.response.getTransports() when the corresponding credential was
  -- registered.
  -- TODO

  -- 2. Call navigator.credentials.get() and pass options as the publicKey
  -- option. Let credential be the result of the successfully resolved promise.
  -- If the promise is rejected, abort the ceremony with a user-visible error,
  -- or otherwise guide the user experience as might be determinable from the
  -- context available in the rejected promise. For information on different
  -- error contexts and the circumstances leading to them, see § 6.3.3 The
  -- authenticatorGetAssertion Operation.
  -- Note: Implemented by caller

  -- 3. Let response be credential.response. If response is not an instance of
  -- AuthenticatorAssertionResponse, abort the ceremony with a user-visible
  -- error.
  -- Note: Already done as part of decoding
  let response = M.pkcResponse credential

  -- 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
  -- TODO: Implement extensions

  -- 5. If options.allowCredentials is not empty, verify that credential.id
  -- identifies one of the public key credentials listed in
  -- options.allowCredentials.
  case M.pkcogAllowCredentials options of
    Nothing -> pure ()
    Just allowCredentials
      | M.pkcIdentifier credential `elem` map M.pkcdId allowCredentials -> pure ()
      | otherwise -> throwError $ VerificationErrorDisallowedCredential credential

  -- Look up the owner (user handle) and public key of the returned credential
  (credentialOwner, credentialPublicKey, storedSignCount) <- lookupCredential (M.pkcIdentifier credential)

  -- 6. Identify the user being authenticated and verify that this user is the
  -- owner of the public key credential source credentialSource identified by
  -- credential.id:
  --
  -- -> If the user was identified before the authentication ceremony was
  -- initiated, e.g., via a username or cookie, verify that the identified
  -- user is the owner of credentialSource. If response.userHandle is present,
  -- let userHandle be its value. Verify that userHandle also maps to the same
  -- user.
  --
  -- -> If the user was not identified before the authentication ceremony was
  -- initiated, verify that response.userHandle is present, and that the user
  -- identified by this value is the owner of credentialSource.
  case (mauthenticatedUser, M.argUserHandle response) of
    (Just authenticatedUser, Just userHandle)
      | authenticatedUser /= credentialOwner ->
        throwError $ VerificationErrorAuthenticatedUserHandleMismatch authenticatedUser credentialOwner
      | userHandle /= credentialOwner ->
        throwError $ VerificationErrorCredentialUserHandleMismatch userHandle credentialOwner
      | otherwise -> pure ()
    (Just authenticatedUser, Nothing)
      | authenticatedUser /= credentialOwner ->
        throwError $ VerificationErrorAuthenticatedUserHandleMismatch authenticatedUser credentialOwner
      | otherwise -> pure ()
    (Nothing, Just userHandle)
      | userHandle /= credentialOwner ->
        throwError $ VerificationErrorCredentialUserHandleMismatch userHandle credentialOwner
      | otherwise -> pure ()
    (Nothing, Nothing) ->
      throwError VerificationErrorCannotVerifyUserHandle

  -- 7. Using credential.id (or credential.rawId, if base64url encoding is
  -- inappropriate for your use case), look up the corresponding credential
  -- public key and let credentialPublicKey be that credential public key.
  -- Note: Done with lookupCredential above

  -- 8. Let cData, authData and sig denote the value of response’s
  -- clientDataJSON, authenticatorData, and signature respectively.
  let M.AuthenticatorAssertionResponse
        { M.argClientData = c,
          M.argAuthenticatorData = authData,
          M.argSignature = sig
        } = response

  -- 9. Let JSONtext be the result of running UTF-8 decode on the value of
  -- cData.
  -- Note: Done as part of decoding

  -- 10. Let C, the client data claimed as used for the signature, be the
  -- result of running an implementation-specific JSON parser on JSONtext.
  -- Note: Done as part of decoding

  -- 11. Verify that the value of C.type is the string webauthn.get.
  -- Note: Done as part of decoding

  -- 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
  unless (M.ccdChallenge c == M.pkcogChallenge options) $
    throwError $ VerificationErrorChallengeMismatch (M.ccdChallenge c) (M.pkcogChallenge options)

  -- 13. Verify that the value of C.origin matches the Relying Party's origin.
  unless (M.ccdOrigin c == origin) $
    throwError $ VerificationErrorOriginMismatch (M.ccdOrigin c) origin

  -- 14. Verify that the value of C.tokenBinding.status matches the state of
  -- Token Binding for the TLS connection over which the attestation was
  -- obtained. If Token Binding was used on that TLS connection, also verify
  -- that C.tokenBinding.id matches the base64url encoding of the Token
  -- Binding ID for the connection.
  -- TODO

  -- 15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
  -- expected by the Relying Party.
  -- Note: If using the appid extension, this step needs some special logic.
  -- See § 10.1 FIDO AppID Extension (appid) for details.
  unless (M.adRpIdHash authData == rpIdHash) $
    throwError $ VerificationErrorRpIdHashMismatch (M.adRpIdHash authData) rpIdHash

  -- 16. Verify that the User Present bit of the flags in authData is set.
  unless (M.adfUserPresent (M.adFlags authData)) $
    throwError VerificationErrorUserNotPresent

  -- 17. If user verification is required for this assertion, verify that the
  -- User Verified bit of the flags in authData is set.
  -- Note: The spec is interpreted to mean that the userVerification option
  -- being set to "required" is what is meant by whether user verification is
  -- required
  case (M.pkcogUserVerification options, M.adfUserVerified (M.adFlags authData)) of
    (M.UserVerificationRequirementRequired, True) -> pure ()
    (M.UserVerificationRequirementRequired, False) -> throwError VerificationErrorUserNotVerified
    (M.UserVerificationRequirementPreferred, True) -> pure ()
    (M.UserVerificationRequirementPreferred, False) ->
      -- TODO: Maybe throw warning that user verification was preferred but not provided
      pure ()
    (M.UserVerificationRequirementDiscouraged, True) ->
      -- TODO: Maybe throw warning that user verification was discouraged but provided
      pure ()
    (M.UserVerificationRequirementDiscouraged, False) -> pure ()

  -- 18. Verify that the values of the client extension outputs in
  -- clientExtensionResults and the authenticator extension outputs in the
  -- extensions in authData are as expected, considering the client extension
  -- input values that were given in options.extensions and any specific policy
  -- of the Relying Party regarding unsolicited extensions, i.e., those that
  -- were not specified as part of options.extensions. In the general case,
  -- the meaning of "are as expected" is specific to the Relying Party and
  -- which extensions are in use.
  -- TODO

  -- 19. Let hash be the result of computing a hash over the cData using SHA-256.
  -- Note: Done during decoding, since it relies on the specific serialization
  -- used
  let hash = convert (M.unClientDataHash (M.ccdHash c))

  -- 20. Using credentialPublicKey, verify that sig is a valid signature over
  -- the binary concatenation of authData and hash.
  let message = M.adRawData authData <> hash
  unless (PublicKey.verify credentialPublicKey message (M.unAssertionSignature sig)) $
    throwError $ VerificationErrorInvalidSignature credentialPublicKey message sig

  -- 21. Let storedSignCount be the stored signature counter value associated
  -- with credential.id. If authData.signCount is nonzero or storedSignCount
  -- is nonzero, then run the following sub-step:
  -- - If authData.signCount is
  --   -> greater than storedSignCount:
  --      Update storedSignCount to be the value of authData.signCount.
  --   -> less than or equal to storedSignCount:
  --      This is a signal that the authenticator may be cloned, i.e. at least
  --      two copies of the credential private key may exist and are being
  --      used in parallel. Relying Parties should incorporate this information
  --      into their risk scoring. Whether the Relying Party updates
  --      storedSignCount in this case, or not, or fails the authentication
  --      ceremony or not, is Relying Party-specific.
  when (M.adSignCount authData /= 0 || storedSignCount /= 0) $
    if M.adSignCount authData > storedSignCount
      then undefined
      else undefined

  undefined
