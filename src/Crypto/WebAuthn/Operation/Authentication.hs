{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}

-- | Stability: experimental
-- This module implements assertion of the received authenticator response.
-- See the WebAuthn
-- [specification](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
-- for the algorithm implemented in this module.
-- Assertion is typically represented as a "login" or "authentication" action
-- in the front-end.
-- [Section 7 of the specification](https://www.w3.org/TR/webauthn-2/#sctn-rp-operations)
-- describes when the relying party must perform assertion. Another relevant
-- section is
-- [Section 1.3.3](https://www.w3.org/TR/webauthn-2/#sctn-sample-authentication)
-- which is a high level overview of the authentication procedure.
module Crypto.WebAuthn.Operation.Authentication
  ( verifyAuthenticationResponse,
    AuthenticationError (..),
    AuthenticationResult (..),
    SignatureCounterResult (..),
  )
where

import qualified Codec.CBOR.Read as CBOR
import Codec.Serialise (decode)
import Control.Exception (Exception)
import Control.Monad (unless)
import qualified Crypto.Hash as Hash
import qualified Crypto.WebAuthn.Cose.Internal.Verify as Cose
import Crypto.WebAuthn.Internal.Utils (failure)
import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.Operation.CredentialEntry (CredentialEntry (cePublicKeyBytes, ceSignCounter, ceUserHandle))
import Data.ByteArray (convert)
import qualified Data.ByteString.Lazy as LBS
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import Data.Validation (Validation)
import qualified Data.List.NonEmpty as NonEmpty

-- | Errors that may occur during [assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
data AuthenticationError
  = -- | The provided Credential was not one explicitly allowed by the server
    AuthenticationCredentialDisallowed
      { -- | The credentials allowed by the server
        aeAllowedCredentials :: [M.CredentialDescriptor],
        -- | The credential returned by the client
        aeReceivedCredential :: M.Credential 'M.Authentication 'True
      }
  | -- | The received credential does not match the currently identified user
    AuthenticationIdentifiedUserHandleMismatch
      { -- | The `M.UserHandle` of the user who is attempting authentication
        aeIdentifiedUser :: M.UserHandle,
        -- | The owner of the credential passed to the
        -- `verifyAuthenticationResponse` function (retrieved from the
        -- database)
        aeRegisteredUser :: M.UserHandle
      }
  | -- | The stored credential does not match the user specified in the
    -- response
    AuthenticationCredentialUserHandleMismatch
      { -- | The `M.UserHandle` of the user who is attempting authentication
        aeIdentifiedUser :: M.UserHandle,
        -- | The `M.UserHandle` reported by the authenticator in the response
        aeAuthenticatorUser :: M.UserHandle
      }
  | -- | No user was identified and the response did not specify a user
    AuthenticationCannotVerifyUserHandle
  | -- | The received challenge does not match the originally created
    -- challenge
    AuthenticationChallengeMismatch
      { -- | The challenge created by the relying party and part of the
        -- `M.CredentialOptions`
        aeCreatedChallenge :: M.Challenge,
        -- | The challenge received from the client, part of the response
        aeReceivedChallenge :: M.Challenge
      }
  | -- | The origin derived by the client does match the assumed origin
    AuthenticationOriginMismatch
      { -- | The origin explicitly passed to the `verifyAuthenticationResponse`
        -- response, set by the RP
        aeExpectedOrigin :: NonEmpty.NonEmpty M.Origin,
        -- | The origin received from the client as part of the client data
        aeReceivedOrigin :: M.Origin
      }
  | -- | The rpIdHash in the authData is not a valid hash over the RpId
    -- expected by the Relying party
    AuthenticationRpIdHashMismatch
      { -- | The RP ID hash explicitly passed to the
        -- `verifyAuthenticationResponse` response, set by the RP
        aeExpectedRpIdHash :: M.RpIdHash,
        -- | The RP ID hash received from the client as part of the authenticator
        -- data
        aeReceivedRpIdHash :: M.RpIdHash
      }
  | -- | The UserPresent bit was not set in the authData
    AuthenticationUserNotPresent
  | -- | The UserVerified bit was not set in the authData while user
    -- verification was required
    AuthenticationUserNotVerified
  | -- | The public key provided in the 'CredentialEntry' could not be decoded
    AuthenticationSignatureDecodingError CBOR.DeserialiseFailure
  | -- | The public key doesn't verify the signature over the authData
    AuthenticationSignatureInvalid Text
  deriving (Show, Exception)

-- | [Section 6.1.1 of the specification](https://www.w3.org/TR/webauthn-2/#sctn-sign-counter)
-- describes the use of the signature counter, and describes what the relying
-- part must do with them. In particular:
--
-- The [signature counter](https://www.w3.org/TR/webauthn-2/#signature-counter)
-- 's purpose is to aid
-- [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) in
-- detecting cloned authenticators. Clone detection is more important for
-- authenticators with limited protection measures.
--
-- A [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) stores
-- the [signature counter](https://www.w3.org/TR/webauthn-2/#signature-counter)
-- of the most recent
-- [authenticatorGetAssertion](https://www.w3.org/TR/webauthn-2/#authenticatorgetassertion)
-- operation. (Or the counter from the
-- [authenticatorMakeCredential](https://www.w3.org/TR/webauthn-2/#authenticatormakecredential)
-- operation if no
-- [authenticatorGetAssertion](https://www.w3.org/TR/webauthn-2/#authenticatorgetassertion)
-- has ever been performed on a credential.) In subsequent
-- [authenticatorGetAssertion](https://www.w3.org/TR/webauthn-2/#authenticatorgetassertion)
-- operations, the
-- [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party) compares
-- the stored
-- [signature counter](https://www.w3.org/TR/webauthn-2/#signature-counter)
-- value with the new
-- `[signCount](https://www.w3.org/TR/webauthn-2/#signcount)` value returned in
-- the assertion’s
-- [authenticator data](https://www.w3.org/TR/webauthn-2/#authenticator-data).
-- If either is non-zero, and the new
-- `[signCount](https://www.w3.org/TR/webauthn-2/#signcount)` value is less
-- than or equal to the stored value, a cloned authenticator may exist, or the
-- authenticator may be malfunctioning.
data SignatureCounterResult
  = -- | There is no signature counter being used, the database entry doesn't
    -- need to be updated, but we also have no guarantees about the
    -- authenticator not being cloned
    SignatureCounterZero
  | -- | The signature counter needs to be updated in the database
    SignatureCounterUpdated M.SignatureCounter
  | -- | The signature counter decreased, the authenticator was potentially
    -- cloned and the relying party may want to e.g. lock this credential
    SignatureCounterPotentiallyCloned
  deriving (Eq, Show)

-- | A successful result of 'verifyAuthenticationResponse', it should be inspected by the Relying Party to enforce its policy regarding logins.
newtype AuthenticationResult = AuthenticationResult
  { -- | How the signature counter of the credential changed compared to the
    -- existing database entry
    arSignatureCounterResult :: SignatureCounterResult
  }
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
-- Verifies a 'M.Credential' response for an [authentication ceremony](https://www.w3.org/TR/webauthn-2/#authentication).
--
-- The 'arSignatureCounterResult' field of the result should be inspected to
-- enforce Relying Party policy regarding potentially cloned authenticators.
--
-- Though this library implements the WebAuthn L2 spec, for origin validation we
-- follow the L3 draft. This is because allowing multiple origins is often
-- needed in the wild. See [Validating the origin of a credential](https://www.w3.org/tr/webauthn-3/#sctn-validating-origin) 
-- more details.
-- In the simplest case, just a single origin is allowed and this is the 'M.RpId' with @https://@ prepended:
--
-- > verifyAuthenticationResponse (NonEmpty.singleton (M.Origin "https://example.org")) ...
--
-- In the more complex case, multiple origins are allowed:
--
-- > verifyAuthenticationResponse (M.Origin <$> "https://example.org" :| ["https://signin.example.org"]) ...
--
-- One might also allow native apps to authenticate:
--
-- > verifyAuthenticationResponse (M.Origin <$> "https://example.org" :| ["ios:bundle-id:org.example.ourapp"]) ...
--
-- See Apple's documentation on [associated domains](https://developer.apple.com/documentation/authenticationservices/public-private_key_authentication/supporting_passkeys/)
-- and Google's documentation on [Digital Asset Links](https://developers.google.com/identity/passkeys/developer-guides) for more information on how to link app
-- origins to your Relying Party ID.
verifyAuthenticationResponse ::
  -- | The list of allowed origins for the ceremony
  NonEmpty.NonEmpty M.Origin ->
  -- | The hash of the relying party id
  M.RpIdHash ->
  -- | The user handle, in case the user is identified already
  -- TODO: Mention that this would be empty for username-less authentication
  Maybe M.UserHandle ->
  -- | The database entry for the credential, as created in the initial
  -- attestation and optionally updated in subsequent assertions
  CredentialEntry ->
  -- | The options that were passed to the get() method
  M.CredentialOptions 'M.Authentication ->
  -- | The credential returned from get()
  M.Credential 'M.Authentication 'True ->
  -- | Either a non-empty list of validation errors in case of the assertion
  -- being invalid
  -- Or in case of success a signature counter result, which should be dealt
  -- with
  Validation (NonEmpty AuthenticationError) AuthenticationResult
verifyAuthenticationResponse origins rpIdHash midentifiedUser entry options credential = do
  -- 1. Let options be a new PublicKeyCredentialRequestOptions structure
  -- configured to the Relying Party's needs for the ceremony.
  -- NOTE: Implemented by caller
  -- If options.allowCredentials is present, the transports member of each
  -- item SHOULD be set to the value returned by
  -- credential.response.getTransports() when the corresponding credential was
  -- registered.
  -- TODO: The transports property is currently not propagated by webauthn-json.
  -- see: <https://github.com/github/webauthn-json/pull/44>

  -- 2. Call navigator.credentials.get() and pass options as the publicKey
  -- option. Let credential be the result of the successfully resolved promise.
  -- If the promise is rejected, abort the ceremony with a user-visible error,
  -- or otherwise guide the user experience as might be determinable from the
  -- context available in the rejected promise. For information on different
  -- error contexts and the circumstances leading to them, see § 6.3.3 The
  -- authenticatorGetAssertion Operation.
  -- NOTE: Implemented by caller

  -- 3. Let response be credential.response. If response is not an instance of
  -- AuthenticatorAssertionResponse, abort the ceremony with a user-visible
  -- error.
  -- NOTE: Already done as part of decoding
  let response = M.cResponse credential

  -- 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.

  -- 5. If options.allowCredentials is not empty, verify that credential.id
  -- identifies one of the public key credentials listed in
  -- options.allowCredentials.
  let allowCredentials = M.coaAllowCredentials options
  unless
    (null allowCredentials || M.cIdentifier credential `elem` map M.cdId allowCredentials)
    . failure
    $ AuthenticationCredentialDisallowed allowCredentials credential

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
  let owner = ceUserHandle entry

  -- According to the [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id)
  -- The user handle MUST NOT be empty, though it MAY be null.
  -- For clarification see https://github.com/w3c/webauthn/issues/1722
  -- However, Safari returns an empty string instead of null, see the bug report:
  -- https://bugs.webkit.org/show_bug.cgi?id=239737
  let mUserHandler = case M.araUserHandle response of
        Just (M.UserHandle "") -> Nothing
        userHandle -> userHandle

  case (midentifiedUser, mUserHandler) of
    (Just identifiedUser, Just userHandle)
      | identifiedUser /= owner ->
          failure $ AuthenticationIdentifiedUserHandleMismatch identifiedUser owner
      | userHandle /= owner ->
          failure $ AuthenticationCredentialUserHandleMismatch userHandle owner
      | otherwise -> pure ()
    (Just identifiedUser, Nothing)
      | identifiedUser /= owner ->
          failure $ AuthenticationIdentifiedUserHandleMismatch identifiedUser owner
      | otherwise -> pure ()
    (Nothing, Just userHandle)
      | userHandle /= owner ->
          failure $ AuthenticationCredentialUserHandleMismatch userHandle owner
      | otherwise -> pure ()
    (Nothing, Nothing) ->
      failure AuthenticationCannotVerifyUserHandle

  -- 7. Using credential.id (or credential.rawId, if base64url encoding is
  -- inappropriate for your use case), look up the corresponding credential
  -- public key and let credentialPublicKey be that credential public key.
  -- NOTE: Done by the caller, passed with entry

  -- 8. Let cData, authData and sig denote the value of response’s
  -- clientDataJSON, authenticatorData, and signature respectively.
  let M.AuthenticatorResponseAuthentication
        { M.araClientData = c,
          M.araAuthenticatorData = authData@M.AuthenticatorData {M.adRawData = M.WithRaw rawData},
          M.araSignature = sig
        } = response

  -- 9. Let JSONtext be the result of running UTF-8 decode on the value of
  -- cData.
  -- NOTE: Done as part of decoding

  -- 10. Let C, the client data claimed as used for the signature, be the
  -- result of running an implementation-specific JSON parser on JSONtext.
  -- NOTE: Done as part of decoding

  -- 11. Verify that the value of C.type is the string webauthn.get.
  -- NOTE: Done as part of decoding

  -- 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
  unless (M.ccdChallenge c == M.coaChallenge options) $
    failure $
      AuthenticationChallengeMismatch (M.coaChallenge options) (M.ccdChallenge c)

  -- 13. Verify that the value of C.origin matches the Relying Party's origin.
  -- NOTE: We follow the L3 draft of the spec here, which allows for multiple origins.
  -- https://www.w3.org/TR/webauthn-3/#sctn-validating-origin
  unless (M.ccdOrigin c `elem` NonEmpty.toList origins) $
    failure $
      AuthenticationOriginMismatch origins (M.ccdOrigin c)

  -- 14. Verify that the value of C.tokenBinding.status matches the state of
  -- Token Binding for the TLS connection over which the attestation was
  -- obtained. If Token Binding was used on that TLS connection, also verify
  -- that C.tokenBinding.id matches the base64url encoding of the Token
  -- Binding ID for the connection.
  -- TODO: We do not implement TokenBinding, see the documentation of
  -- `CollectedClientData` for more information.

  -- 15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
  -- expected by the Relying Party.
  -- Note: If using the appid extension, this step needs some special logic.
  -- See § 10.1 FIDO AppID Extension (appid) for details.
  unless (M.adRpIdHash authData == rpIdHash) $
    failure $
      AuthenticationRpIdHashMismatch rpIdHash (M.adRpIdHash authData)

  -- 16. Verify that the User Present bit of the flags in authData is set.
  unless (M.adfUserPresent (M.adFlags authData)) $
    failure AuthenticationUserNotPresent

  -- 17. If user verification is required for this assertion, verify that the
  -- User Verified bit of the flags in authData is set.
  -- NOTE: The spec is interpreted to mean that the userVerification option
  -- being set to "required" is what is meant by whether user verification is
  -- required
  case ( M.coaUserVerification options,
         M.adfUserVerified (M.adFlags authData)
       ) of
    (M.UserVerificationRequirementRequired, True) -> pure ()
    (M.UserVerificationRequirementRequired, False) -> failure AuthenticationUserNotVerified
    (M.UserVerificationRequirementPreferred, True) -> pure ()
    (M.UserVerificationRequirementPreferred, False) -> pure ()
    (M.UserVerificationRequirementDiscouraged, True) -> pure ()
    (M.UserVerificationRequirementDiscouraged, False) -> pure ()

  -- 18. Verify that the values of the client extension outputs in
  -- clientExtensionResults and the authenticator extension outputs in the
  -- extensions in authData are as expected, considering the client extension
  -- input values that were given in options.extensions and any specific policy
  -- of the Relying Party regarding unsolicited extensions, i.e., those that
  -- were not specified as part of options.extensions. In the general case,
  -- the meaning of "are as expected" is specific to the Relying Party and
  -- which extensions are in use.
  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.

  -- 19. Let hash be the result of computing a hash over the cData using SHA-256.
  -- NOTE: Done on raw data from decoding so that we don't need to encode again
  -- here and so that we use the exact some serialization
  let hash = M.ClientDataHash $ Hash.hash $ M.unRaw $ M.ccdRawData c

  -- 20. Using credentialPublicKey, verify that sig is a valid signature over
  -- the binary concatenation of authData and hash.
  let pubKeyBytes = LBS.fromStrict $ M.unPublicKeyBytes $ cePublicKeyBytes entry
      message = Cose.Message $ rawData <> convert (M.unClientDataHash hash)
  case CBOR.deserialiseFromBytes decode pubKeyBytes of
    Left err -> failure $ AuthenticationSignatureDecodingError err
    Right (_, coseKey) ->
      case Cose.verify coseKey message (Cose.Signature $ M.unAssertionSignature sig) of
        Right () -> pure ()
        Left err -> failure $ AuthenticationSignatureInvalid err

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
  signCountResult <- case (M.adSignCount authData, ceSignCounter entry) of
    (0, 0) -> pure SignatureCounterZero
    (returned, stored)
      | returned > stored -> pure $ SignatureCounterUpdated returned
      | otherwise -> pure SignatureCounterPotentiallyCloned

  -- 22. If all the above steps are successful, continue with the
  -- authentication ceremony as appropriate. Otherwise, fail the
  -- authentication ceremony.
  pure $
    AuthenticationResult
      { arSignatureCounterResult = signCountResult
      }
