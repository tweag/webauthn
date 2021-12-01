{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Operations.Attestation (AttestationError, verifyAttestationResponse, allSupportedFormats) where

import Control.Exception.Base (SomeException (SomeException))
import Control.Monad (unless)
import Crypto.Fido2.Model (SupportedAttestationStatementFormats, sasfSingleton)
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Operations.Attestation.AndroidKey as AndroidKey
import qualified Crypto.Fido2.Operations.Attestation.Apple as Apple
import qualified Crypto.Fido2.Operations.Attestation.FidoU2F as FidoU2F
import qualified Crypto.Fido2.Operations.Attestation.None as None
import qualified Crypto.Fido2.Operations.Attestation.Packed as Packed
import Crypto.Fido2.Operations.Common (CredentialEntry (CredentialEntry, ceCredentialId, cePublicKeyBytes, ceSignCounter, ceUserHandle), failure)
import qualified Crypto.Fido2.PublicKey as PublicKey
import qualified Crypto.Hash as Hash
import Data.List.NonEmpty (NonEmpty)
import Data.Validation (Validation, liftError)

allSupportedFormats :: SupportedAttestationStatementFormats
allSupportedFormats =
  foldMap
    sasfSingleton
    [ None.format,
      Packed.format,
      AndroidKey.format,
      FidoU2F.format,
      Apple.format
    ]

data AttestationError
  = -- | The returned challenge does not match the desired one
    AttestationChallengeMismatch M.Challenge M.Challenge
  | -- | The returned origin does not match the relying party's origin
    AttestationOriginMismatch M.Origin M.Origin
  | -- | The hash of the relying party id does not match the has in the returned authentication data
    AttestationRpIdHashMismatch M.RpIdHash M.RpIdHash
  | -- | The userpresent bit in the authdata was not set
    AttestationUserNotPresent
  | -- | The userverified bit in the authdata was not set
    AttestationUserNotVerified
  | -- | TODO: Fix this description
    -- The desired algorithm is not supported by this implementation or by the fido2 specification
    AttestationUndesiredPublicKeyAlgorithm PublicKey.COSEAlgorithmIdentifier [PublicKey.COSEAlgorithmIdentifier]
  | -- | There was some exception in the statement format specific section
    AttestationFormatError SomeException
  deriving (Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- This function implements step 8 - 21 of the spec, step 1-7 are done
-- either by the server or ensured by the typesystem during decoding.
verifyAttestationResponse ::
  -- | The origin of the server
  M.Origin ->
  -- | The relying party id
  M.RpIdHash ->
  -- | The options passed to the create() method
  M.PublicKeyCredentialOptions 'M.Create ->
  -- | The response from the authenticator
  M.PublicKeyCredential 'M.Create 'True ->
  -- | Either a nonempty list of validation errors in case the attestation FailedReason
  -- Or () in case of a result.
  Validation (NonEmpty AttestationError) CredentialEntry
verifyAttestationResponse
  rpOrigin
  rpIdHash
  options@M.PublicKeyCredentialCreationOptions {pkcocChallenge, pkcocPubKeyCredParams}
  credential@M.PublicKeyCredential
    { M.pkcResponse =
        M.AuthenticatorAttestationResponse
          { arcClientData = c,
            arcAttestationObject =
              M.AttestationObject
                { aoAuthData = authData@M.AuthenticatorData {adAttestedCredentialData = M.AttestedCredentialData {..}},
                  ..
                }
          }
    } = do
    -- 1. Let options be a new PublicKeyCredentialCreationOptions structure
    -- configured to the Relying Party's needs for the ceremony.
    -- NOTE: Implemented by caller

    -- 2. Call navigator.credentials.create() and pass options as the publicKey
    -- option. Let credential be the result of the successfully resolved
    -- promise. If the promise is rejected, abort the ceremony with a
    -- user-visible error, or otherwise guide the user experience as might be
    -- determinable from the context available in the rejected promise. For
    -- example if the promise is rejected with an error code equivalent to
    -- "InvalidStateError", the user might be instructed to use a different
    -- authenticator. For information on different error contexts and the
    -- circumstances leading to them, see § 6.3.2 The
    -- authenticatorMakeCredential Operation.
    -- NOTE: Implemented by caller

    -- 3. Let response be credential.response. If response is not an instance
    -- of AuthenticatorAttestationResponse, abort the ceremony with a
    -- user-visible error.
    -- NOTE: Already done as part of decoding

    -- 4. Let clientExtensionResults be the result of calling
    -- credential.getClientExtensionResults().
    -- TODO: Implement extensions

    -- 5. Let JSONtext be the result of running UTF-8 decode on the value of
    -- response.clientDataJSON.
    -- NOTE: Done as part of decoding

    -- 6. Let C, the client data claimed as collected during the credential
    -- creation, be the result of running an implementation-specific JSON
    -- parser on JSONtext.
    -- NOTE: Done as part of decoding

    -- 7. Verify that the value of C.type is webauthn.create.
    -- NOTE: Done as part of decoding

    -- 8. Verify that the value of C.challenge equals the base64url encoding of
    -- options.challenge.
    unless (M.ccdChallenge c == pkcocChallenge) $
      failure $ AttestationChallengeMismatch (M.ccdChallenge c) pkcocChallenge

    -- 9. Verify that the value of C.origin matches the Relying Party's origin.
    unless (M.ccdOrigin c == rpOrigin) $
      failure $ AttestationOriginMismatch (M.ccdOrigin c) rpOrigin

    -- 10. Verify that the value of C.tokenBinding.status matches the state of
    -- Token Binding for the TLS connection over which the assertion was
    -- obtained. If Token Binding was used on that TLS connection, also verify
    -- that C.tokenBinding.id matches the base64url encoding of the Token
    -- Binding ID for the connection.
    -- TODO: Token binding is not currently supported.

    -- 11. Let hash be the result of computing a hash over
    -- response.clientDataJSON using SHA-256.
    -- NOTE: Done on raw data from decoding so that we don't need to encode again
    -- here and so that we use the exact some serialization
    let hash = M.ClientDataHash $ Hash.hash $ M.unRaw $ M.ccdRawData c

    -- 12. Perform CBOR decoding on the attestationObject field of the
    -- AuthenticatorAttestationResponse structure to obtain the attestation
    -- statement format fmt, the authenticator data authData, and the attestation
    -- statement attStmt.
    -- NOTE: Already done as part of decoding

    -- 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP
    -- ID expected by the Relying Party.
    unless (M.adRpIdHash authData == rpIdHash) $
      failure $ AttestationRpIdHashMismatch (M.adRpIdHash authData) rpIdHash

    -- 14. Verify that the User Present bit of the flags in authData is set.
    unless (M.adfUserPresent (M.adFlags authData)) $
      failure AttestationUserNotPresent

    -- 15. If user verification is required for this registration, verify that
    -- the User Verified bit of the flags in authData is set.
    -- NOTE: The spec is interpreted to mean that the userVerification option
    -- from authenticatorSelection being set to "required" is what is meant by
    -- whether user verification is required
    case ( M.ascUserVerification <$> M.pkcocAuthenticatorSelection options,
           M.adfUserVerified (M.adFlags authData)
         ) of
      (Nothing, _) -> pure ()
      (Just M.UserVerificationRequirementRequired, True) -> pure ()
      (Just M.UserVerificationRequirementRequired, False) -> failure AttestationUserNotVerified
      (Just M.UserVerificationRequirementPreferred, True) -> pure ()
      -- TODO: Maybe throw warning that user verification was preferred but not provided
      (Just M.UserVerificationRequirementPreferred, False) -> pure ()
      -- TODO: Maybe throw warning that user verification was discouraged but provided
      (Just M.UserVerificationRequirementDiscouraged, True) -> pure ()
      (Just M.UserVerificationRequirementDiscouraged, False) -> pure ()

    -- 16. Verify that the "alg" parameter in the credential public key in
    -- authData matches the alg attribute of one of the items in
    -- options.pubKeyCredParams.
    let acdAlg = PublicKey.toCOSEAlgorithmIdentifier acdCredentialPublicKey
        desiredAlgs = map M.pkcpAlg pkcocPubKeyCredParams
    unless (acdAlg `elem` desiredAlgs) $
      failure $ AttestationUndesiredPublicKeyAlgorithm acdAlg desiredAlgs

    -- 17. Verify that the values of the client extension outputs in
    -- clientExtensionResults and the authenticator extension outputs in the
    -- extensions in authData are as expected, considering the client extension
    -- input values that were given in options.extensions and any specific
    -- policy of the Relying Party regarding unsolicited extensions, i.e.,
    -- those that were not specified as part of options.extensions. In the
    -- general case, the meaning of "are as expected" is specific to the
    -- Relying Party and which extensions are in use.
    -- TODO: Extensions aren't currently implemented

    -- 18. Determine the attestation statement format by performing a USASCII
    -- case-sensitive match on fmt against the set of supported WebAuthn
    -- Attestation Statement Format Identifier values. An up-to-date list of
    -- registered WebAuthn Attestation Statement Format Identifier values is
    -- maintained in the IANA "WebAuthn Attestation Statement Format Identifiers"
    -- registry [IANA-WebAuthn-Registries] established by [RFC8809].
    -- NOTE: This check is done during decoding and enforced by the type-system

    -- 19. Verify that attStmt is a correct attestation statement, conveying a
    -- valid attestation signature, by using the attestation statement format
    -- fmt’s verification procedure given attStmt, authData and hash.
    _attType <-
      liftError (pure . AttestationFormatError . SomeException) $
        M.asfVerify aoFmt aoAttStmt authData hash

    -- 20. If validation is successful, obtain a list of acceptable trust
    -- anchors (i.e. attestation root certificates) for that attestation type
    -- and attestation statement format fmt, from a trusted source or from
    -- policy. For example, the FIDO Metadata Service [FIDOMetadataService]
    -- provides one way to obtain such information, using the aaguid in the
    -- attestedCredentialData in authData.
    -- TODO: The metadata service is not currently implemented

    -- 21. Assess the attestation trustworthiness using the outputs of the
    -- verification procedure in step 19, as follows:
    --
    -- -> If no attestation was provided, verify that None attestation is
    --    acceptable under Relying Party policy.
    -- -> If self attestation was used, verify that self attestation is
    --    acceptable under Relying Party policy.
    -- -> Otherwise, use the X.509 certificates returned as the attestation
    --    trust path from the verification procedure to verify that the
    --    attestation public key either correctly chains up to an acceptable
    --    root certificate, or is itself an acceptable certificate (i.e., it
    --    and the root certificate obtained in Step 20 may be the same).
    -- TODO: A policy is not currently implement, as is the metadata service.

    -- TODO: This function should result in the trustworthiness of the attestation.
    -- NOTE: Further steps of the procedure are handled by the server side
    pure $
      CredentialEntry
        { ceUserHandle = M.pkcueId $ M.pkcocUser options,
          ceCredentialId = M.pkcIdentifier credential,
          cePublicKeyBytes = M.PublicKeyBytes $ M.unRaw acdCredentialPublicKeyBytes,
          ceSignCounter = M.adSignCount authData
        }
