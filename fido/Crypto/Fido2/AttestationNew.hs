{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.AttestationNew (AttestationError, verifyAttestationResponse) where

import Control.Exception.Base (SomeException (SomeException))
import Control.Monad (unless, when)
import Crypto.Fido2.Error (CommonError (ChallengeMismatch, CryptoAlgorithmUnsupported, RpIdHashMismatch, RpOriginMismatch, UserNotPresent, UserNotVerified))
import Crypto.Fido2.Model
  ( AttestationObject (AttestationObject, aoAttStmt, aoAuthData, aoFmt),
    AttestationStatementFormat (asfVerify),
    AttestedCredentialData (AttestedCredentialData, acdCredentialPublicKey),
    AuthenticatorData (AuthenticatorData, adAttestedCredentialData, adFlags, adRpIdHash),
    AuthenticatorDataFlags (adfUserPresent, adfUserVerified),
    AuthenticatorResponse
      ( AuthenticatorAttestationResponse,
        arcAttestationObject,
        arcClientData
      ),
    CollectedClientData (ccdChallenge, ccdHash, ccdOrigin),
    Origin,
    PublicKeyCredentialOptions (PublicKeyCredentialCreationOptions, pkcocChallenge, pkcocPubKeyCredParams),
    PublicKeyCredentialParameters (pkcpAlg),
    RpId (unRpId),
    RpIdHash (unRpIdHash),
    UserVerificationRequirement (UserVerificationRequirementRequired),
    WebauthnType (Create),
  )
import Crypto.Fido2.PublicKey (keyAlgorithm)
import qualified Crypto.Hash as Hash
import Data.Bifunctor (first)
import qualified Data.Text.Encoding as Text

data AttestationError
  = -- | A common error occured during attestation
    AttestationCommonError CommonError
  | AttestationFormatError SomeException

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- This function implements step 8 - 24 of the spec, step 1-7 are done
-- either by the server or ensured by the typesystem during decoding.
verifyAttestationResponse ::
  Origin ->
  RpId ->
  PublicKeyCredentialOptions 'Create ->
  UserVerificationRequirement ->
  AuthenticatorResponse 'Create ->
  Either AttestationError ()
verifyAttestationResponse
  rpOrigin
  rpId
  PublicKeyCredentialCreationOptions {pkcocChallenge, pkcocPubKeyCredParams}
  userVerificationRequirement
  AuthenticatorAttestationResponse
    { arcClientData,
      arcAttestationObject =
        AttestationObject
          { aoAuthData = aoAuthData@AuthenticatorData {adAttestedCredentialData = AttestedCredentialData {..}, ..},
            ..
          }
    } = do
    -- 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
    when (ccdChallenge arcClientData /= pkcocChallenge) . Left $ AttestationCommonError ChallengeMismatch

    -- 9. Verify that the value of C.origin matches the Relying Party's origin.
    when (ccdOrigin arcClientData /= rpOrigin) . Left $ AttestationCommonError RpOriginMismatch

    -- 10. Verify that the value of C.tokenBinding.status matches the state of Token
    -- Binding for the TLS connection over which the assertion was obtained. If
    -- Token Binding was used on that TLS connection, also verify that
    -- C.tokenBinding.id matches the base64url encoding of the Token Binding ID for
    -- the connection.
    -- TODO: Token binding is not currently supported.

    -- 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
    -- NOTE: This was already done, and is a field of the CollectedClientData, see step 17

    -- 12. Perform CBOR decoding on the attestationObject field of the
    -- AuthenticatorAttestationResponse structure to obtain the attestation
    -- statement format fmt, the authenticator data authData, and the attestation
    -- statement attStmt.
    -- NOTE: Already matched in the function patternmatch

    -- 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
    when (Hash.hash (Text.encodeUtf8 $ unRpId rpId) /= unRpIdHash adRpIdHash) . Left $ AttestationCommonError RpIdHashMismatch

    -- 14. Verify that the User Present bit of the flags in authData is set.
    unless (adfUserPresent adFlags) . Left $ AttestationCommonError UserNotPresent

    -- 15. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
    when (userVerificationRequirement == UserVerificationRequirementRequired && not (adfUserVerified adFlags)) . Left $ AttestationCommonError UserNotVerified

    -- 16. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
    -- TODO: Remove undefined when the CoseAlgorithmIdentifiers have been unified
    unless (undefined keyAlgorithm acdCredentialPublicKey `elem` map pkcpAlg pkcocPubKeyCredParams) . Left $ AttestationCommonError CryptoAlgorithmUnsupported

    -- 17. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the
    -- extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific
    -- policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general
    -- case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
    -- TODO: Extensions aren't currently implemented

    -- 18. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported
    -- WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier
    -- values is maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
    -- NOTE: This check is done during decoding and enforced by the type-system

    -- 19. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
    -- by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
    _attType <- first (AttestationFormatError . SomeException) $ asfVerify aoFmt aoAttStmt aoAuthData (ccdHash arcClientData)

    -- 20. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt,
    -- from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
    -- using the aaguid in the attestedCredentialData in authData.
    -- TODO: The metadata service is not currently implemented

    -- 21. Assess the attestation trustworthiness using the outputs of the verification procedure in step 19, as follows:
    --
    -- -   If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
    -- -   If self attestation was used, verify that self attestation is acceptable under Relying Party policy.
    -- -   Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure
    --     to verify that the attestation public key either correctly chains up to an acceptable root certificate,
    --     or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step 20 may be the same).
    -- TODO: A policy is not currently implement, as is the metadata service.

    -- TODO: This function should result in the trustworthiness of the attestation.
    pure ()
