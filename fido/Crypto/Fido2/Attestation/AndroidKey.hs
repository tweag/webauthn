{-# LANGUAGE NamedFieldPuns #-}

-- | Implements step 2-6 of the verification procedure of chapter 8.4
module Crypto.Fido2.Attestation.AndroidKey (verify) where

import Control.Monad (unless, when)
import Crypto.Fido2.Attestation.AndroidKey.Statement (AuthorisationList (allApplications, origin, purpose), ExtAttestation (attestationChallenge, softwareEnforced, teeEnforced), Stmt (Stmt, alg, attExt, sig, x5c))
import Crypto.Fido2.Error
  ( AttestationError
      ( AndroidKeyAllApplicationsFieldFound,
        AndroidKeyOriginFieldInvalid,
        AndroidKeyPurposeFieldInvalid,
        AttestationCommonError,
        CertiticatePublicKeyInvalid,
        CredentialDataMissing,
        CredentialKeyMismatch
      ),
    CommonError (ChallengeMismatch, InvalidSignature),
  )
import Crypto.Fido2.Protocol (AttestedCredentialData (credentialPublicKey), AuthenticatorData (AuthenticatorData, attestedCredentialData, rawData))
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (Digest, SHA256)
import Data.ByteArray (convert)
import Data.Maybe (isJust)
import qualified Data.Set as Set
import Data.X509 (Certificate (certPubKey), getCertificate)

-- https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h
kmOriginGenerated :: Integer
kmOriginGenerated = 0

-- https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h
kmPurposeSign :: Integer
kmPurposeSign = 2

-- https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
verify :: Stmt -> AuthenticatorData -> Digest SHA256 -> Either AttestationError AttestedCredentialData
verify Stmt {alg = _alg, sig, x5c, attExt} AuthenticatorData {rawData, attestedCredentialData} clientDataHash = do
  -- 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to
  -- extract the contained fields.
  -- NOTE: The validity of the data is already checked during decoding.

  -- 2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the
  -- public key in the first certificate in x5c with the algorithm specified in alg.
  -- TODO: Maybe use verifyX509Sig like in Packed.hs
  let signedData = rawData <> convert clientDataHash
      cert = getCertificate x5c
  x5cKey <- maybe (Left CertiticatePublicKeyInvalid) pure $ PublicKey.toPublicKey $ certPubKey cert
  unless (PublicKey.verify x5cKey signedData sig) . Left $ AttestationCommonError InvalidSignature

  -- 3. Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the
  -- attestedCredentialData in authenticatorData.
  credData <- maybe (Left CredentialDataMissing) pure attestedCredentialData
  let key = credentialPublicKey credData
  unless (key == x5cKey) $ Left CredentialKeyMismatch

  -- 4. Verify that the attestationChallenge field in the attestation certificate extension data is identical to
  -- clientDataHash.
  -- See https://source.android.com/security/keystore/attestation for the ASN1 description
  unless (attestationChallenge attExt == clientDataHash) . Left $ AttestationCommonError ChallengeMismatch

  -- 5. Verify the following using the appropriate authorization list from the attestation certificate extension data:

  -- 5.a The AuthorizationList.allApplications field is not present on either
  -- authorization list (softwareEnforced nor teeEnforced), since
  -- PublicKeyCredential MUST be scoped to the RP ID.
  let software = softwareEnforced attExt
      tee = teeEnforced attExt
  when (isJust (allApplications software) || isJust (allApplications tee)) $ Left AndroidKeyAllApplicationsFieldFound

  -- 5.b For the following, use only the teeEnforced authorization list if the
  -- RP wants to accept only keys from a trusted execution environment,
  -- otherwise use the union of teeEnforced and softwareEnforced.
  -- TODO: Allow the users of the library set the required trust level
  -- 5.b.1 The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
  unless (origin software == Just kmOriginGenerated || origin tee == Just kmOriginGenerated) $ Left AndroidKeyOriginFieldInvalid

  -- 5.b.2 The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
  -- NOTE: This statement is ambiguous as the purpose field is a set. Existing libraries take the same approach, checking if KM_PURPOSE_SIGN is the only member.
  let targetSet = Just $ Set.singleton kmPurposeSign
  unless (targetSet == purpose software || targetSet == purpose tee) $ Left AndroidKeyPurposeFieldInvalid

  -- 6. If successful, return implementation-specific values representing attestation type Basic and attestation trust
  -- path x5c.
  maybe (Left CredentialDataMissing) pure attestedCredentialData
