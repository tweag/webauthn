{-# LANGUAGE NamedFieldPuns #-}

-- | Implements step 2-6 of the verification procedure of chapter 8.4
module Crypto.Fido2.Attestation.FidoU2F (verify) where

import Control.Monad (unless)
import Crypto.Fido2.Attestation.FidoU2F.Statement (Stmt (Stmt, attCert, sig))
import Crypto.Fido2.Error (AttestationError (CredentialDataMissing, U2FNoECKeyInAttestedCredentialData, U2FNoECKeyinCertificate, U2FUnexpectedCoordinateLength))
import Crypto.Fido2.Protocol
  ( AttestedCredentialData
      ( AttestedCredentialData,
        credentialId,
        credentialPublicKey
      ),
    AuthenticatorData
      ( AuthenticatorData,
        attestedCredentialData,
        rpIdHash
      ),
    CredentialId (CredentialId),
    URLEncodedBase64 (URLEncodedBase64),
  )
import Crypto.Fido2.PublicKey (ECDSAKey (ECDSAKey), PublicKey (ECDSAPublicKey))
import Crypto.Fido2.Signature (verifyX509Sig)
import Crypto.Hash (Digest, SHA256)
import Crypto.Number.Serialize (i2osp)
import Crypto.PubKey.ECC.Types (CurveName (SEC_p256r1), Point (Point))
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import Data.X509
  ( Certificate (certPubKey),
    PubKey (PubKeyEC),
    PubKeyEC (PubKeyEC_Named, pubkeyEC_name),
    getCertificate,
  )
import qualified Data.X509 as X509

-- https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation
verify :: Stmt -> AuthenticatorData -> Digest SHA256 -> Either AttestationError AttestedCredentialData
verify Stmt {sig, attCert} AuthenticatorData {rpIdHash, attestedCredentialData} clientDataHash = do
  -- 1. Verify that attStmt is valid CBOR conforming to the syntax defined above
  -- and perform CBOR decoding on it to extract the contained fields.
  -- NOTE: The validity of the data is already checked during decoding.

  -- 2.a Check that x5c has exactly one element and let attCert be that element.
  -- NOTE: This has already been done during decoding

  -- 2.b Let certificate public key be the public key conveyed by attCert. If
  -- certificate public key is not an Elliptic Curve (EC) public key over the
  -- P-256 curve, terminate this algorithm and return an appropriate error.
  let certPubKey' = certPubKey $ getCertificate attCert
  case certPubKey' of
    -- TODO: Will we only get named curves?
    (PubKeyEC PubKeyEC_Named {pubkeyEC_name = SEC_p256r1}) -> pure ()
    _ -> Left U2FNoECKeyinCertificate

  -- 3. Extract the claimed rpIdHash from authenticatorData, and the claimed
  -- credentialId and credentialPublicKey from
  -- authenticatorData.attestedCredentialData.
  credData@AttestedCredentialData {credentialId, credentialPublicKey} <- maybe (Left CredentialDataMissing) pure attestedCredentialData

  -- 4. Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of
  -- [RFC8152]) to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in
  -- Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).

  -- 4.a Let x be the value corresponding to the "-2" key (representing x
  -- coordinate) in credentialPublicKey, and confirm its size to be of 32 bytes.
  -- If size differs or "-2" key is not found, terminate this algorithm and
  -- return an appropriate error.
  -- 4.b Let y be the value corresponding to the "-3" key (representing y
  -- coordinate) in credentialPublicKey, and confirm its size to be of 32 bytes.
  -- If size differs or "-3" key is not found, terminate this algorithm and
  -- return an appropriate error.
  -- NOTE: The decoding already happened in the decoding step
  (x, y) <- case credentialPublicKey of
    ECDSAPublicKey (ECDSAKey _ (Point x y)) -> pure (x, y)
    _ -> Left U2FNoECKeyInAttestedCredentialData

  -- We decode the x and y values in an earlier stage of the process. In order to construct the publicKeyU2F, we have to reencode the value.
  -- TODO: This is suboptimal, and we might consider not decoding, or keeping the undecoded values as an additional field.
  let xb = i2osp x
      yb = i2osp y
  unless (BS.length xb == 32 && BS.length yb == 32) $ Left U2FUnexpectedCoordinateLength

  -- 4.c Let publicKeyU2F be the concatenation 0x04 || x || y.
  let publicKeyU2F = BS.singleton 0x04 <> xb <> yb

  -- 5. Let verificationData be the concatenation of (0x00 || rpIdHash ||
  -- clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of
  -- [FIDO-U2F-Message-Formats]).
  let CredentialId (URLEncodedBase64 credId) = credentialId
      verificationData = BS.singleton 0x00 <> convert rpIdHash <> convert clientDataHash <> credId <> publicKeyU2F

  -- 6. Verify the sig using verificationData and the certificate public key per
  -- section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
  verifyX509Sig (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) certPubKey' verificationData sig

  -- 7. Optionally, inspect x5c and consult externally provided knowledge to
  -- determine whether attStmt conveys a Basic or AttCA attestation.

  -- 8. If successful, return implementation-specific values representing
  -- attestation type Basic, AttCA or uncertainty, and attestation trust path
  -- x5c.
  pure credData
