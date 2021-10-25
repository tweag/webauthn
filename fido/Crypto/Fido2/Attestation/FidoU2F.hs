{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Attestation.FidoU2F
  ( asfFidoU2F,
    AttestationStatementFormatFidoU2F (AttestationStatementFormatFidoU2F),
    ASFFidoU2FDecodingError (..),
    ASFFidoU2FStatement (..),
    ASFFidoU2FVerifyingError (..),
  )
where

import Codec.CBOR.Term (Term (TBytes, TList))
import Control.Exception (Exception)
import Control.Monad (unless)
import Crypto.Fido2.Model
  ( AttestationType (AttestationTypeSelf),
    AttestedCredentialData (AttestedCredentialData, acdCredentialId, acdCredentialPublicKey),
    AuthenticatorData (AuthenticatorData, adAttestedCredentialData, adRpIdHash),
    ClientDataHash (unClientDataHash),
    CredentialId (unCredentialId),
    RpIdHash (unRpIdHash),
  )
import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.PublicKey (ECDSAKey (ECDSAKey), PublicKey (ECDSAPublicKey))
import Crypto.Number.Serialize (i2osp)
import Crypto.PubKey.ECC.Types (CurveName (SEC_p256r1), Point (Point))
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.HashMap.Strict as Map
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509

data AttestationStatementFormatFidoU2F = AttestationStatementFormatFidoU2F
  deriving (Show)

data ASFFidoU2FDecodingError
  = -- | No Signature field was present
    ASFFidoU2FNoSig
  | -- | No x5c certificate was present
    ASFFidoU2FNoX5C
  | -- | Multiple x5c certificates were found where only one was expected
    ASFFidoU2FMultipleX5C
  | -- | There was an error decoding the x5c certificate, string is the error resulted by the `Data.X509.decodeSignedCertificate` function
    ASFFidoU2FDecodingErrorX5C String
  deriving (Show, Exception)

data ASFFidoU2FVerifyingError
  = ASFFidoU2FNoECKeyInCertificate
  | ASFFidoU2FCredentialDataMissing
  | ASFFidoU2FNoECKeyInAttestedCredentialData
  | ASFFidoU2FUnexpectedCoordinateLength
  | ASFFidoU2FInvalidSignature
  deriving (Show, Exception)

data ASFFidoU2FStatement = ASFFidoU2FStatement
  { sig :: ByteString,
    attCert :: X509.SignedCertificate
  }
  deriving (Show, Eq)

instance M.AttestationStatementFormat AttestationStatementFormatFidoU2F where
  type AttStmt AttestationStatementFormatFidoU2F = ASFFidoU2FStatement
  asfIdentifier _ = "fido-u2f"

  type AttStmtDecodingError AttestationStatementFormatFidoU2F = ASFFidoU2FDecodingError

  asfDecode _ m = do
    sig <- case Map.lookup "sig" m of
      Just (TBytes sig) -> pure sig
      _ -> Left ASFFidoU2FNoSig
    -- 2. Check that x5c has exactly one element and let attCert be that element.
    attCert <- case Map.lookup "x5c" m of
      Just (TList [TBytes certBytes]) ->
        either (Left . ASFFidoU2FDecodingErrorX5C) pure $ X509.decodeSignedCertificate certBytes
      Just (TList []) -> Left ASFFidoU2FNoX5C
      Just (TList _) -> Left ASFFidoU2FMultipleX5C
      _ -> Left ASFFidoU2FNoX5C
    pure $ ASFFidoU2FStatement sig attCert

  type AttStmtVerificationError AttestationStatementFormatFidoU2F = ASFFidoU2FVerifyingError

  asfVerify _ ASFFidoU2FStatement {attCert, sig} AuthenticatorData {adRpIdHash, adAttestedCredentialData = AttestedCredentialData {acdCredentialId, acdCredentialPublicKey}} clientDataHash = do
    -- 1. Verify that attStmt is valid CBOR conforming to the syntax defined above
    -- and perform CBOR decoding on it to extract the contained fields.
    -- NOTE: The validity of the data is already checked during decoding.

    -- 2.a Check that x5c has exactly one element and let attCert be that element.
    -- NOTE: This has already been done during decoding

    -- 2.b Let certificate public key be the public key conveyed by attCert. If
    -- certificate public key is not an Elliptic Curve (EC) public key over the
    -- P-256 curve, terminate this algorithm and return an appropriate error.
    let certPubKey = X509.certPubKey $ X509.getCertificate attCert
    case certPubKey of
      -- TODO: Will we only get named curves?
      (X509.PubKeyEC X509.PubKeyEC_Named {X509.pubkeyEC_name = SEC_p256r1}) -> pure ()
      _ -> Left ASFFidoU2FNoECKeyInCertificate

    -- 3. Extract the claimed rpIdHash from authenticatorData, and the claimed
    -- credentialId and credentialPublicKey from authenticatorData.attestedCredentialData.
    -- NOTE: Done in patternmatch

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
    (x, y) <- case acdCredentialPublicKey of
      ECDSAPublicKey (ECDSAKey _ (Point x y)) -> pure (x, y)
      _ -> Left ASFFidoU2FNoECKeyInAttestedCredentialData

    -- We decode the x and y values in an earlier stage of the process. In order to construct the publicKeyU2F, we have to reencode the value.
    -- TODO: This is suboptimal, and we might consider not decoding, or keeping the undecoded values as an additional field.
    let xb = i2osp x
        yb = i2osp y
    unless (BS.length xb == 32 && BS.length yb == 32) $ Left ASFFidoU2FUnexpectedCoordinateLength

    -- 4.c Let publicKeyU2F be the concatenation 0x04 || x || y.
    let publicKeyU2F = BS.singleton 0x04 <> xb <> yb

    -- 5. Let verificationData be the concatenation of (0x00 || rpIdHash ||
    -- clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of
    -- [FIDO-U2F-Message-Formats]).
    let credId = unCredentialId acdCredentialId
        verificationData = BS.singleton 0x00 <> BA.convert (unRpIdHash adRpIdHash) <> BA.convert (unClientDataHash clientDataHash) <> credId <> publicKeyU2F

    -- 6. Verify the sig using verificationData and the certificate public key per
    -- section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
    case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) certPubKey verificationData sig of
      X509.SignaturePass -> pure ()
      -- TODO: Pass along SignatureFailure to error
      X509.SignatureFailed _ -> Left ASFFidoU2FInvalidSignature

    -- 7. Optionally, inspect x5c and consult externally provided knowledge to
    -- determine whether attStmt conveys a Basic or AttCA attestation.
    -- TODO: Metadata

    -- 8. If successful, return implementation-specific values representing
    -- attestation type Basic, AttCA or uncertainty, and attestation trust path
    -- x5c.
    -- TODO: Metadata
    pure AttestationTypeSelf

asfFidoU2F :: M.SomeAttestationStatementFormat
asfFidoU2F = M.SomeAttestationStatementFormat AttestationStatementFormatFidoU2F
