{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

-- | Stability: experimental
-- This module implements the
-- [FIDO U2F Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation).
module Crypto.WebAuthn.AttestationStatementFormat.FidoU2F
  ( format,
    Format (..),
    VerificationError (..),
  )
where

import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (unless)
import Crypto.PubKey.ECC.Types (CurveName (SEC_p256r1))
import qualified Crypto.WebAuthn.Cose.PublicKeyWithSignAlg as Cose
import Crypto.WebAuthn.Internal.Utils (failure)
import qualified Crypto.WebAuthn.Model.Types as M
import Data.Aeson (ToJSON, object, toJSON, (.=))
import Data.Bifunctor (first)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.HashMap.Strict ((!?))
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.EC as X509
import qualified Data.X509.Validation as X509

-- | The Fido U2F format. The sole purpose of this type is to instantiate the
-- AttestationStatementFormat typeclass below.
data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | Verification errors specific to Fido U2F attestation
data VerificationError
  = -- | The public key in the certificate was not an EC Key or the curve was not the p256 curve
    CertificatePublicKeyInvalid X509.PubKey
  | -- | The COSE encoding of the credential public key does not have key type EC2
    CredentialPublicKeyNotCoseEC2 Cose.CosePublicKey
  | -- | The x and/or y coordinates of the credential public key are longer than 32 bytes
    CoordinateSizeInvalid
      { -- | Actual length in bytes of the x coordinate
        xLength :: Int,
        -- | Actual length in bytes of the y coordinate
        yLength :: Int
      }
  | -- | The provided public key cannot validate the signature over the verification data
    SignatureInvalid X509.SignatureFailure
  deriving (Show, Exception)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation)
data Statement = Statement
  { sig :: BS.ByteString,
    attCert :: X509.SignedCertificate
  }
  deriving (Show, Eq)

instance ToJSON Statement where
  toJSON Statement {..} =
    object
      [ "attestnCert" .= attCert,
        "sig" .= sig
      ]

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement
  asfIdentifier _ = "fido-u2f"

  asfDecode _ xs = case (xs !? "sig", xs !? "x5c") of
    (Just (CBOR.TBytes sig), Just (CBOR.TList [CBOR.TBytes certBytes])) -> do
      attCert <- first (("Failed to decode signed certificate: " <>) . Text.pack) (X509.decodeSignedCertificate certBytes)
      pure $ Statement sig attCert
    _ -> Left $ "CBOR map didn't have expected value types (sig: bytes, x5c: one-element list): " <> Text.pack (show xs)

  asfEncode _ Statement {..} =
    CBOR.TMap
      [ (CBOR.TString "sig", CBOR.TBytes sig),
        (CBOR.TString "x5c", CBOR.TList [CBOR.TBytes $ X509.encodeSignedObject attCert])
      ]

  type AttStmtVerificationError Format = VerificationError

  asfVerify
    _
    _
    Statement {..}
    M.AuthenticatorData
      { M.adAttestedCredentialData = M.AttestedCredentialData {..},
        ..
      }
    clientDataHash = do
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
        X509.PubKeyEC pk ->
          case X509.ecPubKeyCurveName pk of
            Just SEC_p256r1 -> pure ()
            _ -> failure $ CertificatePublicKeyInvalid certPubKey
        _ -> failure $ CertificatePublicKeyInvalid certPubKey

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
      -- NOTE: Already done during decoding of the COSE public key
      case extractPublicKey . M.unRaw $ acdCredentialPublicKeyBytes of
        Nothing -> failure $ CredentialPublicKeyNotCoseEC2 acdCredentialPublicKey
        Just (xb, yb) -> do
          -- We decode the x and y values in an earlier stage of the process. In order to construct the publicKeyU2F, we have to reencode the value.
          unless (BS.length xb == 32 && BS.length yb == 32) $
            failure $ CoordinateSizeInvalid (BS.length xb) (BS.length yb)
          -- 4.c Let publicKeyU2F be the concatenation 0x04 || x || y.
          let publicKeyU2F = BS.singleton 0x04 <> xb <> yb

          -- 5. Let verificationData be the concatenation of (0x00 || rpIdHash ||
          -- clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of
          -- [FIDO-U2F-Message-Formats]).
          let credId = M.unCredentialId acdCredentialId
              verificationData =
                BS.singleton 0x00
                  <> BA.convert (M.unRpIdHash adRpIdHash)
                  <> BA.convert (M.unClientDataHash clientDataHash)
                  <> credId
                  <> publicKeyU2F

          -- 6. Verify the sig using verificationData and the certificate public key per
          -- section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
          case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) certPubKey verificationData sig of
            X509.SignaturePass -> pure ()
            X509.SignatureFailed e -> failure $ SignatureInvalid e
          pure ()

      -- 7. Optionally, inspect x5c and consult externally provided knowledge to
      -- determine whether attStmt conveys a Basic or AttCA attestation.
      -- 8. If successful, return implementation-specific values representing
      -- attestation type Basic, AttCA or uncertainty, and attestation trust path
      -- x5c.
      pure $
        M.SomeAttestationType $
          M.AttestationTypeVerifiable M.VerifiableAttestationTypeUncertain (M.FidoU2FCert attCert)

  asfTrustAnchors _ _ = mempty

-- | Helper function that wraps the Fido U2F format into the general
-- SomeAttestationStatementFormat type.
format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format

-- [(spec)](https://www.iana.org/assignments/cose/cose.xhtml)
-- This function assumes the provided key is an ECC key, which is a valid
-- assumption as we have already verified that in step 2.b
-- Any non ECC key would result in another error here, which is fine.
extractPublicKey :: BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
extractPublicKey keyBS = do
  (rest, result) <- either (const Nothing) pure $ CBOR.deserialiseFromBytes CBOR.decodeTerm $ LBS.fromStrict keyBS
  unless (LBS.null rest) Nothing
  pairs <- case result of
    CBOR.TMap pairs -> return pairs
    _ -> Nothing
  let xKey = -2
  let yKey = -3
  case (CBOR.TInt xKey `lookup` pairs, CBOR.TInt yKey `lookup` pairs) of
    (Just (CBOR.TBytes x), Just (CBOR.TBytes y)) -> do
      pure (x, y)
    _ -> Nothing
