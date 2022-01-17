{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

-- | This module implements
-- [Fido U2F attestation](https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation).
module Crypto.WebAuthn.Operations.Attestation.FidoU2F
  ( format,
    Format (..),
    VerificationError (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (unless)
import Crypto.PubKey.ECC.Types (CurveName (SEC_p256r1))
import Crypto.WebAuthn.Internal.Utils (failure)
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Crypto.WebAuthn.PublicKey as PublicKey
import Data.Aeson (ToJSON, object, toJSON, (.=))
import Data.Bifunctor (first)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
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

-- | Decoding errors specific to Fido U2F attestation
data DecodingError
  = -- | No Signature field was present
    NoSig
  | -- | No x5c certificate was present
    NoX5C
  | -- | Multiple x5c certificates were found where only one was expected
    MultipleX5C
  | -- | There was an error decoding the x5c certificate, string is the error resulted by the `Data.X509.decodeSignedCertificate` function
    DecodingErrorX5C String
  deriving (Show, Exception)

-- | Verification errors specific to Fido U2F attestation
data VerificationError
  = -- | The public key in the certificate was not an EC Key or the curve was not the p256 curve
    InvalidCertificatePublicKey X509.PubKey
  | -- | The credential public key is not an ECDSA key
    NonECDSACredentialPublicKey PublicKey.PublicKey
  | -- | The x and/or y coordinates of the credential public key don't have a length of 32 bytes
    WrongCoordinateSize Int Int
  | -- | The provided public key cannot validate the signature over the verification data
    InvalidSignature X509.SignatureFailure
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

  asfEncode _ Statement {sig, attCert} =
    CBOR.TMap
      [ (CBOR.TString "sig", CBOR.TBytes sig),
        (CBOR.TString "x5c", CBOR.TList [CBOR.TBytes $ X509.encodeSignedObject attCert])
      ]

  type AttStmtVerificationError Format = VerificationError

  asfVerify
    _
    _
    Statement {attCert, sig}
    M.AuthenticatorData
      { M.adRpIdHash,
        M.adAttestedCredentialData = M.AttestedCredentialData {M.acdCredentialId, M.acdCredentialPublicKey}
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
            _ -> failure $ InvalidCertificatePublicKey certPubKey
        _ -> failure $ InvalidCertificatePublicKey certPubKey

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
      case PublicKey.fromCose acdCredentialPublicKey of
        PublicKey.PublicKeyECDSA {ecdsaX = xb, ecdsaY = yb} -> do
          let xlen = BS.length xb
              ylen = BS.length yb
          unless (xlen == 32 && ylen == 32) $ failure $ WrongCoordinateSize xlen ylen

          -- 4.c Let publicKeyU2F be the concatenation 0x04 || x || y.
          let publicKeyU2F = BS.singleton 0x04 <> xb <> yb

          -- 5. Let verificationData be the concatenation of (0x00 || rpIdHash ||
          -- clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of
          -- [FIDO-U2F-Message-Formats]).
          let credId = M.unCredentialId acdCredentialId
              verificationData = BS.singleton 0x00 <> BA.convert (M.unRpIdHash adRpIdHash) <> BA.convert (M.unClientDataHash clientDataHash) <> credId <> publicKeyU2F

          -- 6. Verify the sig using verificationData and the certificate public key per
          -- section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
          case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) certPubKey verificationData sig of
            X509.SignaturePass -> pure ()
            X509.SignatureFailed e -> failure $ InvalidSignature e
          pure ()
        key -> failure $ NonECDSACredentialPublicKey key

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
