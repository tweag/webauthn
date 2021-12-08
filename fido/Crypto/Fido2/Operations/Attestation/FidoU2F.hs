{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Fido2.Operations.Attestation.FidoU2F
  ( format,
    Format (..),
    DecodingError (..),
    Statement (..),
    VerifyingError (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (unless, void)
import Crypto.Fido2.Metadata.Service.IDL (metadataStatement)
import Crypto.Fido2.Metadata.Service.Processing (metadataByKeyIdentifier)
import Crypto.Fido2.Metadata.Statement.IDL (attestationTypes)
import Crypto.Fido2.Model
  ( AttestedCredentialData (AttestedCredentialData, acdCredentialId, acdCredentialPublicKey),
    AuthenticatorData (AuthenticatorData, adAttestedCredentialData, adRpIdHash),
    ClientDataHash (unClientDataHash),
    CredentialId (unCredentialId),
    RpIdHash (unRpIdHash),
  )
import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.PublicKey (PublicKey (ES256PublicKey))
import Crypto.Fido2.Registry (AuthenticatorAttestationType (ATTESTATION_ATTCA, ATTESTATION_BASIC_FULL))
import Crypto.Number.Serialize (i2osp)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.PubKey.ECC.Types (CurveName (SEC_p256r1), Point (Point))
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.HashMap.Strict as Map
import Data.List.NonEmpty (NonEmpty ((:|)))
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import Debug.Trace (trace, traceShow)
import Data.ASN1.Object (toASN1)
import Data.ASN1.Parse (runParseASN1, ParseASN1, onNextContainer, getNextContainer, getNext)
import Data.ASN1.Types (ASN1ConstructionType(Sequence), ASN1 (BitString))
import Data.ASN1.BitArray (bitArrayGetData, bitArrayLength)
import Crypto.Hash (Digest, SHA1, hash)
import Data.ByteArray (convert)
import qualified Data.ByteString.Base16 as Base16
import Data.Text.Encoding (decodeUtf8)

data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

data DecodingError
  = -- | No Signature field was present
    NoSig
  | -- | No x5c certificate was present
    NoX5C
  | -- | Multiple x5c certificates were found where only one was expected
    MultipleX5C
  | -- | There was an error decoding the x5c certificate, string is the error resulted by the `Data.X509.decodeSignedCertificate` function
    DecodingErrorX5C String
  | DecodingErrorCertificateExtension String
  deriving (Show, Exception)

data VerifyingError
  = -- | The public key in the certificate was not an EC Key or the curve was not the p256 curve
    IncorrectKeyInCertificate
  | -- | The key in the attested credential data was not an EC key or the point was the point at infinity
    NoECKeyInAttestedCredentialData
  | -- | After encoding the x or y coordinate of the public key did not have the required 32 byte length
    UnexpectedCoordinateLength
  | -- | The provided public key cannot validate the signature over the verification data
    InvalidSignature
  deriving (Show, Exception)

data Statement = Statement
  { sig :: ByteString,
    attCert :: X509.SignedCertificate,
    keyIdentifier :: X509.ExtAuthorityKeyId
  }
  deriving (Show, Eq)

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement
  asfIdentifier _ = "fido-u2f"

  type AttStmtDecodingError Format = DecodingError

  asfDecode _ m = do
    sig <- case Map.lookup "sig" m of
      Just (CBOR.TBytes sig) -> pure sig
      _ -> Left NoSig
    -- 2. Check that x5c has exactly one element and let attCert be that element.
    attCert <- case Map.lookup "x5c" m of
      Just (CBOR.TList [CBOR.TBytes certBytes]) ->
        either (Left . DecodingErrorX5C) pure $ X509.decodeSignedCertificate certBytes
      Just (CBOR.TList []) -> Left NoX5C
      Just (CBOR.TList _) -> Left MultipleX5C
      _ -> Left NoX5C

    let x = toASN1 (X509.certPubKey $ X509.getCertificate attCert) []
        Right (y :: BS.ByteString) = runParseASN1 p x
        {-
        SubjectPublicKeyInfo  ::=  SEQUENCE  {
             algorithm            AlgorithmIdentifier,
             subjectPublicKey     BIT STRING  }
        -}
        p :: ParseASN1 BS.ByteString
        p = onNextContainer Sequence $ do
          {-
          AlgorithmIdentifier  ::=  SEQUENCE  {
               algorithm               OBJECT IDENTIFIER,
               parameters              ANY DEFINED BY algorithm OPTIONAL  }
          -}
          -- We're not interested in this
          void $ getNextContainer Sequence
          BitString bitArray <- getNext
          unless (bitArrayLength bitArray `mod` 8 == 0) $ fail "bitArray has padding"
          pure $ bitArrayGetData bitArray
        h :: Digest SHA1 = trace ("Public key bytes are: " <> Text.unpack (decodeUtf8 (Base16.encode y))) $ hash y
    let keyId = trace ("Public key id is: " <> Text.unpack (decodeUtf8 (Base16.encode (convert h)))) $ X509.ExtAuthorityKeyId $ convert h
      -- case X509.extensionGetE (X509.certExtensions (X509.getCertificate attCert)) of
      --Just (Right ext) -> trace "Got a key id" $ pure $ Just ext
      --Just (Left err) -> trace "Failed to decode key id" $ Left $ DecodingErrorCertificateExtension err
      --Nothing -> trace "No key id!" $ pure Nothing
    pure $ traceShow x $ Statement sig attCert keyId

  asfEncode _ Statement {sig, attCert} =
    CBOR.TMap
      [ (CBOR.TString "sig", CBOR.TBytes sig),
        (CBOR.TString "x5c", CBOR.TList [CBOR.TBytes $ X509.encodeSignedObject attCert])
      ]

  type AttStmtVerificationError Format = VerifyingError

  asfVerify _ Statement {attCert, sig, keyIdentifier} registry AuthenticatorData {adRpIdHash, adAttestedCredentialData = AttestedCredentialData {acdCredentialId, acdCredentialPublicKey}} clientDataHash = do
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
      _ -> Left IncorrectKeyInCertificate

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
      ES256PublicKey (ECDSA.PublicKey _ (Point x y)) -> pure (x, y)
      _ -> Left NoECKeyInAttestedCredentialData

    -- We decode the x and y values in an earlier stage of the process. In order to construct the publicKeyU2F, we have to reencode the value.
    -- TODO: This is suboptimal, and we might consider not decoding, or keeping the undecoded values as an additional field.
    let xb = i2osp x
        yb = i2osp y
    unless (BS.length xb == 32 && BS.length yb == 32) $ Left UnexpectedCoordinateLength

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
      X509.SignatureFailed _ -> Left InvalidSignature

    -- 7. Optionally, inspect x5c and consult externally provided knowledge to
    -- determine whether attStmt conveys a Basic or AttCA attestation.
    let metadataEntry = metadataByKeyIdentifier registry keyIdentifier
        verifiableAttType = case metadataEntry >>= metadataStatement of
          -- 8. If successful, return implementation-specific values representing
          -- attestation type Basic, AttCA or uncertainty, and attestation trust path
          -- x5c.
          Nothing -> M.VerifiableAttestationTypeUncertain
          Just statement -> case attestationTypes statement of
            ATTESTATION_BASIC_FULL :| _ -> M.VerifiableAttestationTypeBasic
            ATTESTATION_ATTCA :| _ -> M.VerifiableAttestationTypeAttCA
            _ -> M.VerifiableAttestationTypeUncertain

    pure (M.AttestationTypeVerifiable verifiableAttType $ pure attCert, M.FidoU2FAuthenticator keyIdentifier, metadataEntry)

  asfTrustAnchors _ _ = mempty

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
