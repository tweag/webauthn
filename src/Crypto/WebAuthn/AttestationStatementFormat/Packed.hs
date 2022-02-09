{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

-- | Stability: experimental
-- This module implements the
-- [Packed Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation).
module Crypto.WebAuthn.AttestationStatementFormat.Packed
  ( format,
    Format (..),
    VerificationError (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM, unless, when)
import qualified Crypto.WebAuthn.Cose.Algorithm as Cose
import qualified Crypto.WebAuthn.Cose.Internal.Verify as Cose
import qualified Crypto.WebAuthn.Cose.Key as Cose
import Crypto.WebAuthn.Internal.Utils (IdFidoGenCeAAGUID (IdFidoGenCeAAGUID), failure)
import Crypto.WebAuthn.Model (AAGUID)
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Data.ASN1.OID as OID
import Data.Aeson (ToJSON, object, toJSON, (.=))
import Data.Bifunctor (first)
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import Data.HashMap.Strict ((!?))
import Data.List.NonEmpty (NonEmpty ((:|)), toList)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509

-- | The Packed format. The sole purpose of this type is to instantiate the
-- AttestationStatementFormat typeclass below.
data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation)
data Statement = Statement
  { alg :: Cose.CoseSignAlg,
    sig :: BS.ByteString,
    x5c :: Maybe (NE.NonEmpty X509.SignedCertificate, IdFidoGenCeAAGUID)
  }
  deriving (Eq, Show)

instance ToJSON Statement where
  toJSON Statement {..} =
    object
      ( [ "alg" .= alg,
          "sig" .= sig
        ]
          ++ maybe [] (\(x5c', _) -> ["x5c" .= x5c']) x5c
      )

-- | Verification errors specific to Packed attestation
data VerificationError
  = -- | The Algorithm from the attestation format does not match the algorithm
    -- of the key in the credential data
    AlgorithmMismatch
      { -- | The algorithm received in the attestation statement
        statementAlg :: Cose.CoseSignAlg,
        -- | The algorithm of the credentialPublicKey in authenticatorData
        credentialAlg :: Cose.CoseSignAlg
      }
  | -- | The statement key cannot verify the signature over the attested
    -- credential data and client data for self attestation
    InvalidSignature Text
  | -- | The statement certificate cannot verify the signature over the attested
    -- credential data and client data for nonself attestation
    VerificationFailure X509.SignatureFailure
  | -- | The certificate does not meet the requirements layed out in the
    -- webauthn specification
    -- https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
    CertificateRequirementsUnmet
  | -- | The AAGUID in the certificate extension does not match the AAGUID in
    -- the authenticator data
    CertificateAAGUIDMismatch
      { -- | AAGUID from the id-fido-gen-ce-aaguid certificate extension
        certificateExtensionAAGUID :: AAGUID,
        -- | A AGUID from the attested credential data in the authenticator
        -- data
        attestedCredentialDataAAGUID :: AAGUID
      }
  deriving (Show, Exception)

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement

  asfIdentifier _ = "packed"

  asfDecode _ xs =
    case (xs !? "alg", xs !? "sig", xs !? "x5c") of
      (Just (CBOR.TInt algId), Just (CBOR.TBytes sig), Just (CBOR.TList x5cRaw)) -> do
        alg <- Cose.toCoseSignAlg algId
        x5c <- case NE.nonEmpty x5cRaw of
          Nothing -> pure Nothing
          Just x5cBytes -> do
            x5c@(signedCert :| _) <- forM x5cBytes $ \case
              CBOR.TBytes certBytes ->
                first (("Failed to decode signed certificate: " <>) . Text.pack) (X509.decodeSignedCertificate certBytes)
              cert ->
                Left $ "Certificate CBOR value is not bytes: " <> Text.pack (show cert)

            let cert = X509.getCertificate signedCert
            aaguidExt <- case X509.extensionGetE (X509.certExtensions cert) of
              Just (Right ext) -> pure ext
              Just (Left err) -> Left $ "Failed to decode certificate aaguid extension: " <> Text.pack err
              Nothing -> Left "Certificate aaguid extension is missing"
            pure $ Just (x5c, aaguidExt)
        pure $ Statement {..}
      _ -> Left $ "CBOR map didn't have expected value types (alg: int, sig: bytes, x5c: list): " <> Text.pack (show xs)

  asfEncode _ Statement {..} =
    let encodedx5c = case x5c of
          Nothing -> []
          Just (certChain, _) -> map (CBOR.TBytes . X509.encodeSignedObject) $ toList certChain
     in CBOR.TMap
          [ (CBOR.TString "sig", CBOR.TBytes sig),
            (CBOR.TString "alg", CBOR.TInt $ Cose.fromCoseSignAlg alg),
            (CBOR.TString "x5c", CBOR.TList encodedx5c)
          ]

  type AttStmtVerificationError Format = VerificationError

  asfVerify
    _
    _
    Statement {alg = stmtAlg, sig = stmtSig, x5c = stmtx5c}
    M.AuthenticatorData {M.adRawData = M.WithRaw rawData, M.adAttestedCredentialData = credData}
    clientDataHash = do
      let signedData = rawData <> convert (M.unClientDataHash clientDataHash)
      case stmtx5c of
        -- Self attestation
        Nothing -> do
          -- Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
          let key = M.acdCredentialPublicKey credData
              signAlg = Cose.signAlg key
          when (stmtAlg /= signAlg) . failure $ AlgorithmMismatch stmtAlg signAlg

          -- Verify that sig is a valid signature over the concatenation of
          -- authenticatorData and clientDataHash using the credential public key with alg.
          case Cose.verify key signedData stmtSig of
            Right () -> pure ()
            Left err -> failure $ InvalidSignature err

          pure $ M.SomeAttestationType M.AttestationTypeSelf

        -- Basic, AttCA
        Just (x5c@(certCred :| _), IdFidoGenCeAAGUID certAAGUID) -> do
          let cert = X509.getCertificate certCred
              pubKey = X509.certPubKey cert
          -- Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using
          -- the attestation public key in attestnCert with the algorithm specified in alg.
          case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pubKey signedData stmtSig of
            X509.SignaturePass -> pure ()
            X509.SignatureFailed err -> failure $ VerificationFailure err

          -- Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation Statement Certificate
          -- Requirements.
          let dnElements = X509.getDistinguishedElements $ X509.certSubjectDN cert
          unless
            ( hasDnElement X509.DnCountry dnElements
                && hasDnElement X509.DnOrganization dnElements
                && hasDnElement X509.DnCommonName dnElements
                && findDnElement X509.DnOrganizationUnit dnElements == Just "Authenticator Attestation"
            )
            $ failure CertificateRequirementsUnmet

          -- If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
          -- the value of this extension matches the aaguid in authenticatorData.
          let aaguid = M.acdAaguid credData
          unless (certAAGUID == aaguid) . failure $ CertificateAAGUIDMismatch certAAGUID aaguid

          pure $
            M.SomeAttestationType $
              M.AttestationTypeVerifiable M.VerifiableAttestationTypeUncertain (M.Fido2Chain x5c)
      where
        hasDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Bool
        hasDnElement el = isJust . findDnElement el

        findDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Maybe X509.ASN1CharacterString
        findDnElement dnElementName = lookup (OID.getObjectID dnElementName)

  asfTrustAnchors _ _ = mempty

-- | Helper function that wraps the Packed format into the general
-- SomeAttestationStatementFormat type.
format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
