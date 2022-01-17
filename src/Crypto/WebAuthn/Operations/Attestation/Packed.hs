{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

-- | This module implements
-- [Packed attestation](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation).
module Crypto.WebAuthn.Operations.Attestation.Packed
  ( format,
    Format (..),
    VerificationError (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM, unless, when)
import qualified Crypto.WebAuthn.Cose.Key as Cose
import qualified Crypto.WebAuthn.Cose.Registry as Cose
import Crypto.WebAuthn.Identifier (IdFidoGenCeAAGUID (IdFidoGenCeAAGUID))
import Crypto.WebAuthn.Internal.Utils (failure)
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Crypto.WebAuthn.PublicKey as PublicKey
import Data.ASN1.Error (ASN1Error)
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
    VerificationErrorAlgorithmMismatch
  | -- | The statement key cannot verify the signature over the attested
    -- credential data and client data for self attestation
    VerificationErrorInvalidSignature Text
  | -- | The statement certificate cannot verify the signature over the attested
    -- credential data and client data for nonself attestation
    VerificationErrorVerificationFailure X509.SignatureFailure
  | -- | The certificate does not meet the requirements layed out in the
    -- webauthn specification
    -- https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
    VerificationErrorCertificateRequirementsUnmet
  | -- | The (supposedly) ASN1 encoded certificate extension could not be
    -- decoded
    VerificationErrorASN1Error ASN1Error
  | -- | The certificate extension does not contain a AAGUID
    VerificationErrorCredentialAAGUIDMissing
  | -- | The AAGUID in the certificate extension does not match the AAGUID in
    -- the authenticator data
    VerificationErrorCertificateAAGUIDMismatch
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

  asfEncode _ Statement {alg, sig, x5c} =
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
              signAlg = Cose.keySignAlg key
          when (stmtAlg /= signAlg) $ failure VerificationErrorAlgorithmMismatch

          -- Verify that sig is a valid signature over the concatenation of
          -- authenticatorData and clientDataHash using the credential public key with alg.
          case PublicKey.verify signAlg (PublicKey.fromCose key) signedData stmtSig of
            Right () -> pure ()
            Left err -> failure $ VerificationErrorInvalidSignature err

          pure $ M.SomeAttestationType M.AttestationTypeSelf

        -- Basic, AttCA
        Just (x5c@(certCred :| _), IdFidoGenCeAAGUID credAAGUID) -> do
          let cert = X509.getCertificate certCred
              pubKey = X509.certPubKey cert
          -- Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using
          -- the attestation public key in attestnCert with the algorithm specified in alg.
          case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pubKey signedData stmtSig of
            X509.SignaturePass -> pure ()
            X509.SignatureFailed err -> failure $ VerificationErrorVerificationFailure err

          -- Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation Statement Certificate
          -- Requirements.
          let dnElements = X509.getDistinguishedElements $ X509.certSubjectDN cert
          unless
            ( hasDnElement X509.DnCountry dnElements
                && hasDnElement X509.DnOrganization dnElements
                && hasDnElement X509.DnCommonName dnElements
                && findDnElement X509.DnOrganizationUnit dnElements == Just "Authenticator Attestation"
            )
            $ failure VerificationErrorCertificateRequirementsUnmet

          -- If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
          -- the value of this extension matches the aaguid in authenticatorData.
          let aaguid = M.acdAaguid credData
          unless (aaguid == credAAGUID) $ failure VerificationErrorCertificateAAGUIDMismatch

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
