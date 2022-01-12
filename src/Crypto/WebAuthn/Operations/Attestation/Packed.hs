{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.WebAuthn.Operations.Attestation.Packed
  ( format,
    Format (..),
    DecodingError (..),
    Statement (..),
    VerificationError (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM, unless, when)
import qualified Crypto.WebAuthn.Cose.Key as Cose
import qualified Crypto.WebAuthn.Cose.Registry as Cose
import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.Operations.Common (IdFidoGenCeAAGUID (IdFidoGenCeAAGUID))
import qualified Crypto.WebAuthn.PublicKey as PublicKey
import Data.ASN1.Error (ASN1Error)
import qualified Data.ASN1.OID as OID
import Data.Aeson (ToJSON, object, toJSON, (.=))
import Data.Bifunctor (first)
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import Data.HashMap.Strict (HashMap, (!?))
import Data.List.NonEmpty (NonEmpty ((:|)), toList)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509

data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation)
data Statement = Statement
  { alg :: Cose.CoseSignAlg,
    sig :: BS.ByteString,
    x5c :: Maybe (NE.NonEmpty X509.SignedCertificate),
    aaguidExt :: Maybe IdFidoGenCeAAGUID
  }
  deriving (Eq, Show)

instance ToJSON Statement where
  toJSON Statement {..} =
    object
      ( [ "alg" .= alg,
          "sig" .= sig
        ]
          ++ maybe [] (\x5c' -> ["x5c" .= x5c']) x5c
      )

data DecodingError
  = -- | The provided CBOR encoded data was malformed. Either because a field
    -- was missing, or because the field contained the wrong type of data
    DecodingErrorUnexpectedCBORStructure (HashMap Text CBOR.Term)
  | -- | The algorithm identifier was invalid, or unsupported by the library
    DecodingErrorUnknownAlgorithmIdentifier Int
  | -- | The x5c field of the attestation statement could not be decoded for
    -- the provided reason
    DecodingErrorCertificate String
  | -- | The required id-fido-gen-ce-aaguid extension was not found in the
    -- certificate
    DecodingErrorCertificateExtensionMissing
  | -- | The required id-fido-gen-ce-aaguid extension of the certificate could
    -- not be decoded
    DecodingErrorCertificateExtension String
  deriving (Show, Exception)

data VerificationError
  = -- | The Algorithm from the attestation format does not match the algorithm
    -- of the key in the credential data
    VerificationErrorAlgorithmMismatch
  | -- | The statement key cannot verify the signature over the attested
    -- credential data and client data for self attestation
    VerificationErrorInvalidSignature String
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

  type AttStmtDecodingError Format = DecodingError

  asfDecode _ xs =
    case (xs !? "alg", xs !? "sig", xs !? "x5c") of
      (Just (CBOR.TInt algId), Just (CBOR.TBytes sig), x5cValue) -> do
        alg <- maybe (Left $ DecodingErrorUnknownAlgorithmIdentifier algId) Right (Cose.toCoseSignAlg algId)
        x5c <- case x5cValue of
          Nothing -> pure Nothing
          Just (CBOR.TList (NE.nonEmpty -> Just x5cRaw)) -> do
            chain <- forM x5cRaw $ \case
              CBOR.TBytes certBytes ->
                first DecodingErrorCertificate (X509.decodeSignedCertificate certBytes)
              _ -> Left $ DecodingErrorUnexpectedCBORStructure xs
            pure $ Just chain
          _ -> Left $ DecodingErrorUnexpectedCBORStructure xs

        aaguidExt <- case x5c of
          Nothing -> pure Nothing
          Just chain -> do
            let cert = X509.getCertificate $ NE.head chain
            case X509.extensionGetE (X509.certExtensions cert) of
              Just (Right ext) -> pure $ Just ext
              Just (Left err) -> Left $ DecodingErrorCertificateExtension err
              Nothing -> pure Nothing
        pure $ Statement {..}
      _ -> Left $ DecodingErrorUnexpectedCBORStructure xs

  asfEncode _ Statement {alg, sig, x5c} =
    let encodedx5c = case x5c of
          Nothing -> []
          Just certChain -> map (CBOR.TBytes . X509.encodeSignedObject) $ toList certChain
     in CBOR.TMap
          [ (CBOR.TString "sig", CBOR.TBytes sig),
            (CBOR.TString "alg", CBOR.TInt $ Cose.fromCoseSignAlg alg),
            (CBOR.TString "x5c", CBOR.TList encodedx5c)
          ]

  type AttStmtVerificationError Format = VerificationError

  asfVerify
    _
    _
    Statement {alg = stmtAlg, sig = stmtSig, x5c = stmtx5c, aaguidExt}
    M.AuthenticatorData {M.adRawData = M.WithRaw rawData, M.adAttestedCredentialData = credData}
    clientDataHash = do
      let signedData = rawData <> convert (M.unClientDataHash clientDataHash)
      case stmtx5c of
        -- Self attestation
        Nothing -> do
          -- Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
          let key = M.acdCredentialPublicKey credData
              signAlg = Cose.keySignAlg key
          when (stmtAlg /= signAlg) $ Left VerificationErrorAlgorithmMismatch

          -- Verify that sig is a valid signature over the concatenation of
          -- authenticatorData and clientDataHash using the credential public key with alg.
          case PublicKey.verify signAlg (PublicKey.fromCose key) signedData stmtSig of
            Right () -> pure ()
            Left err -> Left $ VerificationErrorInvalidSignature err

          pure $ M.SomeAttestationType M.AttestationTypeSelf

        -- Basic, AttCA
        Just x5c@(certCred :| _) -> do
          let cert = X509.getCertificate certCred
              pubKey = X509.certPubKey cert
          -- Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using
          -- the attestation public key in attestnCert with the algorithm specified in alg.
          case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pubKey signedData stmtSig of
            X509.SignaturePass -> pure ()
            X509.SignatureFailed err -> Left $ VerificationErrorVerificationFailure err

          -- Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation Statement Certificate
          -- Requirements.
          let dnElements = X509.getDistinguishedElements $ X509.certSubjectDN cert
          unless
            ( hasDnElement X509.DnCountry dnElements
                && hasDnElement X509.DnOrganization dnElements
                && hasDnElement X509.DnCommonName dnElements
                && findDnElement X509.DnOrganizationUnit dnElements == Just "Authenticator Attestation"
            )
            $ Left VerificationErrorCertificateRequirementsUnmet

          -- If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
          -- the value of this extension matches the aaguid in authenticatorData.
          let aaguid = M.acdAaguid credData

          case aaguidExt of
            Just (IdFidoGenCeAAGUID credAAGUID) -> unless (aaguid == credAAGUID) $ Left VerificationErrorCertificateAAGUIDMismatch
            Nothing -> pure ()

          pure $
            M.SomeAttestationType $
              M.AttestationTypeVerifiable M.VerifiableAttestationTypeUncertain (M.Fido2Chain x5c)
      where
        hasDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Bool
        hasDnElement el = isJust . findDnElement el

        findDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Maybe X509.ASN1CharacterString
        findDnElement dnElementName = lookup (OID.getObjectID dnElementName)

  asfTrustAnchors _ _ = mempty

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
