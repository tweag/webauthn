{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Fido2.Operations.Attestation.Packed
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
import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier, toAlg, toCOSEAlgorithmIdentifier)
import qualified Crypto.Fido2.PublicKey as PublicKey
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (ASN1Decoding (decodeASN1))
import Data.ASN1.Error (ASN1Error)
import qualified Data.ASN1.OID as OID
import Data.ASN1.Prim (ASN1 (OctetString))
import Data.Bifunctor (first)
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import Data.ByteString.Lazy (fromStrict)
import Data.HashMap.Strict (HashMap, (!?))
import Data.List (find)
import Data.List.NonEmpty (NonEmpty ((:|)))
import qualified Data.List.NonEmpty as NE
import Data.Maybe (isJust)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509

data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- packedStmtFormat (https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation)
data Statement = Statement
  { alg :: COSEAlgorithmIdentifier,
    sig :: BS.ByteString,
    x5c :: Maybe M.NonEmptyCertificateChain
  }
  deriving (Eq, Show)

data DecodingError
  = DecodingErrorUnexpectedCBORStructure (HashMap Text CBOR.Term)
  | DecodingErrorUnknownAlgorithmIdentifier Int
  | DecodingErrorCertificate String
  deriving (Show, Exception)

data VerificationError
  = VerificationErrorAlgorithmMismatch
  | VerificationErrorInvalidSignature
  | VerificationErrorVerificationFailure X509.SignatureFailure
  | VerificationErrorCertificateRequirementsUnmet
  | VerificationErrorCredentialAAGUIDMissing
  | VerificationErrorCertificateAAGUIDMismatch
  | VerificationErrorASN1Error ASN1Error
  deriving (Show, Exception)

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement

  asfIdentifier _ = "packed"

  type AttStmtDecodingError Format = DecodingError

  asfDecode _ xs =
    case (xs !? "alg", xs !? "sig", xs !? "x5c") of
      (Just (CBOR.TInt algId), Just (CBOR.TBytes sig), x5cValue) -> do
        alg <- maybe (Left $ DecodingErrorUnknownAlgorithmIdentifier algId) Right (toAlg algId)
        x5c <- case x5cValue of
          Nothing -> pure Nothing
          Just (CBOR.TList (NE.nonEmpty -> Just x5cRaw)) -> do
            chain <- forM x5cRaw $ \case
              CBOR.TBytes certBytes ->
                first DecodingErrorCertificate (X509.decodeSignedCertificate certBytes)
              _ -> Left $ DecodingErrorUnexpectedCBORStructure xs
            pure $ Just chain
          _ -> Left $ DecodingErrorUnexpectedCBORStructure xs
        pure $ Statement {..}
      _ -> Left $ DecodingErrorUnexpectedCBORStructure xs

  type AttStmtVerificationError Format = VerificationError

  asfVerify
    _
    Statement {alg = stmtAlg, sig = stmtSig, x5c = stmtx5c}
    M.AuthenticatorData {M.adRawData, M.adAttestedCredentialData = credData}
    clientDataHash = do
      let signedData = adRawData <> convert (M.unClientDataHash clientDataHash)
      case stmtx5c of
        -- Self attestation
        Nothing -> do
          -- Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
          let key = M.acdCredentialPublicKey credData
              alg = toCOSEAlgorithmIdentifier key
          when (stmtAlg /= alg) $ Left VerificationErrorAlgorithmMismatch

          -- Verify that sig is a valid signature over the concatenation of
          -- authenticatorData and clientDataHash using the credential public key with alg.
          unless (PublicKey.verify key signedData stmtSig) . Left $ VerificationErrorInvalidSignature

          pure M.AttestationTypeSelf

        -- Basic, AttCA
        Just x5c@(certCred :| _) -> do
          let cert = X509.getCertificate certCred
              pubKey = X509.certPubKey cert
          -- Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using
          -- the attestation public key in attestnCert with the algorithm specified in alg.
          case X509.verifySignature (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pubKey signedData stmtSig of
            X509.SignaturePass -> pure ()
            X509.SignatureFailed err -> Left $ VerificationErrorVerificationFailure err

          -- Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation Statement Certificate
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
          let (X509.Extensions mX509Exts) = X509.certExtensions cert
              mX509Ext = mX509Exts >>= findProperExtension [1, 3, 6, 1, 4, 1, 45724, 1, 1, 4]
              aaguid = M.acdAaguid credData

          case mX509Ext of
            Nothing -> pure ()
            Just ext -> do
              certAAGUID <- decodeAAGUID (X509.extRawContent ext)
              unless (aaguid == certAAGUID) (Left VerificationErrorCertificateAAGUIDMismatch)

          -- TODO: Inspect x5c and consult externally provided knowledge to
          -- determine whether attStmt conveys a Basic or AttCA attestation. Blocked
          -- by https://github.com/tweag/haskell-fido2/pull/11
          pure $ M.AttestationTypeUncertain x5c
      where
        hasDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Bool
        hasDnElement el = isJust . findDnElement el

        findDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Maybe X509.ASN1CharacterString
        findDnElement dnElementName = lookup (OID.getObjectID dnElementName)

        findProperExtension :: OID.OID -> [X509.ExtensionRaw] -> Maybe X509.ExtensionRaw
        findProperExtension extensionOID = find ((==) extensionOID . X509.extRawOID)

        decodeAAGUID :: BS.ByteString -> Either VerificationError M.AAGUID
        decodeAAGUID bs = do
          asn1 <- either (Left . VerificationErrorASN1Error) pure . decodeASN1 DER $ fromStrict bs
          case asn1 of
            [OctetString s] -> Right $ M.AAGUID s
            _ -> Left VerificationErrorCredentialAAGUIDMissing

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
