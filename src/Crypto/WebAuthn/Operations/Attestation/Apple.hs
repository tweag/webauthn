{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.WebAuthn.Operations.Attestation.Apple
  ( format,
    Format (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM)
import Control.Monad.Cont (unless)
import Crypto.Hash (Digest, SHA256, digestFromByteString, hash)
import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.PublicKey (certPublicKey)
import qualified Crypto.WebAuthn.PublicKey as PublicKey
import qualified Data.ASN1.Parse as ASN1
import qualified Data.ASN1.Types as ASN1
import Data.Bifunctor (first)
import qualified Data.ByteArray as BA
import Data.FileEmbed (embedFile)
import Data.HashMap.Strict (HashMap, (!?))
import Data.List.NonEmpty (NonEmpty ((:|)), toList)
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

data DecodingError
  = -- | The provided CBOR encoded data was malformed. Either because a field
    -- was missing, or because the field contained the wrong type of data
    DecodingErrorUnexpectedCBORStructure (HashMap Text CBOR.Term)
  | -- | An error occurred during the decoding of the certificate
    DecodingErrorCertificate String
  | -- | An error occurred during the decoding of the public key in the certificate
    DecodingErrorPublicKey X509.PubKey
  | -- | The required apple extension is missing from the certificate
    DecodingErrorCertificateExtensionMissing
  deriving (Show, Exception)

data VerificationError
  = -- | The nonce found in the certificate extension does not match the
    -- expected nonce
    -- (first: expected, second: received)
    NonceMismatch (Digest SHA256) (Digest SHA256)
  | -- | The public Key found in the certificate does not match the
    -- credential's public key.
    -- (first: credential, second: certificate)
    PublickeyMismatch PublicKey.PublicKey PublicKey.PublicKey
  deriving (Show, Exception)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation)
-- We extend the statement to include values we would further have to decode
-- during the verification procedure.
data Statement = Statement
  { x5c :: NE.NonEmpty X509.SignedCertificate,
    sNonce :: Digest SHA256,
    subjectPublicKey :: PublicKey.PublicKey
  }
  deriving (Eq, Show)

-- | Undocumented, but the Apple Nonce Extension should only contain the nonce
newtype AppleNonceExtension = AppleNonceExtension
  { nonce :: Digest SHA256
  }
  deriving (Eq, Show)

instance X509.Extension AppleNonceExtension where
  extOID = const [1, 2, 840, 113635, 100, 8, 2]
  extHasNestedASN1 = const False
  extEncode = error "extEncode for AppleNonceExtension is unimplemented"
  extDecode asn1 = ASN1.runParseASN1 decode asn1
    where
      decode :: ASN1.ParseASN1 AppleNonceExtension
      decode = do
        ASN1.OctetString nonce <-
          ASN1.onNextContainer ASN1.Sequence $
            ASN1.onNextContainer (ASN1.Container ASN1.Context 1) ASN1.getNext
        maybe
          (fail "The nonce in the Extention was not a valid SHA256 hash")
          (pure . AppleNonceExtension)
          (digestFromByteString nonce)

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement
  asfIdentifier _ = "apple"

  type AttStmtDecodingError Format = DecodingError
  asfDecode _ xs = case xs !? "x5c" of
    Just (CBOR.TList (NE.nonEmpty -> Just x5cRaw)) -> do
      x5c@(credCert :| _) <- forM x5cRaw $ \case
        CBOR.TBytes certBytes ->
          first DecodingErrorCertificate (X509.decodeSignedCertificate certBytes)
        _ ->
          Left (DecodingErrorUnexpectedCBORStructure xs)

      let cert = X509.getCertificate credCert

      subjectPublicKey <- case certPublicKey cert of
        Nothing -> Left $ DecodingErrorPublicKey (X509.certPubKey cert)
        Just key -> pure key

      AppleNonceExtension {..} <- maybe (Left DecodingErrorCertificateExtensionMissing) pure $ X509.extensionGet $ X509.certExtensions cert

      pure $ Statement x5c nonce subjectPublicKey
    _ -> Left (DecodingErrorUnexpectedCBORStructure xs)

  asfEncode _ Statement {x5c} =
    let encodedx5c = map (CBOR.TBytes . X509.encodeSignedObject) $ toList x5c
     in CBOR.TMap
          [ (CBOR.TString "x5c", CBOR.TList encodedx5c)
          ]

  type AttStmtVerificationError Format = VerificationError

  -- https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
  asfVerify
    _
    Statement {..}
    M.AuthenticatorData {M.adRawData, M.adAttestedCredentialData = credData}
    clientDataHash = do
      -- 1. Let authenticatorData denote the authenticator data for the
      -- attestation, and let clientDataHash denote the hash of the serialized
      -- client data.
      -- NOTE: Done in decoding

      -- 2. Concatenate authenticatorData and clientDataHash to form
      -- nonceToHash.
      let nonceToHash = M.unRaw adRawData <> BA.convert (M.unClientDataHash clientDataHash)

      -- 3. Perform SHA-256 hash of nonceToHash to produce nonce.
      let nonce :: Digest SHA256 = hash nonceToHash

      -- 4. Verify that nonce equals the value of the extension with OID
      -- 1.2.840.113635.100.8.2 in credCert.
      unless (nonce == sNonce) . Left $ NonceMismatch nonce sNonce

      -- 5. Verify that the credential public key equals the Subject Public Key
      -- of credCert.
      let credentialPublicKey = M.acdCredentialPublicKey credData
      unless (credentialPublicKey == subjectPublicKey) . Left $ PublickeyMismatch credentialPublicKey subjectPublicKey

      -- 6. If successful, return implementation-specific values representing
      -- attestation type Anonymization CA and attestation trust path x5c.
      pure $
        M.SomeAttestationType $
          M.AttestationTypeVerifiable M.VerifiableAttestationTypeAnonCA (M.Fido2Chain x5c)

  asfTrustAnchors _ _ = rootCertificateStore

rootCertificateStore :: X509.CertificateStore
rootCertificateStore = X509.makeCertificateStore [rootCertificate]

-- | The root certificate used for apple attestation formats
rootCertificate :: X509.SignedCertificate
rootCertificate = case X509.decodeSignedCertificate $(embedFile "root-certs/apple/Apple_WebAuthn_Root_CA.crt") of
  Left err -> error $ "Error while decoding Apple root certificate: " <> err
  Right cert -> cert

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
