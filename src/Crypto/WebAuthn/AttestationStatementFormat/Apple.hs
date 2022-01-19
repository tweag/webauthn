{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

-- | Stability: experimental
-- This module implements the
-- [Apple Anonymous Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation).
-- Note that this attestation statement format is currently not registered in the
-- [WebAuthn Attestation Statement Format Identifiers IANA registry](https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids).
module Crypto.WebAuthn.AttestationStatementFormat.Apple
  ( format,
    Format (..),
    Statement (..),
    VerificationError (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM)
import Control.Monad.Cont (unless)
import Crypto.Hash (Digest, SHA256, hash)
import qualified Crypto.WebAuthn.Cose.Internal.Verify as Cose
import Crypto.WebAuthn.Internal.Utils (AppleNonceExtension (AppleNonceExtension, nonce), failure)
import qualified Crypto.WebAuthn.Model.Types as M
import Data.Aeson (ToJSON, object, toJSON, (.=))
import Data.Bifunctor (first)
import qualified Data.ByteArray as BA
import Data.FileEmbed (embedFile)
import Data.HashMap.Strict ((!?))
import Data.List.NonEmpty (NonEmpty ((:|)), toList)
import qualified Data.List.NonEmpty as NE
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

-- | The Apple format. The sole purpose of this type is to instantiate the
-- AttestationStatementFormat typeclass below.
data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | Verification errors specific to Apple attestation
data VerificationError
  = -- | The nonce found in the certificate extension does not match the
    -- expected nonce
    -- (first: expected, second: received)
    NonceMismatch (Digest SHA256) (Digest SHA256)
  | -- | The public Key found in the certificate does not match the
    -- credential's public key.
    -- (first: credential, second: certificate)
    PublickeyMismatch Cose.PublicKey Cose.PublicKey
  deriving (Show, Exception)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation)
-- We extend the statement to include values we would further have to decode
-- during the verification procedure.
data Statement = Statement
  { x5c :: NE.NonEmpty X509.SignedCertificate,
    sNonce :: Digest SHA256,
    pubKey :: Cose.PublicKey
  }
  deriving (Eq, Show)

instance ToJSON Statement where
  toJSON Statement {..} =
    object
      [ "x5c" .= x5c
      ]

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement
  asfIdentifier _ = "apple"

  asfDecode _ xs = case xs !? "x5c" of
    Just (CBOR.TList (NE.nonEmpty -> Just x5cRaw)) -> do
      x5c@(credCert :| _) <- forM x5cRaw $ \case
        CBOR.TBytes certBytes ->
          first (("Failed to decode signed certificate: " <>) . Text.pack) (X509.decodeSignedCertificate certBytes)
        cert ->
          Left $ "Certificate CBOR value is not bytes: " <> Text.pack (show cert)

      let cert = X509.getCertificate credCert

      pubKey <- Cose.fromX509 $ X509.certPubKey cert

      AppleNonceExtension {..} <- case X509.extensionGetE $ X509.certExtensions cert of
        Just (Right ext) -> pure ext
        Just (Left err) -> Left $ "Failed to decode certificate apple nonce extension: " <> Text.pack err
        Nothing -> Left "Certificate apple nonce extension is missing"

      pure $ Statement x5c nonce pubKey
    _ -> Left $ "CBOR map didn't have expected value types (x5c: nonempty list): " <> Text.pack (show xs)

  asfEncode _ Statement {..} =
    let encodedx5c = map (CBOR.TBytes . X509.encodeSignedObject) $ toList x5c
     in CBOR.TMap
          [ (CBOR.TString "x5c", CBOR.TList encodedx5c)
          ]

  type AttStmtVerificationError Format = VerificationError

  -- https://www.w3.org/TR/webauthn-2/#sctn-apple-anonymous-attestation
  asfVerify
    _
    _
    Statement {..}
    M.AuthenticatorData {adAttestedCredentialData = credData, ..}
    clientDataHash = do
      -- 1. Let authenticatorData denote the authenticator data for the
      -- attestation, and let clientDataHash denote the hash of the serialized
      -- client data.
      -- NOTE: Done in decoding

      -- 2. Concatenate authenticatorData and clientDataHash to form
      -- nonceToHash.
      let nonceToHash = M.unRaw adRawData <> BA.convert (M.unClientDataHash clientDataHash)

      -- 3. Perform SHA-256 hash of nonceToHash to produce nonce.
      let nonce = hash nonceToHash

      -- 4. Verify that nonce equals the value of the extension with OID
      -- 1.2.840.113635.100.8.2 in credCert.
      unless (nonce == sNonce) . failure $ NonceMismatch nonce sNonce

      -- 5. Verify that the credential public key equals the Subject Public Key
      -- of credCert.
      let credentialPublicKey = Cose.fromCose $ M.acdCredentialPublicKey credData
      unless (credentialPublicKey == pubKey) . failure $ PublickeyMismatch credentialPublicKey pubKey

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

-- | Helper function that wraps the Apple format into the general
-- SomeAttestationStatementFormat type.
format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
