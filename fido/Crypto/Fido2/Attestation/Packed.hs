-- | Implements step 1-3 of the verification procedure of chapter 8.2
module Crypto.Fido2.Attestation.Packed (verify) where

import Control.Monad (unless, when)
import Crypto.Fido2.Attestation.Error (Error (DecodingError, InvalidAlgorithm, InvalidAttestationStatement, NoAttestedCredentialDataFound))
import Crypto.Fido2.Attestation.Packed.Statement (Stmt (Stmt, alg, sig, x5c))
import Crypto.Fido2.Protocol (AttestedCredentialData (credentialPublicKey), AuthenticatorData (AuthenticatorData, attestedCredentialData, rawData), aaguid)
import Crypto.Fido2.PublicKey (keyAlgorithm)
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Fido2.Signature (verifyX509Sig)
import Crypto.Hash (Digest, SHA256)
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (ASN1Decoding (decodeASN1))
import qualified Data.ASN1.OID as OID (OID, getObjectID)
import Data.ASN1.Prim (ASN1 (OctetString))
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (fromStrict)
import Data.Foldable (find)
import Data.Maybe (isJust)
import qualified Data.X509 as X509

verify :: Stmt -> AuthenticatorData -> Digest SHA256 -> Either Error AttestedCredentialData
verify Stmt {alg = stmtAlg, sig = stmtSig, x5c = stmtx5c} authData@AuthenticatorData {rawData = rawAuthData} clientDataHash = do
  let signedData = rawAuthData <> convert clientDataHash
  credData <- maybe (Left NoAttestedCredentialDataFound) pure $ attestedCredentialData authData
  case stmtx5c of
    Nothing -> do
      -- Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
      let key = credentialPublicKey credData
      when (stmtAlg /= keyAlgorithm key) $ Left InvalidAlgorithm

      -- Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.
      unless (PublicKey.verify key signedData stmtSig) $ Left InvalidAttestationStatement

      pure credData
    Just x5c -> do
      let cert = X509.getCertificate x5c
          pubKey = X509.certPubKey cert
      -- Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using
      -- the attestation public key in attestnCert with the algorithm specified in alg.
      verifyX509Sig (X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC) pubKey signedData stmtSig

      -- Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation Statement Certificate
      -- Requirements.
      let dnElements = X509.getDistinguishedElements $ X509.certSubjectDN cert
      unless
        ( hasDnElement X509.DnCountry dnElements
            && hasDnElement X509.DnOrganization dnElements
            && hasDnElement X509.DnCommonName dnElements
            && findDnElement X509.DnOrganizationUnit dnElements == Just "Authenticator Attestation"
        )
        $ Left DecodingError

      -- If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that
      -- the value of this extension matches the aaguid in authenticatorData.
      let (X509.Extensions mX509Exts) = X509.certExtensions cert
          mX509Ext = mX509Exts >>= findProperExtension [1, 3, 6, 1, 4, 1, 45724, 1, 1, 4]
      adAAGUID <- maybe (Left InvalidAttestationStatement) (pure . aaguid) $ attestedCredentialData authData
      case mX509Ext of
        Nothing -> pure ()
        Just ext -> do
          certAAGUID <- decodeAAGUID (X509.extRawContent ext)
          unless (adAAGUID == certAAGUID) (Left InvalidAttestationStatement)

      pure credData
  where
    hasDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Bool
    hasDnElement el = isJust . findDnElement el

    findDnElement :: X509.DnElement -> [(OID.OID, X509.ASN1CharacterString)] -> Maybe X509.ASN1CharacterString
    findDnElement dnElementName = lookup (OID.getObjectID dnElementName)

    findProperExtension :: OID.OID -> [X509.ExtensionRaw] -> Maybe X509.ExtensionRaw
    findProperExtension extensionOID = find ((==) extensionOID . X509.extRawOID)

    decodeAAGUID :: ByteString -> Either Error ByteString
    decodeAAGUID bs = do
      asn1 <- either (const . Left $ DecodingError) pure . decodeASN1 DER $ fromStrict bs
      case asn1 of
        [OctetString s] -> Right s
        _ -> Left DecodingError