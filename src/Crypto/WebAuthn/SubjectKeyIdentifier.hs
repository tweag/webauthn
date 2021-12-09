module Crypto.WebAuthn.SubjectKeyIdentifier
  ( SubjectKeyIdentifier (..),
    certificateSubjectKeyIdentifier,
  )
where

import Control.Monad (void)
import Crypto.Hash (Digest, SHA1, hash)
import qualified Data.ASN1.BitArray as ASN1
import qualified Data.ASN1.Parse as ASN1
import qualified Data.ASN1.Types as ASN1
import qualified Data.ByteString as BS
import qualified Data.X509 as X509

-- | [(spec)](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2)
-- The subject key identifier extension provides a means of identifying
-- certificates that contain a particular public key.
-- This type represents method 1 of computing the identifier, as used in the
-- [attestationCertificateKeyIdentifiers](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#dom-metadatablobpayloadentry-attestationcertificatekeyidentifiers)
-- field of the [Metadata Service](https://fidoalliance.org/metadata/)
newtype SubjectKeyIdentifier = SubjectKeyIdentifier {unSubjectKeyIdentifier :: Digest SHA1}
  deriving (Eq, Show)

-- | [(spec)](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2)
-- Computes the 'SubjectKeyIdentifier' from a 'X509.Certificate' according to
-- method 1 in the above specification.
-- Note that this function only fails if the 'ASN1.ASN1Object' instance of
-- 'X509.PubKey' has a bug
certificateSubjectKeyIdentifier :: X509.Certificate -> SubjectKeyIdentifier
certificateSubjectKeyIdentifier cert = SubjectKeyIdentifier . hash $ publicKeyBytes
  where
    -- The x509 library doesn't expose the public key bytes directly
    -- so we instead render the ASN.1 from the public key,
    -- then decode only the public key bytes
    asns = ASN1.toASN1 (X509.certPubKey cert) []
    err = error $ "Failed to decode the public key from the ASN.1 object generated: " <> show asns
    publicKeyBytes = either err id $ ASN1.runParseASN1 parsePublicKeyBytes asns

    -- SubjectPublicKeyInfo  ::=  SEQUENCE  {
    --      algorithm            AlgorithmIdentifier,
    --      subjectPublicKey     BIT STRING  }
    parsePublicKeyBytes :: ASN1.ParseASN1 BS.ByteString
    parsePublicKeyBytes = ASN1.onNextContainer ASN1.Sequence $ do
      -- AlgorithmIdentifier  ::=  SEQUENCE  { ... }
      -- We're not interested in this
      void $ ASN1.getNextContainer ASN1.Sequence
      ASN1.BitString bitArray <- ASN1.getNext
      if ASN1.bitArrayLength bitArray `mod` 8 == 0
        then pure $ ASN1.bitArrayGetData bitArray
        else -- This should never happen, because the x509 libraries 'ASN1.ASN1Object'
        -- instance for 'X509.PubKey' always inserts 8-bit aligned bit strings
          ASN1.throwParseError "subjectPublicKey is not 8-bit aligned!"
