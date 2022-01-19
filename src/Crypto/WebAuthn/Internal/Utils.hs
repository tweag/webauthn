{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RecordWildCards #-}

-- | Stability: internal
--
-- Internal utilities
module Crypto.WebAuthn.Internal.Utils
  ( JSONEncoding,
    EnumJSONEncoding,
    Aeson.CustomJSON (..),
    Lowercase,
    failure,
    certificateSubjectKeyIdentifier,
    IdFidoGenCeAAGUID (..),
    AppleNonceExtension (..),
  )
where

import Control.Monad (void)
import Crypto.Hash (hash)
import qualified Crypto.Hash as Hash
import Crypto.WebAuthn.Model.Identifier (AAGUID (AAGUID), SubjectKeyIdentifier (SubjectKeyIdentifier))
import qualified Data.ASN1.BitArray as ASN1
import Data.ASN1.Parse (ParseASN1, getNext, runParseASN1)
import qualified Data.ASN1.Parse as ASN1
import Data.ASN1.Prim (ASN1 (OctetString))
import qualified Data.ASN1.Types as ASN1
import Data.Bifunctor (first)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Char (toLower)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.UUID as UUID
import Data.Validation (Validation (Failure))
import Data.X509 (Extension)
import qualified Data.X509 as X509
import qualified Deriving.Aeson as Aeson
import GHC.TypeLits (Symbol)

-- | Custom JSONEncoding for use in the library. We add a "lit" prefix to every
-- field that would otherwise be a Haskell keyword.
type JSONEncoding = Aeson.CustomJSON '[Aeson.OmitNothingFields, Aeson.FieldLabelModifier (Aeson.StripPrefix "lit")]

-- | Type for 'Aeson.StringModifier' that makes all characters lowercase
data Lowercase

-- | Deriving.Aeson instance turning a string into lowercase.
instance Aeson.StringModifier Lowercase where
  getStringModifier = map toLower

-- | Custom JSON Encoding for enumerations, strips the given prefix and maps
-- all constructors to lowercase.
type EnumJSONEncoding (prefix :: Symbol) = Aeson.CustomJSON '[Aeson.ConstructorTagModifier '[Aeson.StripPrefix prefix, Lowercase]]

-- | A convenience function for creating a 'Validation' failure of a single
-- 'NonEmpty' value
failure :: e -> Validation (NonEmpty e) a
failure = Failure . pure

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

-- | The `id-fido-gen-ce-aaguid` contains the AAGUID of the authenticator.
newtype IdFidoGenCeAAGUID = IdFidoGenCeAAGUID AAGUID
  deriving (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements)
instance Extension IdFidoGenCeAAGUID where
  extOID = const [1, 3, 6, 1, 4, 1, 45724, 1, 1, 4]
  extHasNestedASN1 = const True
  extEncode = error "Unimplemented: This library does not implement encoding the ID_FIDO_GEN_CE_AAGUID extension"
  extDecode asn1 =
    first ("Could not decode ASN1 id-fido-gen-ce-aaguid extension: " ++) $
      runParseASN1 decodeFidoAAGUID asn1
    where
      decodeFidoAAGUID :: ParseASN1 IdFidoGenCeAAGUID
      decodeFidoAAGUID = do
        OctetString bytes <- getNext
        case UUID.fromByteString $ LBS.fromStrict bytes of
          Just aaguid -> pure $ IdFidoGenCeAAGUID $ AAGUID aaguid
          Nothing -> fail "Could not extract aaguid"

-- | An Apple specific X509 certificate extension.
-- Undocumented, but the Apple Nonce Extension should only contain the nonce.
-- Encoding of the extension is used during emulation tests.
newtype AppleNonceExtension = AppleNonceExtension
  { nonce :: Hash.Digest Hash.SHA256
  }
  deriving (Eq, Show)

instance X509.Extension AppleNonceExtension where
  extOID = const [1, 2, 840, 113635, 100, 8, 2]
  extHasNestedASN1 = const False
  extEncode AppleNonceExtension {..} =
    [ ASN1.Start ASN1.Sequence,
      ASN1.Start $ ASN1.Container ASN1.Context 1,
      ASN1.OctetString $ BA.convert nonce,
      ASN1.End $ ASN1.Container ASN1.Context 1,
      ASN1.End ASN1.Sequence
    ]
  extDecode = ASN1.runParseASN1 decode
    where
      decode :: ASN1.ParseASN1 AppleNonceExtension
      decode = do
        ASN1.OctetString nonce <-
          ASN1.onNextContainer ASN1.Sequence $
            ASN1.onNextContainer (ASN1.Container ASN1.Context 1) ASN1.getNext
        maybe
          (fail "The nonce in the Extention was not a valid SHA256 hash")
          (pure . AppleNonceExtension)
          (Hash.digestFromByteString nonce)
