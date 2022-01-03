{-# LANGUAGE RecordWildCards #-}

module Crypto.WebAuthn.Operations.Common
  ( CredentialEntry (..),
    failure,
    IdFidoGenCeAAGUID (..),
  )
where

import qualified Crypto.WebAuthn.Model as M
import Data.ASN1.Parse (ParseASN1, getNext, runParseASN1)
import Data.ASN1.Types (ASN1 (OctetString))
import Data.Aeson (ToJSON)
import Data.Bifunctor (Bifunctor (first))
import qualified Data.ByteString.Lazy as LBS
import Data.List.NonEmpty (NonEmpty)
import qualified Data.UUID as UUID
import Data.Validation (Validation (Failure))
import Data.X509 (Extension, extDecode, extEncode, extHasNestedASN1, extOID)
import GHC.Generics (Generic)

-- | This type represents the database row that a Relying Party server needs
-- to store for each credential that's registered to a user
data CredentialEntry = CredentialEntry
  { ceCredentialId :: M.CredentialId,
    ceUserHandle :: M.UserHandle,
    cePublicKeyBytes :: M.PublicKeyBytes,
    ceSignCounter :: M.SignatureCounter
  }
  deriving (Eq, Show, Generic, ToJSON)

failure :: e -> Validation (NonEmpty e) a
failure = Failure . pure

newtype IdFidoGenCeAAGUID = IdFidoGenCeAAGUID M.AAGUID
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
          Just aaguid -> pure $ IdFidoGenCeAAGUID $ M.AAGUID aaguid
          Nothing -> fail "Could not extract aaguid"
