{-# LANGUAGE RecordWildCards #-}

module Crypto.Fido2.Operations.Common
  ( CredentialEntryRaw (..),
    decodeCredentialEntry,
    CredentialEntry (..),
    failure,
  )
where

import qualified Codec.CBOR.Read as CBOR
import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.PublicKey (PublicKey, decodePublicKey)
import qualified Data.ByteString.Lazy as LBS
import Data.List.NonEmpty (NonEmpty)
import Data.Validation (Validation (Failure))

data CredentialEntryRaw = CredentialEntryRaw
  { cerUserHandle :: M.UserHandle,
    cerCredentialId :: M.CredentialId,
    cerPublicKeyBytes :: M.PublicKeyBytes,
    cerSignCounter :: M.SignatureCounter
  }
  deriving (Show)

decodeCredentialEntry :: CredentialEntryRaw -> Either CBOR.DeserialiseFailure CredentialEntry
decodeCredentialEntry CredentialEntryRaw {..} = do
  let ceUserHandle = cerUserHandle
  let ceCredentialId = cerCredentialId
  (_, cePublicKey) <-
    CBOR.deserialiseFromBytes decodePublicKey $
      LBS.fromStrict $ M.unPublicKeyBytes cerPublicKeyBytes
  let ceSignCounter = cerSignCounter
  pure $ CredentialEntry {..}

data CredentialEntry = CredentialEntry
  { ceUserHandle :: M.UserHandle,
    ceCredentialId :: M.CredentialId,
    cePublicKey :: PublicKey,
    ceSignCounter :: M.SignatureCounter
  }
  deriving (Show)

failure :: e -> Validation (NonEmpty e) a
failure = Failure . pure
