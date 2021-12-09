{-# LANGUAGE RecordWildCards #-}

module Crypto.WebAuthn.Operations.Common
  ( CredentialEntry (..),
    failure,
  )
where

import qualified Crypto.WebAuthn.Model as M
import Data.List.NonEmpty (NonEmpty)
import Data.Validation (Validation (Failure))

-- | This type represents the database row that a Relying Party server needs
-- to store for each credential that's registered to a user
data CredentialEntry = CredentialEntry
  { ceCredentialId :: M.CredentialId,
    ceUserHandle :: M.UserHandle,
    cePublicKeyBytes :: M.PublicKeyBytes,
    ceSignCounter :: M.SignatureCounter
  }
  deriving (Eq, Show)

failure :: e -> Validation (NonEmpty e) a
failure = Failure . pure
