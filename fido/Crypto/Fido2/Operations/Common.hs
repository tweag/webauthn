{-# LANGUAGE RecordWildCards #-}

module Crypto.Fido2.Operations.Common
  ( CredentialEntry (..),
    failure,
  )
where

import qualified Crypto.Fido2.Model as M
import Data.List.NonEmpty (NonEmpty)
import Data.Validation (Validation (Failure))

-- | This type represents the database row that a Relying Party server needs
-- to store for each credential that's registered to a user
data CredentialEntry = CredentialEntry
  { ceUserHandle :: M.UserHandle,
    ceCredentialId :: M.CredentialId,
    cePublicKeyBytes :: M.PublicKeyBytes,
    ceSignCounter :: M.SignatureCounter
  }
  deriving (Show)

failure :: e -> Validation (NonEmpty e) a
failure = Failure . pure
