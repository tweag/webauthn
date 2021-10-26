module Crypto.Fido2.Operations.Common
  ( CredentialEntry (..),
    failure,
  )
where

import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.PublicKey (PublicKey)
import Data.List.NonEmpty (NonEmpty)
import Data.Validation (Validation (Failure))

data CredentialEntry = CredentialEntry
  { ceUserHandle :: M.UserHandle,
    cePublicKey :: PublicKey,
    ceSignCounter :: M.SignatureCounter
  }

failure :: e -> Validation (NonEmpty e) a
failure = Failure . pure
