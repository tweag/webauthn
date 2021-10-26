{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Operations.Attestation.None
  ( format,
    Format (..),
  )
where

import qualified Crypto.Fido2.Model as M
import Data.Void (Void)

data Format = Format
  deriving (Show)

instance M.AttestationStatementFormat Format where
  type AttStmt Format = ()
  asfIdentifier _ = "none"

  type AttStmtDecodingError Format = Void
  asfDecode _ _ = Right ()

  type AttStmtVerificationError Format = Void
  asfVerify _ _ _ _ = Right M.AttestationTypeNone

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
