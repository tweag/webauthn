{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.AttestationNew.None (asfNone) where

import qualified Crypto.Fido2.AttestationNew as V
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript.Decoding as D
import Data.Void (Void)

data None = None
  deriving (Show)

instance M.AttestationStatementFormat None where
  type AttStmt None = ()
  asfIdentifier _ = "none"

instance D.DecodingAttestationStatementFormat None where
  type AttStmtDecodingError None = Void
  asfDecode _ _ = Right ()

instance V.VerifiableAttestationStatementFormat None where
  type AttStmtValidationError None = Void
  asfVerify _ _ _ _ = Right M.AttestationTypeNone

asfNone :: D.SomeAttestationStatementFormat
asfNone = D.SomeAttestationStatementFormat None
