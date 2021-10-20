{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.AttestationNew.None (asfNone, AttestationStatementFormatNone (AttestationStatementFormatNone)) where

import qualified Crypto.Fido2.AttestationNew.Format as F
import qualified Crypto.Fido2.Model as M
import Data.Void (Void)

data AttestationStatementFormatNone = AttestationStatementFormatNone
  deriving (Show)

instance M.AttestationStatementFormat AttestationStatementFormatNone where
  type AttStmt AttestationStatementFormatNone = ()
  asfIdentifier _ = "none"

instance F.DecodableAttestationStatementFormat AttestationStatementFormatNone where
  type AttStmtDecodingError AttestationStatementFormatNone = Void
  asfDecode _ _ = Right ()

instance F.VerifiableAttestationStatementFormat AttestationStatementFormatNone where
  type AttStmtVerificationError AttestationStatementFormatNone = Void
  asfVerify _ _ _ _ = Right M.AttestationTypeNone

asfNone :: F.SomeAttestationStatementFormat
asfNone = F.SomeAttestationStatementFormat AttestationStatementFormatNone
