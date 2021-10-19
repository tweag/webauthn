{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.AttestationNew.None (asfNone, AttestationStatementFormatNone (AttestationStatementFormatNone)) where

import qualified Crypto.Fido2.AttestationNew as V
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript.Decoding as D
import Data.Void (Void)

data AttestationStatementFormatNone = AttestationStatementFormatNone
  deriving (Show)

instance M.AttestationStatementFormat AttestationStatementFormatNone where
  type AttStmt AttestationStatementFormatNone = ()
  asfIdentifier _ = "none"

instance D.DecodableAttestationStatementFormat AttestationStatementFormatNone where
  type AttStmtDecodingError AttestationStatementFormatNone = Void
  asfDecode _ _ = Right ()

instance V.VerifiableAttestationStatementFormat AttestationStatementFormatNone where
  type AttStmtVerificationError AttestationStatementFormatNone = Void
  asfVerify _ _ _ _ = Right M.AttestationTypeNone

asfNone :: D.SomeAttestationStatementFormat
asfNone = D.SomeAttestationStatementFormat AttestationStatementFormatNone
