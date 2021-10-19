{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.AttestationNew
  ( VerifiableAttestationStatementFormat (..),
  )
where

import Control.Exception (Exception)
import qualified Crypto.Fido2.Model as M
import Data.Kind (Type)

-- | Extends the 'M.AttestationStatementFormat' class with the ability for the
-- attestation statement to be verified.
class
  (Exception (AttStmtVerificationError a), M.AttestationStatementFormat a) =>
  VerifiableAttestationStatementFormat a
  where
  -- | The type of verification errors that can occur when verifying this
  -- attestation statement using 'asfVerify'
  type AttStmtVerificationError a :: Type

  -- | [(spec)](https://www.w3.org/TR/webauthn-2/#verification-procedure)
  -- The procedure to verify an [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement)
  asfVerify ::
    a ->
    M.AttStmt a ->
    M.AuthenticatorData 'M.Create ->
    M.ClientDataHash ->
    Either (AttStmtVerificationError a) M.AttestationType
