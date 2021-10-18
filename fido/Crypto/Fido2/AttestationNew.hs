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

-- TODO: Document
class
  (Exception (AttStmtValidationError a), M.AttestationStatementFormat a) =>
  VerifiableAttestationStatementFormat a
  where
  type AttStmtValidationError a :: Type
  asfVerify ::
    a ->
    M.AttStmt a ->
    M.AuthenticatorData 'M.Create ->
    M.ClientDataHash ->
    Either (AttStmtValidationError a) M.AttestationType
