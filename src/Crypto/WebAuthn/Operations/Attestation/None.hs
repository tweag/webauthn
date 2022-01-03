{-# LANGUAGE TypeFamilies #-}

module Crypto.WebAuthn.Operations.Attestation.None
  ( format,
    Format (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import qualified Crypto.WebAuthn.Model as M
import qualified Data.Text as Text
import Data.Void (Void)

data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

instance M.AttestationStatementFormat Format where
  type AttStmt Format = ()
  asfIdentifier _ = "none"

  type AttStmtDecodingError Format = Void
  asfDecode _ _ = Right ()
  asfEncode _ _ = CBOR.TMap []

  type AttStmtVerificationError Format = Void
  asfVerify _ _ _ _ = pure $ M.SomeAttestationType M.AttestationTypeNone

  asfTrustAnchors _ _ = mempty

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
