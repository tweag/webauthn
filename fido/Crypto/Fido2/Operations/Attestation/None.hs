{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Operations.Attestation.None
  ( format,
    Format (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import qualified Crypto.Fido2.Model as M
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
  asfVerify _ _ _ _ = pure $ M.AttStmtVerificationResult M.AttestationTypeNone M.UnknownAuthenticator

  asfTrustAnchors _ _ = mempty

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
