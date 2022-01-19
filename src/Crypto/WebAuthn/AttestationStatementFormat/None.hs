{-# LANGUAGE TypeFamilies #-}

-- | Stability: experimental
-- This module implements the
-- [None Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-none-attestation).
-- Note that this attestation statement format is currently not registered in the
-- [WebAuthn Attestation Statement Format Identifiers IANA registry](https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids).
module Crypto.WebAuthn.AttestationStatementFormat.None
  ( format,
    Format (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Data.Text as Text
import Data.Void (Void)

-- | The None format. The sole purpose of this type is to instantiate the
-- AttestationStatementFormat typeclass below.
data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

instance M.AttestationStatementFormat Format where
  type AttStmt Format = ()
  asfIdentifier _ = "none"

  asfDecode _ _ = Right ()
  asfEncode _ _ = CBOR.TMap []

  type AttStmtVerificationError Format = Void
  asfVerify _ _ _ _ _ = pure $ M.SomeAttestationType M.AttestationTypeNone

  asfTrustAnchors _ _ = mempty

-- | Helper function that wraps the None format into the general
-- SomeAttestationStatementFormat type.
format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
