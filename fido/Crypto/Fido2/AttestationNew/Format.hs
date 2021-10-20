{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.AttestationNew.Format
  ( VerifiableAttestationStatementFormat (..),
    DecodableAttestationStatementFormat (..),
    SomeAttestationStatementFormat (..),
    SupportedAttestationStatementFormats (..),
    mkSupportedAttestationStatementFormats,
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import qualified Crypto.Fido2.Model as M
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HashMap
import Data.Kind (Type)
import Data.Text (Text)
import qualified Data.Text as Text

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

-- | Extends the 'M.AttestationStatementFormat' class with the ability for the
-- attestation statement to be decoded from a CBOR map.
class
  ( M.AttestationStatementFormat a,
    Exception (AttStmtDecodingError a)
  ) =>
  DecodableAttestationStatementFormat a
  where
  -- | The type of decoding errors that can occur when decoding this
  -- attestation statement using 'asfDecode'
  type AttStmtDecodingError a :: Type

  -- | A decoder for the attestation statement [syntax](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats).
  -- The @attStmt@ CBOR map is given as an input. See
  -- [Generating an Attestation Object](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
  asfDecode ::
    a ->
    HashMap Text CBOR.Term ->
    Either (AttStmtDecodingError a) (M.AttStmt a)

-- | An arbitrary [attestation statement format](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats).
-- In contrast to 'DecodingAttestationStatementFormat', this type can be put into a list.
-- This is used for 'mkSupportedAttestationStatementFormats'
data SomeAttestationStatementFormat
  = forall a.
    ( VerifiableAttestationStatementFormat a,
      DecodableAttestationStatementFormat a
    ) =>
    SomeAttestationStatementFormat a

-- | A type representing the set of supported attestation statement formats.
-- The constructor is intentionally not exported, use
-- 'mkSupportedAttestationStatementFormats' instead
newtype SupportedAttestationStatementFormats
  = -- HashMap invariant: asfIdentifier (hm ! k) == k
    SupportedAttestationStatementFormats (HashMap Text SomeAttestationStatementFormat)

-- | Creates a valid 'SupportedAttestationStatementFormats' from a list of 'SomeAttestationStatementFormat's.
mkSupportedAttestationStatementFormats :: [SomeAttestationStatementFormat] -> SupportedAttestationStatementFormats
mkSupportedAttestationStatementFormats formats = SupportedAttestationStatementFormats asfMap
  where
    asfMap = HashMap.fromListWithKey merge (map withIdentifier formats)
    merge ident _ _ =
      error $
        "mkSupportedAttestationStatementFormats: Duplicate attestation statement format identifier \""
          <> Text.unpack ident
          <> "\""
    withIdentifier someFormat@(SomeAttestationStatementFormat format) =
      (M.asfIdentifier format, someFormat)
