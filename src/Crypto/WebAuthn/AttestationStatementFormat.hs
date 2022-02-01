-- | Stability: experimental
-- This module exports all supported [attestation statement format](https://www.w3.org/TR/webauthn-2/#attestation-statement-format)s by this library.
module Crypto.WebAuthn.AttestationStatementFormat (allSupportedFormats) where

import qualified Crypto.WebAuthn.AttestationStatementFormat.AndroidKey as AndroidKey
import qualified Crypto.WebAuthn.AttestationStatementFormat.AndroidSafetyNet as AndroidSafetyNet
import qualified Crypto.WebAuthn.AttestationStatementFormat.Apple as Apple
import qualified Crypto.WebAuthn.AttestationStatementFormat.FidoU2F as FidoU2F
import qualified Crypto.WebAuthn.AttestationStatementFormat.None as None
import qualified Crypto.WebAuthn.AttestationStatementFormat.Packed as Packed
import qualified Crypto.WebAuthn.AttestationStatementFormat.TPM as TPM
import qualified Crypto.WebAuthn.Model.Types as M

-- | All supported [attestation statement formats](https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats)
-- of this library. This value can be passed to 'Crypto.WebAuthn.Model.WebIDL.Decoding.decodeCreatedPublicKeyCredential'.
-- Since 'M.SupportedAttestationStatementFormats' is a 'Semigroup' the '<>' operator can be used to add additional formats if needed.
allSupportedFormats :: M.AttestationStatementFormatRegistry
allSupportedFormats =
  foldMap
    M.singletonAttestationStatementFormat
    [ None.format,
      Packed.format,
      AndroidKey.format,
      AndroidSafetyNet.format,
      FidoU2F.format,
      Apple.format,
      TPM.format
    ]
