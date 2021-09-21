module Crypto.Fido2.Error (Error (..), DecodingError (..), AttestationError (..)) where

import qualified Codec.CBOR.Read as CBOR
import Crypto.Error (CryptoError)
import Data.ASN1.Error (ASN1Error)
import qualified Data.Aeson.Types as Aeson
import Data.Binary.Get (ByteOffset)
import Data.ByteString.Lazy (ByteString)
import Data.Text (Text)

data Error
  = InvalidWebauthnType
  | ChallengeMismatch
  | ChallengeMissing
  | CredentialMismatch
  | RpOriginMismatch
  | RpIdHashMismatch
  | UserNotPresent
  | UserNotVerified
  | InvalidSignature
  | ExtensionsInvalid
  | CryptoFailure CryptoError
  | CryptoCurveUnsupported
  | CryptoAlgorithmUnsupported
  | CryptoKeyTypeUnsupported
  | AttestationError AttestationError
  | DecodingError DecodingError
  deriving (Show, Eq)

data DecodingError
  = Base64Failure
  | CBORFailure CBOR.DeserialiseFailure
  | JSONFailure Aeson.JSONPath String
  | BinaryFailure (ByteString, ByteOffset, String)
  | FormatUnsupported Text
  deriving (Show, Eq)

data AttestationError
  = CredentialDataMissing
  | StatementMissing Text
  | StatementInvalidSignature
  | StatementAlgorithmMismatch
  | -- | The attestation format was none, but attestation data was still present.
    StatementPresentForNone
  | AttestationCredentialDataMissing
  | AttestationCredentialAAGUIDMissing
  | -- | The certificate's trust could not be established. This could be because it was unsigned,
    -- or the signed certificate was not found in the certificate store.
    TrustFailure
  | CertificateAAGUIDMismatch
  | -- | The specified TPM field does not match
    TPMMismatch Text
  | -- | The specified TPM field is invalid
    TPMInvalid Text
  | -- | https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
    CertificateRequirementsUnmet
  | CertiticatePublicKeyInvalid
  | ASN1Error ASN1Error
  deriving (Show, Eq)
