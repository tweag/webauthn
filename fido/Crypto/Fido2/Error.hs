module Crypto.Fido2.Error (CommonError (..), DecodingError (..), AttestationError (..), AssertionError (..)) where

import qualified Codec.CBOR.Read as CBOR
import Crypto.Error (CryptoError)
import Data.ASN1.Error (ASN1Error)
import qualified Data.Aeson.Types as Aeson
import Data.Binary.Get (ByteOffset)
import Data.ByteString.Lazy (ByteString)
import Data.Text (Text)

-- | Errors that are shared between attestation and assertion
data CommonError
  = -- | The given attestation type did not match the correct method
    InvalidWebauthnType
  | -- | The returned challenge does not match the desired one
    ChallengeMismatch
  | -- | The returned credential cannot be found in the known credentials
    CredentialMismatch
  | -- | The returned origin does not match the relying party's origin
    RpOriginMismatch
  | -- | The hash of the relying party id does not match the has in the returned authentication data
    RpIdHashMismatch
  | -- | The userpresent bit in the authdata was not set
    UserNotPresent
  | -- | The userverified bit in the authdata was not set
    UserNotVerified
  | -- | The provided signature is not valid over the authData and hash
    InvalidSignature
  | -- | An wrapper around the CryptoError type from the cryptonite library
    CryptoFailure CryptoError
  | -- | The desired curve is not supported by this implementation or by the fido2 specification
    -- TODO: Use
    CryptoCurveUnsupported
  | -- | The desired algorithm is not supported by this implementation or by the fido2 specification
    -- TODO: Use
    CryptoAlgorithmUnsupported
  | -- | The desired key type is not supported by this implementation or by the fido2 specification
    -- TODO: Use
    CryptoKeyTypeUnsupported
  | -- | Any part of the data could not be decoded for the provided reason
    DecodingError DecodingError
  deriving (Show, Eq)

-- | Any error that occurs during decoding
data DecodingError
  = -- | The base64 encoded data could not be decoded
    Base64Failure
  | -- | The CBOR encoded data could not be decoded for the provided reason
    CBORFailure CBOR.DeserialiseFailure
  | -- | The JSON data could not be parsed
    JSONFailure Aeson.JSONPath String
  | -- | The binary data could not be decoded
    BinaryFailure (ByteString, ByteOffset, String)
  | -- | The desired attestation format is not supported
    FormatUnsupported Text
  deriving (Show, Eq)

-- | Any error that occurs during assertion
newtype AssertionError
  = -- | A common error occured
    -- TODO: Currently, assertion only results in common errors, although this might not strictly be true.
    -- A re-evaluation is needed after attestation has been fully implemented
    AssertionCommonError CommonError
  deriving (Show, Eq)

-- | Any error that occurs during attestation
data AttestationError
  = -- | No attested credential was found
    CredentialDataMissing
  | -- | The algorithm in the attestation statement differs from the algorithm
    --   corresponding to the public key in the authentication data
    StatementAlgorithmMismatch
  | -- | The attestation format was none, but attestation data was still present.
    StatementPresentForNone
  | -- | No AAGUID was found in the attested credential data
    AttestationCredentialAAGUIDMissing
  | -- | The certificate's trust could not be established. This could be because it was unsigned,
    -- or the signed certificate was not found in the certificate store.
    TrustFailure
  | -- | The AAGUID of the credential data differs from the AAGUID in the certificate of the statement
    CertificateAAGUIDMismatch
  | -- | The specified TPM field does not match
    TPMMismatch Text
  | -- | The specified TPM field is invalid
    TPMInvalid Text
  | -- | https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation-cert-requirements
    CertificateRequirementsUnmet
  | -- | The certificate could not be parsed in a way to retrieve the public key
    -- TODO: Maybe a different name?
    CertiticatePublicKeyInvalid
  | -- | The ASN1 decoding failed for the provided reason
    ASN1Error ASN1Error
  | -- | A common error occured during attestation
    AttestationCommonError CommonError
  deriving (Show, Eq)
