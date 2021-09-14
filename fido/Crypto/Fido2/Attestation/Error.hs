module Crypto.Fido2.Attestation.Error (Error (..)) where

-- TODO: Add supplementary fields giving more error info
data Error
  = InvalidWebauthnType
  | ChallengeDidNotMatch
  | OriginDidNotMatch
  | RpIdMismatch
  | UserNotPresent
  | UserNotVerified
  | UnsupportedAttestationFormat
  | InvalidAttestationStatement
  | NoAttestedCredentialDataFound
  | NotTrustworthy
  | InvalidAlgorithm
  | InvalidCertificate
  | DecodingError
  | InvalidSignature
  deriving (Show, Eq)
