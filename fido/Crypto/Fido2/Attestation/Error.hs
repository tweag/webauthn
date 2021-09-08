module Crypto.Fido2.Attestation.Error (Error (..)) where

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
  deriving (Show, Eq)
