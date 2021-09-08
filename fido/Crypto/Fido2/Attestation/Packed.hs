-- | Implements step 1-3 of the verification procedure of chapter 8.2
module Crypto.Fido2.Attestation.Packed (verify) where

import Codec.CBOR.Decoding (Decoder)
import Codec.CBOR.Term (Term (TInt, TString, TBytes))
import Crypto.Fido2.Attestation.Error (Error (NotTrustworthy))
import Crypto.Fido2.Protocol (AttestedCredentialData, AuthenticatorData)
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier, toAlg)
import Crypto.Hash (Digest, SHA256)
import Data.ByteString (ByteString)
import qualified Data.Map as Map
import Debug.Trace (traceShow)

verify :: [(Term, Term)] -> AuthenticatorData -> Digest SHA256 -> Either Error AttestedCredentialData
verify attStmt authData clientDataHash = do
  -- statement <- decodePackedStmt
  -- 
  -- let athAlg = attestedCredentialData authData
  undefined
