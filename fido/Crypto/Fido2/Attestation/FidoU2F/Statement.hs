-- | Implements step 1-2 of the verification procedure of chapter 8.6
module Crypto.Fido2.Attestation.FidoU2F.Statement
  ( Stmt (Stmt, sig, attCert),
    decode,
  )
where

import Codec.CBOR.Decoding (Decoder)
import Codec.CBOR.Term (Term (TBytes, TList, TString))
import Data.ByteString (ByteString)
import qualified Data.Map as Map
import qualified Data.X509 as X509

-- u2fStmtFormat (https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation)
-- Doesn't conform to spec since we already test some of the requirements during decodig (unlike what the specification proposes)
data Stmt = Stmt
  { sig :: ByteString,
    attCert :: X509.SignedCertificate
  }
  deriving (Show)

decode :: [(Term, Term)] -> Decoder s Stmt
decode xs = do
  let m = Map.fromList xs
  TBytes sig <- maybe (fail "no sig") pure $ Map.lookup (TString "sig") m
  -- 2. Check that x5c has exactly one element and let attCert be that element.
  attCert <- case Map.lookup (TString "x5c") m of
    Just (TList [TBytes certBytes]) ->
      either fail pure $ X509.decodeSignedCertificate certBytes
    Just (TList _) -> fail "more than one certificate found"
    _ -> fail "could not decode the certificate from the attestation statement"
  pure $ Stmt sig attCert
