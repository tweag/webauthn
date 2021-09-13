-- | Implements step 1-3 of the verification procedure of chapter 8.2
module Crypto.Fido2.Attestation.Packed.Statement (Stmt (Stmt, alg, sig, x5c), decode) where

import Codec.CBOR.Decoding (Decoder)
import Codec.CBOR.Term (Term (TBytes, TInt, TList, TString))
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier, toAlg)
import Data.ByteString (ByteString)
import qualified Data.Map as Map
import qualified Data.X509 as X509

-- packedStmtFormat (https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation)
data Stmt = Stmt
  { alg :: COSEAlgorithmIdentifier,
    sig :: ByteString,
    x5c :: Maybe (X509.SignedExact X509.Certificate)
  }
  deriving (Show)

decode :: [(Term, Term)] -> Decoder s Stmt
decode xs = do
  let m = Map.fromList xs
  TInt algId <- maybe (fail "no alg") pure $ Map.lookup (TString "alg") m
  alg <- toAlg algId
  TBytes sig <- maybe (fail "no sig") pure $ Map.lookup (TString "sig") m
  x5c <- case Map.lookup (TString "x5c") m of
    -- TODO: Can we discard the rest?
    Just (TList (TBytes certBytes : _)) ->
      either fail (pure . pure) $ X509.decodeSignedCertificate certBytes
    _ -> pure Nothing
  pure $ Stmt alg sig x5c
