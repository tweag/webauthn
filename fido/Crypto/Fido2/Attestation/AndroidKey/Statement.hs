-- | Implements step 1-3 of the verification procedure of chapter 8.4
module Crypto.Fido2.Attestation.AndroidKey.Statement
  ( Stmt (Stmt, alg, sig, x5c, attExt),
    ExtAttestation (ExtAttestation, attestationChallenge, softwareEnforced, teeEnforced),
    AuthorisationList (AuthorisationList, purpose, allApplications, origin),
    decode,
  )
where

import Codec.CBOR.Decoding (Decoder)
import Codec.CBOR.Term (Term (TBytes, TInt, TList, TString))
import Control.Monad (void)
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier, toAlg)
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Data.ASN1.Parse (ParseASN1, getNext, getNextContainerMaybe, hasNext, onNextContainer, onNextContainerMaybe, runParseASN1)
import Data.ASN1.Types (ASN1 (IntVal, OctetString), ASN1Class (Context), ASN1ConstructionType (Container, Sequence, Set))
import Data.Bifunctor (Bifunctor (first))
import Data.ByteString (ByteString)
import qualified Data.Map as Map
import Data.Set (Set)
import qualified Data.Set as Set
import Data.X509 (Extension, extensionGetE)
import qualified Data.X509 as X509
import Debug.Trace (traceShowId)

-- androidStmtFormat (https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation)
data Stmt = Stmt
  { alg :: COSEAlgorithmIdentifier,
    sig :: ByteString,
    x5c :: X509.SignedExact X509.Certificate,
    -- | Holds the parsed attestation extension of the above X509 certificate
    -- Not part of the spec, but prevents parsing in the AndroidKey.verify function
    attExt :: ExtAttestation
  }
  deriving (Show)

data ExtAttestation = ExtAttestation
  { attestationChallenge :: Digest SHA256,
    softwareEnforced :: AuthorisationList,
    teeEnforced :: AuthorisationList
  }
  deriving (Show)

data AuthorisationList = AuthorisationList
  { purpose :: Maybe (Set Integer),
    allApplications :: Maybe (),
    origin :: Maybe Integer
  }
  deriving (Show)

instance Extension ExtAttestation where
  extOID = const [1, 3, 6, 1, 4, 1, 11129, 2, 1, 17]
  extHasNestedASN1 = const True
  extEncode = error "Can not encode the parsed ExtAttestation to a valid [ASN1] because most fields are dropped during parsing."
  extDecode asn1 = first ("Could not decode ASN1 attestation extension: " ++) $ runParseASN1 decodeExtAttestation (traceShowId asn1)
    where
      decodeExtAttestation :: ParseASN1 ExtAttestation
      decodeExtAttestation = onNextContainer Sequence $ do
        -- Discard the version as the different attestation versions do not differ in a way that is significant to our purpose.
        _attestationVersion <- getNext
        _attestationSecurityLevel <- getNext
        _keyMasterVersion <- getNext
        _keymmasterSecurityLevel <- getNext
        (OctetString attestationChallenge) <- getNext
        _uniqueId <- getNext
        softwareEnforced <- onNextContainer Sequence decodeAttestationList
        teeEnforced <- onNextContainer Sequence decodeAttestationList
        attestationChallengeHash <- maybe (fail "Could not create hash from AttestationChallenge: ") pure $ digestFromByteString attestationChallenge
        pure $ ExtAttestation attestationChallengeHash softwareEnforced teeEnforced

      decodeAttestationList :: ParseASN1 AuthorisationList
      decodeAttestationList = do
        purpose <- onNextContainerMaybe (Container Context 1) (onNextContainer Set $ decodeIntSet Set.empty)
        _algorithm <- getNextContainerMaybe (Container Context 2)
        _keySize <- getNextContainerMaybe (Container Context 3)
        _digest <- getNextContainerMaybe (Container Context 5)
        _padding <- getNextContainerMaybe (Container Context 6)
        _ecCurve <- getNextContainerMaybe (Container Context 10)
        _rsaPublicExponent <- getNextContainerMaybe (Container Context 200)
        _rollbackResistance <- getNextContainerMaybe (Container Context 303)
        _activeDateTime <- getNextContainerMaybe (Container Context 400)
        _originationExpireDateTime <- getNextContainerMaybe (Container Context 401)
        _usageExpireDateTime <- getNextContainerMaybe (Container Context 402)
        _noAuthRequired <- getNextContainerMaybe (Container Context 503)
        _userAuthType <- getNextContainerMaybe (Container Context 504)
        _authTimeout <- getNextContainerMaybe (Container Context 505)
        _allowWhileOnBody <- getNextContainerMaybe (Container Context 506)
        _trustedUserPresenceRequired <- getNextContainerMaybe (Container Context 507)
        _trustedConfirmationRequired <- getNextContainerMaybe (Container Context 508)
        _unlockedDeviceRequired <- getNextContainerMaybe (Container Context 509)
        allApplications <- void <$> getNextContainerMaybe (Container Context 600)
        _applicationId <- getNextContainerMaybe (Container Context 601)
        _creationDateTime <- getNextContainerMaybe (Container Context 701)
        origin <- onNextContainerMaybe (Container Context 702) (getNext >>= \(IntVal i) -> pure i)
        _rollbackResistant <- getNextContainerMaybe (Container Context 703)
        _rootOfTrust <- getNextContainerMaybe (Container Context 704)
        _osVersion <- getNextContainerMaybe (Container Context 705)
        _osPatchLevel <- getNextContainerMaybe (Container Context 706)
        _attestationApplicationId <- getNextContainerMaybe (Container Context 709)
        _attestationIdBrand <- getNextContainerMaybe (Container Context 710)
        _attestationIdDevice <- getNextContainerMaybe (Container Context 711)
        _attestationIdProduct <- getNextContainerMaybe (Container Context 712)
        _attestationIdSerial <- getNextContainerMaybe (Container Context 713)
        _attestationIdImei <- getNextContainerMaybe (Container Context 714)
        _attestationIdMeid <- getNextContainerMaybe (Container Context 715)
        _attestationIdManufacturer <- getNextContainerMaybe (Container Context 716)
        _attestationIdModel <- getNextContainerMaybe (Container Context 717)
        _vendorPatchLevel <- getNextContainerMaybe (Container Context 718)
        _bootPatchLevel <- getNextContainerMaybe (Container Context 719)
        pure $ AuthorisationList purpose allApplications origin

      decodeIntSet :: Set Integer -> ParseASN1 (Set Integer)
      decodeIntSet set = do
        next <- hasNext
        if next
          then do
            IntVal elem <- getNext
            decodeIntSet (Set.insert elem set)
          else pure set

decode :: [(Term, Term)] -> Decoder s Stmt
decode xs = do
  let m = Map.fromList xs
  TInt algId <- maybe (fail "no alg") pure $ Map.lookup (TString "alg") m
  alg <- toAlg algId
  TBytes sig <- maybe (fail "no sig") pure $ Map.lookup (TString "sig") m
  x5c <- case Map.lookup (TString "x5c") m of
    -- TODO: Can we discard the rest?
    Just (TList (TBytes certBytes : _)) ->
      either fail pure $ X509.decodeSignedCertificate certBytes
    _ -> fail "no x5c"
  let cert = X509.getCertificate x5c
      mX509Exts = X509.certExtensions cert
  attExt <- maybe (fail "Could not find attestation extension") (either (fail . show) pure) $ extensionGetE mX509Exts
  pure $ Stmt alg sig x5c attExt
