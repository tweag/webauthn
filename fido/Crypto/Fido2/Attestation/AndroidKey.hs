{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.Fido2.Attestation.AndroidKey where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM, unless, void)
import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.PublicKey (COSEAlgorithmIdentifier, PublicKey, toAlg)
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import Data.ASN1.Parse (ParseASN1, getNext, getNextContainerMaybe, hasNext, onNextContainer, onNextContainerMaybe, runParseASN1)
import Data.ASN1.Types (ASN1 (IntVal, OctetString), ASN1Class (Context), ASN1ConstructionType (Container, Sequence, Set))
import Data.Bifunctor (first)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.HashMap.Strict (HashMap, (!?))
import qualified Data.HashMap.Strict as HashMap
import Data.List.NonEmpty (NonEmpty ((:|)))
import qualified Data.List.NonEmpty as NE
import Data.Maybe (fromMaybe)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import Data.X509 (Extension (extDecode, extEncode, extHasNestedASN1, extOID))
import qualified Data.X509 as X509

data ExtAttestation = ExtAttestation
  { attestationChallenge :: Digest SHA256,
    softwareEnforced :: AuthorisationList,
    teeEnforced :: AuthorisationList
  }
  deriving (Eq, Show)

data AuthorisationList = AuthorisationList
  { purpose :: Maybe (Set Integer),
    allApplications :: Maybe (),
    origin :: Maybe Integer
  }
  deriving (Eq, Show)

instance Extension ExtAttestation where
  extOID = const [1, 3, 6, 1, 4, 1, 11129, 2, 1, 17]
  extHasNestedASN1 = const True
  extEncode = error "Can not encode the parsed ExtAttestation to a valid [ASN1] because most fields are dropped during parsing."
  extDecode asn1 =
    first ("Could not decode ASN1 attestation extension: " ++) $
      runParseASN1 decodeExtAttestation asn1
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

data AttestationStatementFormatAndroidKey = AttestationStatementFormatAndroidKey
  deriving (Show)

-- androidStmtFormat (https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation)
data Stmt = Stmt
  { alg :: COSEAlgorithmIdentifier,
    sig :: ByteString,
    x5c :: NonEmpty X509.SignedCertificate,
    -- | Holds the parsed attestation extension of the above X509 certificate
    -- Not part of the spec, but prevents parsing in the AndroidKey.verify function
    pubKey :: PublicKey,
    attExt :: ExtAttestation
  }
  deriving (Eq, Show)

data DecodingError
  = DecodingErrorUnexpectedCBORStructure (HashMap Text CBOR.Term)
  | DecodingErrorUnknownAlgorithmIdentifier Int
  | DecodingErrorCertificate String
  | DecodingErrorCertificateExtensionMissing
  | DecodingErrorCertificateExtension String
  | DecodingErrorPublicKey X509.PubKey
  deriving (Show, Exception)

data VerificationError
  = VerificationErrorCertiticatePublicKeyInvalid
  deriving (Show, Exception)

-- https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h
kmOriginGenerated :: Integer
kmOriginGenerated = 0

-- https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h
kmPurposeSign :: Integer
kmPurposeSign = 2

instance M.AttestationStatementFormat AttestationStatementFormatAndroidKey where
  type AttStmt AttestationStatementFormatAndroidKey = Stmt

  asfIdentifier _ = "android-key"

  type AttStmtDecodingError AttestationStatementFormatAndroidKey = DecodingError

  asfDecode _ xs = do
    case (xs !? "alg", xs !? "sig", xs !? "x5c") of
      (Just (CBOR.TInt algId), Just (CBOR.TBytes sig), Just (CBOR.TList (NE.nonEmpty -> Just x5cRaw))) -> do
        alg <- maybe (Left $ DecodingErrorUnknownAlgorithmIdentifier algId) Right (toAlg algId)
        x5c@(credCert :| _) <- forM x5cRaw $ \case
          CBOR.TBytes certBytes ->
            first DecodingErrorCertificate (X509.decodeSignedCertificate certBytes)
          _ ->
            Left (DecodingErrorUnexpectedCBORStructure xs)

        let cert = X509.getCertificate credCert
        attExt <- case X509.extensionGetE (X509.certExtensions cert) of
          Just (Right ext) -> pure ext
          Just (Left err) -> Left $ DecodingErrorCertificateExtension err
          Nothing -> Left DecodingErrorCertificateExtensionMissing

        pubKey <- case PublicKey.toPublicKey (X509.certPubKey cert) of
          Nothing -> Left $ DecodingErrorPublicKey (X509.certPubKey cert)
          Just key -> pure key

        pure Stmt {..}
      _ -> Left (DecodingErrorUnexpectedCBORStructure xs)

  type AttStmtVerificationError AttestationStatementFormatAndroidKey = VerificationError

  asfVerify _ Stmt {alg = _alg, sig, x5c = x5c@(credCert :| _), attExt, pubKey} M.AuthenticatorData {adRawData, adAttestedCredentialData} clientDataHash = do
    -- 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to
    -- extract the contained fields.
    -- NOTE: The validity of the data is already checked during decoding.

    -- 2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the
    -- public key in the first certificate in x5c with the algorithm specified in alg.
    -- TODO: Maybe use verifyX509Sig like in Packed.hs
    let signedData = adRawData <> convert clientDataHash
    unless (PublicKey.verify pubKey signedData sig) . Left $ undefined

    -- 3. Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the
    -- attestedCredentialData in authenticatorData.
    let key = credentialPublicKey credData
    unless (key == x5cKey) $ Left CredentialKeyMismatch

    -- 4. Verify that the attestationChallenge field in the attestation certificate extension data is identical to
    -- clientDataHash.
    -- See https://source.android.com/security/keystore/attestation for the ASN1 description
    unless (attestationChallenge attExt == clientDataHash) . Left $ AttestationCommonError ChallengeMismatch

    -- 5. Verify the following using the appropriate authorization list from the attestation certificate extension data:

    -- 5.a The AuthorizationList.allApplications field is not present on either
    -- authorization list (softwareEnforced nor teeEnforced), since
    -- PublicKeyCredential MUST be scoped to the RP ID.
    let software = softwareEnforced attExt
        tee = teeEnforced attExt
    when (isJust (allApplications software) || isJust (allApplications tee)) $ Left AndroidKeyAllApplicationsFieldFound

    -- 5.b For the following, use only the teeEnforced authorization list if the
    -- RP wants to accept only keys from a trusted execution environment,
    -- otherwise use the union of teeEnforced and softwareEnforced.
    -- TODO: Allow the users of the library set the required trust level
    -- 5.b.1 The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
    unless (origin software == Just kmOriginGenerated || origin tee == Just kmOriginGenerated) $ Left AndroidKeyOriginFieldInvalid

    -- 5.b.2 The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
    -- NOTE: This statement is ambiguous as the purpose field is a set. Existing libraries take the same approach, checking if KM_PURPOSE_SIGN is the only member.
    let targetSet = Just $ Set.singleton kmPurposeSign
    unless (targetSet == purpose software || targetSet == purpose tee) $ Left AndroidKeyPurposeFieldInvalid

    -- 6. If successful, return implementation-specific values representing attestation type Basic and attestation trust
    -- path x5c.
    maybe (Left CredentialDataMissing) pure attestedCredentialData
