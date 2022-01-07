{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

module Crypto.WebAuthn.Operations.Attestation.AndroidKey
  ( format,
    Format (..),
    DecodingError (..),
    Statement (..),
    VerificationError (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM, unless, void, when)
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.PublicKey (PublicKey, fromAlg, toAlg, toCOSEAlgorithmIdentifier, toPublicKey)
import qualified Crypto.WebAuthn.PublicKey as PublicKey
import Data.ASN1.Parse (ParseASN1, getNext, getNextContainerMaybe, hasNext, onNextContainer, onNextContainerMaybe, runParseASN1)
import Data.ASN1.Types (ASN1 (IntVal, OctetString), ASN1Class (Context), ASN1ConstructionType (Container, Sequence, Set))
import Data.Aeson (ToJSON, object, toJSON, (.=))
import Data.Bifunctor (first)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.HashMap.Strict (HashMap, (!?))
import Data.List.NonEmpty (NonEmpty ((:|)), toList)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (isJust)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as Text
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

-- | [(spec)](https://source.android.com/security/keystore/attestation#tbscertificate-sequence)
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
        origin <-
          onNextContainerMaybe (Container Context 702) $
            getNext >>= \case
              IntVal i -> pure i
              _ -> fail "Unexpected non-IntVal"
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

data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation)
data Statement = Statement
  { sig :: ByteString,
    x5c :: NonEmpty X509.SignedCertificate,
    -- | Holds the parsed attestation extension of the above X509 certificate
    -- Not part of the spec, but prevents parsing in the AndroidKey.verify function
    pubKey :: PublicKey,
    attExt :: ExtAttestation
  }
  deriving (Eq, Show)

instance ToJSON Statement where
  toJSON Statement {..} =
    object
      [ "alg" .= toCOSEAlgorithmIdentifier pubKey,
        "sig" .= sig,
        "x5c" .= x5c
      ]

data DecodingError
  = -- | The provided CBOR encoded data was malformed. Either because a field
    -- was missing, or because the field contained the wrong type of data
    DecodingErrorUnexpectedCBORStructure (HashMap Text CBOR.Term)
  | -- | The algorithm identifier was invalid, or unsupported by the library
    DecodingErrorUnknownAlgorithmIdentifier Int
  | -- | The x5c field of the attestation statement could not be decoded for
    -- the provided reason
    DecodingErrorCertificate String
  | -- | The required "attestation" extension was not found in the certificate
    DecodingErrorCertificateExtensionMissing
  | -- | The required "attestation" extension of the certificate could not be
    -- decoded
    DecodingErrorCertificateExtension String
  | -- | The public key of the certificate could not be decoded
    DecodingErrorPublicKey X509.PubKey
  deriving (Show, Exception)

data VerificationError
  = -- | The public key in the certificate is different from the on in the
    -- attested credential data
    VerificationErrorCredentialKeyMismatch
  | -- | The challenge field of the certificate extension does not match the
    -- clientDataHash
    VerificationErrorClientDataHashMismatch
  | -- | The "attestation" extension is scoped to all applications instead of just the RpId
    VerificationErrorAndroidKeyAllApplicationsFieldFound
  | -- | The origin field(s) were not equal to KM_ORIGIN_GENERATED
    VerificationErrorAndroidKeyOriginFieldInvalid
  | -- | The purpose field(s) were not equal to the singleton set containing
    -- KM_PURPOSE_SIGN
    VerificationErrorAndroidKeyPurposeFieldInvalid
  | -- | The Public key cannot verify the signature over the authenticatorData
    -- and the clientDataHash.
    VerificationErrorVerificationFailure
  deriving (Show, Exception)

-- | [(spec)](https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h)
kmOriginGenerated :: Integer
kmOriginGenerated = 0

-- | [(spec)](https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h)
kmPurposeSign :: Integer
kmPurposeSign = 2

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement

  asfIdentifier _ = "android-key"

  type AttStmtDecodingError Format = DecodingError

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

        pubKey <- case toPublicKey alg (X509.certPubKey cert) of
          Nothing -> Left $ DecodingErrorPublicKey (X509.certPubKey cert)
          Just key -> pure key

        pure Statement {..}
      _ -> Left (DecodingErrorUnexpectedCBORStructure xs)

  asfEncode _ Statement {sig, x5c, pubKey} =
    CBOR.TMap
      [ (CBOR.TString "sig", CBOR.TBytes sig),
        (CBOR.TString "alg", CBOR.TInt $ fromAlg $ toCOSEAlgorithmIdentifier pubKey),
        ( CBOR.TString "x5c",
          CBOR.TList $
            map (CBOR.TBytes . X509.encodeSignedObject) $ toList x5c
        )
      ]

  type AttStmtVerificationError Format = VerificationError

  asfVerify _ _ Statement {sig, x5c, attExt, pubKey} M.AuthenticatorData {adRawData = M.WithRaw rawData, adAttestedCredentialData} clientDataHash = do
    -- 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to
    -- extract the contained fields.
    -- NOTE: The validity of the data is already checked during decoding.

    -- 2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the
    -- public key in the first certificate in x5c with the algorithm specified in alg.
    let signedData = rawData <> convert (M.unClientDataHash clientDataHash)
    unless (PublicKey.verify pubKey signedData sig) $ Left VerificationErrorVerificationFailure

    -- 3. Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the
    -- attestedCredentialData in authenticatorData.
    unless (M.acdCredentialPublicKey adAttestedCredentialData == pubKey) $ Left VerificationErrorCredentialKeyMismatch

    -- 4. Verify that the attestationChallenge field in the attestation certificate extension data is identical to
    -- clientDataHash.
    -- See https://source.android.com/security/keystore/attestation for the ASN1 description
    unless (attestationChallenge attExt == M.unClientDataHash clientDataHash) . Left $ VerificationErrorClientDataHashMismatch

    -- 5. Verify the following using the appropriate authorization list from the attestation certificate extension data:

    -- 5.a The AuthorizationList.allApplications field is not present on either
    -- authorization list (softwareEnforced nor teeEnforced), since
    -- PublicKeyCredential MUST be scoped to the RP ID.
    let software = softwareEnforced attExt
        tee = teeEnforced attExt
    when (isJust (allApplications software) || isJust (allApplications tee)) $ Left VerificationErrorAndroidKeyAllApplicationsFieldFound

    -- 5.b For the following, use only the teeEnforced authorization list if the
    -- RP wants to accept only keys from a trusted execution environment,
    -- otherwise use the union of teeEnforced and softwareEnforced.
    -- TODO: Allow the users of the library set the required trust level
    -- 5.b.1 The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
    unless (origin software == Just kmOriginGenerated || origin tee == Just kmOriginGenerated) $ Left VerificationErrorAndroidKeyOriginFieldInvalid

    -- 5.b.2 The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
    -- NOTE: This statement is ambiguous as the purpose field is a set. Existing libraries take the same approach, checking if KM_PURPOSE_SIGN is the only member.
    let targetSet = Just $ Set.singleton kmPurposeSign
    unless (targetSet == purpose software || targetSet == purpose tee) $ Left VerificationErrorAndroidKeyPurposeFieldInvalid

    -- 6. If successful, return implementation-specific values representing attestation type Basic and attestation trust
    -- path x5c.
    pure $
      M.SomeAttestationType $
        M.AttestationTypeVerifiable M.VerifiableAttestationTypeBasic (M.Fido2Chain x5c)

  asfTrustAnchors _ _ = mempty

format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
