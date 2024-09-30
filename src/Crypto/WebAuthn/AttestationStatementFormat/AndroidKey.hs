{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

-- | Stability: experimental
-- This module implements the
-- [Android Key Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation).
module Crypto.WebAuthn.AttestationStatementFormat.AndroidKey
  ( format,
    Format (..),
    TrustLevel (..),
    VerificationError (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM, unless, void, when)
import Crypto.Hash (Digest, SHA256, digestFromByteString)
import qualified Crypto.WebAuthn.Cose.Internal.Verify as Cose
import qualified Crypto.WebAuthn.Cose.PublicKey as Cose
import qualified Crypto.WebAuthn.Cose.PublicKeyWithSignAlg as Cose
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import Crypto.WebAuthn.Internal.Utils (failure)
import qualified Crypto.WebAuthn.Model.Types as M
import Data.ASN1.Parse (ParseASN1, getNext, getNextContainerMaybe, hasNext, onNextContainer, onNextContainerMaybe, runParseASN1)
import Data.ASN1.Types (ASN1 (IntVal, OctetString), ASN1Class (Context), ASN1ConstructionType (Container, Sequence, Set))
import Data.Aeson (ToJSON, object, toJSON, (.=))
import Data.Bifunctor (first)
import Data.ByteArray (convert)
import Data.HashMap.Strict ((!?))
import Data.List.NonEmpty (NonEmpty ((:|)), toList)
import qualified Data.List.NonEmpty as NE
import Data.Maybe (isJust)
import Data.Set (Set)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as Text
import Data.X509 (Extension (extDecode, extEncode, extHasNestedASN1, extOID))
import qualified Data.X509 as X509

-- | [(spec)](https://source.android.com/security/keystore/attestation#attestation-extension)
-- The X509 extension android uses for attestation information
data ExtAttestation = ExtAttestation
  { attestationChallenge :: Digest SHA256,
    softwareEnforced :: AuthorizationList,
    teeEnforced :: AuthorizationList
  }
  deriving (Eq, Show)

-- | [(spec)](https://source.android.com/security/keystore/attestation#schema)
-- A partial @AuthorizationList@ structure
data AuthorizationList = AuthorizationList
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

      decodeAttestationList :: ParseASN1 AuthorizationList
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
        pure $ AuthorizationList purpose allApplications origin

      decodeIntSet :: Set Integer -> ParseASN1 (Set Integer)
      decodeIntSet set = do
        next <- hasNext
        if next
          then do
            IntVal elem <- getNext
            decodeIntSet (Set.insert elem set)
          else pure set

-- | The required Trust level for Android Key attestation.
data TrustLevel
  = -- | Trust has to be ensured on the software level. This is weaker than TEE
    -- enforced trust.
    SoftwareEnforced
  | -- | Hardware backed attestation, this requires that the Trusted Executing
    -- Environment enforced the attestation.
    TeeEnforced

-- | The Android Key Format. Allow configuration of the required level of
-- trust.
newtype Format = Format
  { requiredTrustLevel :: TrustLevel
  }

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-android-key-attestation)
data Statement = Statement
  { sig :: Cose.Signature,
    x5c :: NonEmpty X509.SignedCertificate,
    -- | Holds both the "alg" from the statement and the public key from the
    -- X.509 certificate
    pubKeyAndAlg :: Cose.PublicKeyWithSignAlg,
    -- | Holds the parsed attestation extension of the above X509 certificate,
    -- prevents having to parse it in the AndroidKey.verify function
    attExt :: ExtAttestation
  }
  deriving (Eq, Show)

instance ToJSON Statement where
  toJSON Statement {..} =
    object
      [ "alg" .= Cose.signAlg pubKeyAndAlg,
        "sig" .= sig,
        "x5c" .= x5c
      ]

-- | Verification errors specific to Android Key attestation
data VerificationError
  = -- | The public key in the certificate is different from the on in the
    -- attested credential data
    PublicKeyMismatch
      -- | The public key part of the credential data
      Cose.PublicKey
      -- | The public key extracted from the signed certificate
      Cose.PublicKey
  | -- | The challenge field of the certificate extension does not match the
    -- clientDataHash
    -- (first: challenge from certificate extension, second: clientDataHash)
    HashMismatch
      -- | The challenge part of the
      -- [@attestation-extension@](https://source.android.com/security/keystore/attestation#attestation-extension)
      (Digest SHA256)
      -- | The client data hash
      (Digest SHA256)
  | -- | The "attestation" extension is scoped to all applications instead of just the RpId
    AndroidKeyAllApplicationsFieldFound
  | -- | The origin field(s) were not equal to KM_ORIGIN_GENERATED (0)
    -- (first: tee-enforced origin, second: software-enforced origin (if allowed by the specified Format))
    AndroidKeyOriginFieldInvalid
      -- | The origin enforced by the trusted execution environment
      (Maybe Integer)
      -- | The origin enforced by software. NOTE: This field is explicitly
      -- set to `Nothing` if the `Format` specified `TeeEnforced` as the
      -- `requiredTrustLevel`.
      (Maybe Integer)
  | -- | The purpose field(s) were not equal to the singleton set containing
    -- KM_PURPOSE_SIGN (2)
    -- (first: tee-enforced purpose, second: software-enforced purpose (if allowed by the specified Format))
    AndroidKeyPurposeFieldInvalid
      -- | The purpose enforced by the trusted execution environment
      (Maybe (Set Integer))
      -- | The purpose enforced by software. NOTE: This field is explicitly
      -- set to `Nothing` if the `Format` specified `TeeEnforced` as the
      -- `requiredTrustLevel`.
      (Maybe (Set Integer))
  | -- | The Public key cannot verify the signature over the authenticatorData
    -- and the clientDataHash.
    VerificationFailure Text
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

  asfDecode _ xs =
    case (xs !? "alg", xs !? "sig", xs !? "x5c") of
      (Just (CBOR.TInt algId), Just (CBOR.TBytes (Cose.Signature -> sig)), Just (CBOR.TList (NE.nonEmpty -> Just x5cRaw))) -> do
        alg <- Cose.toCoseSignAlg algId
        x5c@(credCert :| _) <- forM x5cRaw $ \case
          CBOR.TBytes certBytes ->
            first (("Failed to decode signed certificate: " <>) . Text.pack) (X509.decodeSignedCertificate certBytes)
          cert ->
            Left $ "Certificate CBOR value is not bytes: " <> Text.pack (show cert)

        let cert = X509.getCertificate credCert
        attExt <- case X509.extensionGetE (X509.certExtensions cert) of
          Just (Right ext) -> pure ext
          Just (Left err) -> Left $ "Failed to decode certificate attestation extension: " <> Text.pack err
          Nothing -> Left "Certificate attestation extension is missing"

        pubKey <- Cose.fromX509 $ X509.certPubKey cert

        pubKeyAndAlg <- Cose.makePublicKeyWithSignAlg pubKey alg

        pure Statement {..}
      _ -> Left $ "CBOR map didn't have expected value types (alg: int, sig: bytes, x5c: nonempty list): " <> Text.pack (show xs)

  asfEncode _ Statement {..} =
    CBOR.TMap
      [ (CBOR.TString "sig", CBOR.TBytes $ Cose.unSignature sig),
        (CBOR.TString "alg", CBOR.TInt $ Cose.fromCoseSignAlg $ Cose.signAlg pubKeyAndAlg),
        ( CBOR.TString "x5c",
          CBOR.TList $
            map (CBOR.TBytes . X509.encodeSignedObject) $
              toList x5c
        )
      ]

  type AttStmtVerificationError Format = VerificationError

  asfVerify Format {..} _ Statement {..} M.AuthenticatorData {adRawData = M.WithRaw rawData, ..} clientDataHash = do
    -- 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to
    -- extract the contained fields.
    -- NOTE: The validity of the data is already checked during decoding.

    -- 2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the
    -- public key in the first certificate in x5c with the algorithm specified in alg.
    let signedData = Cose.Message $ rawData <> convert (M.unClientDataHash clientDataHash)
    case Cose.verify pubKeyAndAlg signedData sig of
      Right () -> pure ()
      Left err -> failure $ VerificationFailure err

    -- 3. Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the
    -- attestedCredentialData in authenticatorData.
    let credentialPublicKey = Cose.publicKey (M.acdCredentialPublicKey adAttestedCredentialData)
        pubKey = Cose.publicKey pubKeyAndAlg
    unless (credentialPublicKey == pubKey) . failure $ PublicKeyMismatch credentialPublicKey pubKey

    -- 4. Verify that the attestationChallenge field in the attestation certificate extension data is identical to
    -- clientDataHash.
    -- See https://source.android.com/security/keystore/attestation for the ASN1 description
    let attChallenge = attestationChallenge attExt
    let clientDataHashDigest = M.unClientDataHash clientDataHash
    unless (attChallenge == clientDataHashDigest) . failure $ HashMismatch attChallenge clientDataHashDigest

    -- 5. Verify the following using the appropriate authorization list from the attestation certificate extension data:

    -- 5.a The AuthorizationList.allApplications field is not present on either
    -- authorization list (softwareEnforced nor teeEnforced), since
    -- PublicKeyCredential MUST be scoped to the RP ID.
    let software = softwareEnforced attExt
    let tee = teeEnforced attExt
    when (isJust (allApplications software) || isJust (allApplications tee)) $ failure AndroidKeyAllApplicationsFieldFound

    -- 5.b For the following, use only the teeEnforced authorization list if the
    -- RP wants to accept only keys from a trusted execution environment,
    -- otherwise use the union of teeEnforced and softwareEnforced.
    -- 5.b.1 The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED.
    -- 5.b.2 The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN.
    -- NOTE: This statement is ambiguous as the purpose field is a set. Existing libraries take the same approach, checking if KM_PURPOSE_SIGN is the only member.
    let targetSet = Set.singleton kmPurposeSign
    case requiredTrustLevel of
      SoftwareEnforced -> do
        unless (origin software == Just kmOriginGenerated || origin tee == Just kmOriginGenerated) . failure $ AndroidKeyOriginFieldInvalid (origin tee) (origin software)
        unless (Just targetSet == purpose software || Just targetSet == purpose tee) . failure $ AndroidKeyPurposeFieldInvalid (purpose tee) (purpose software)
        pure ()
      TeeEnforced -> do
        unless (origin tee == Just kmOriginGenerated) . failure $ AndroidKeyOriginFieldInvalid (origin tee) Nothing
        unless (Just targetSet == purpose tee) . failure $ AndroidKeyPurposeFieldInvalid (purpose tee) Nothing
        pure ()

    -- 6. If successful, return implementation-specific values representing attestation type Basic and attestation trust
    -- path x5c.
    pure $
      M.SomeAttestationType $
        M.AttestationTypeVerifiable M.VerifiableAttestationTypeBasic (M.Fido2Chain x5c)

  asfTrustAnchors _ _ = mempty

-- | The default Android Key format configuration. Requires the attestation to
-- be backed by a Trusted Executing Environment (TEE).
format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat $ Format TeeEnforced
