{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ViewPatterns #-}

-- | Stability: experimental
-- This module implements the
-- [TPM Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation).
module Crypto.WebAuthn.AttestationStatementFormat.TPM
  ( format,
    Format (..),
    VerificationError (..),
    -- Exported because it's part of an error constructor
    TPMAlgId (..),
  )
where

import qualified Codec.CBOR.Term as CBOR
import Control.Exception (Exception)
import Control.Monad (forM, unless, when)
import Crypto.Hash (SHA1 (SHA1), SHA256 (SHA256), hashWith)
import qualified Crypto.Hash as Hash
import Crypto.Number.Serialize (os2ip)
import qualified Crypto.WebAuthn.Cose.Internal.Verify as Cose
import qualified Crypto.WebAuthn.Cose.PublicKey as Cose
import qualified Crypto.WebAuthn.Cose.PublicKeyWithSignAlg as Cose
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import Crypto.WebAuthn.Internal.ToJSONOrphans (PrettyHexByteString (PrettyHexByteString))
import Crypto.WebAuthn.Internal.Utils (IdFidoGenCeAAGUID (IdFidoGenCeAAGUID), failure)
import Crypto.WebAuthn.Model.Identifier (AAGUID)
import qualified Crypto.WebAuthn.Model.Types as M
import Data.ASN1.Error (ASN1Error)
import Data.ASN1.OID (OID)
import Data.ASN1.Parse (ParseASN1, getNext, hasNext, runParseASN1)
import Data.ASN1.Prim (ASN1 (ASN1String, OID))
import Data.Aeson (ToJSON, Value (String), object, toJSON, (.=))
import Data.Bifunctor (Bifunctor (first))
import Data.Binary (Word16, Word32, Word64)
import qualified Data.Binary.Get as Get
import qualified Data.Binary.Put as Put
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.FileEmbed (embedDir)
import Data.HashMap.Strict ((!?))
import Data.List.NonEmpty (NonEmpty ((:|)))
import qualified Data.List.NonEmpty as NE
import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8)
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import GHC.Generics (Generic)

tpmManufacturers :: Set.Set Text
tpmManufacturers =
  Set.fromList
    [ "id:FFFFF1D0", -- FIDO testing TPM
    -- From https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.02-Revision-1.00.pdf
      "id:414D4400", -- 'AMD'  AMD
      "id:41544D4C", -- 'ATML' Atmel
      "id:4252434D", -- 'BRCM' Broadcom
      "id:4353434F", -- 'CSCO' Cisco
      "id:464C5953", -- 'FLYS' Flyslice Technologies
      "id:48504500", -- 'HPE'  HPE
      "id:49424d00", -- 'IBM'  IBM
      "id:49465800", -- 'IFX'  Infineon
      "id:494E5443", -- 'INTC' Intel
      "id:4C454E00", -- 'LEN'  Lenovo
      "id:4D534654", -- 'MSFT' Microsoft
      "id:4E534D20", -- 'NSM'  National Semiconductor
      "id:4E545A00", -- 'NTZ'  Nationz
      "id:4E544300", -- 'NTC'  Nuvoton Technology
      "id:51434F4D", -- 'QCOM' Qualcomm
      "id:534D5343", -- 'SMSC' SMSC
      "id:53544D20", -- 'STM ' ST Microelectronics
      "id:534D534E", -- 'SMSN' Samsung
      "id:534E5300", -- 'SNS'  Sinosun
      "id:54584E00", -- 'TXN'  Texas Instruments
      "id:57454300", -- 'WEC'  Winbond
      "id:524F4343", -- 'ROCC' Fuzhou Rockchip
      "id:474F4F47" -- 'GOOG'  Google
    ]

-- | [(spec)](https://trustedcomputinggroup.org/wp-content/uploads/TCG-_Algorithm_Registry_r1p32_pub.pdf)
data TPMAlgId = TPMAlgRSA | TPMAlgSHA1 | TPMAlgSHA256 | TPMAlgECC
  deriving (Show, Eq, Generic, ToJSON)

-- | [(spec)](https://trustedcomputinggroup.org/wp-content/uploads/TCG-_Algorithm_Registry_r1p32_pub.pdf)
toTPMAlgId :: (MonadFail m) => Word16 -> m TPMAlgId
toTPMAlgId 0x0001 = pure TPMAlgRSA
toTPMAlgId 0x0004 = pure TPMAlgSHA1
toTPMAlgId 0x000B = pure TPMAlgSHA256
toTPMAlgId 0x0023 = pure TPMAlgECC
toTPMAlgId _ = fail "Unsupported or invalid TPM_ALD_IG"

-- | [(spec)](https://trustedcomputinggroup.org/wp-content/uploads/TCG-_Algorithm_Registry_r1p32_pub.pdf)
toCurveId :: (MonadFail m) => Word16 -> m Cose.CoseCurveECDSA
toCurveId 0x0003 = pure Cose.CoseCurveP256
toCurveId 0x0004 = pure Cose.CoseCurveP384
toCurveId 0x0005 = pure Cose.CoseCurveP521
toCurveId _ = fail "Unsupported Curve ID"

-- | [(spec)](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf)
tpmGeneratedValue :: Word32
tpmGeneratedValue = 0xff544347

-- | [(spec)](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf)
tpmStAttestCertify :: Word16
tpmStAttestCertify = 0x8017

-- | The TPMS_CLOCK_INFO structure as specified in [TPMv2-Part2](https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf)
-- section 10.11.1.
data TPMSClockInfo = TPMSClockInfo
  { tpmsciClock :: Word64,
    tpmsciResetCount :: Word32,
    tpmsciRestartCount :: Word32,
    tpmsciSafe :: Bool
  }
  deriving (Eq, Show, Generic, ToJSON)

-- | The TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2](https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf)
-- section 10.12.3.
data TPMSCertifyInfo = TPMSCertifyInfo
  { tpmsciName :: PrettyHexByteString,
    tpmsciQualifiedName :: PrettyHexByteString
  }
  deriving (Eq, Show, Generic, ToJSON)

-- | The TPMS_ATTEST structure as specified in
-- [TPMv2-Part2](https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf)
-- section 10.12.8.
data TPMSAttest = TPMSAttest
  { tpmsaMagic :: Word32,
    tpmsaType :: Word16,
    tpmsaQualifiedSigner :: PrettyHexByteString,
    tpmsaExtraData :: PrettyHexByteString,
    tpmsaClockInfo :: TPMSClockInfo,
    tpmsaFirmwareVersion :: Word64,
    tpmsaAttested :: TPMSCertifyInfo
  }
  deriving (Eq, Show, Generic, ToJSON)

-- | The TPMA_OBJECT structure as specified in
-- [TPMv2-Part2](https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf)
-- section 8.3
type TPMAObject = Word32

-- | The TPMU_PUBLIC_PARMS structure as specified in
-- [TPMv2-Part2](https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf)
-- section 12.2.3.7.
data TPMUPublicParms
  = TPMSRSAParms
      { tpmsrpSymmetric :: Word16,
        tpmsrpScheme :: Word16,
        tpmsrpKeyBits :: Word16,
        tpmsrpExponent :: Word32
      }
  | TPMSECCParms
      { tpmsepSymmetric :: Word16,
        tpmsepScheme :: Word16,
        tpmsepCurveId :: Cose.CoseCurveECDSA,
        tpmsepkdf :: Word16
      }
  deriving (Eq, Show, Generic, ToJSON)

-- | The TPMU_PUBLIC_ID structure as specified in
-- [TPMv2-Part2](https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf)
-- section 12.2.3.2.
data TPMUPublicId
  = TPM2BPublicKeyRSA PrettyHexByteString
  | TPMSECCPoint
      { tpmseX :: PrettyHexByteString,
        tpmseY :: PrettyHexByteString
      }
  deriving (Eq, Show, Generic, ToJSON)

-- | The TPMT_PUBLIC structure (see [TPMv2-Part2](https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf) section 12.2.4) used by the TPM to represent the credential public key.
data TPMTPublic = TPMTPublic
  { tpmtpType :: TPMAlgId,
    tpmtpNameAlg :: TPMAlgId,
    tpmtpNameAlgRaw :: Word16,
    tpmtpObjectAttributes :: TPMAObject,
    tpmtpAuthPolicy :: PrettyHexByteString,
    tpmtpParameters :: TPMUPublicParms,
    tpmtpUnique :: TPMUPublicId
  }
  deriving (Eq, Show, Generic, ToJSON)

-- | The TPM format. The sole purpose of this type is to instantiate the
-- AttestationStatementFormat typeclass below.
data Format = Format

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | TPM Subject Alternative Name as described in section 3.2.9 [here](https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf)
data SubjectAlternativeName = SubjectAlternativeName
  { tpmManufacturer :: Text,
    tpmModel :: Text,
    tpmVersion :: Text
  }
  deriving (Eq, Show)

newtype CertInfoBytes = CertInfoBytes {unCertInfoBytes :: BS.ByteString}
  deriving newtype (Eq, Show)

newtype PubAreaBytes = PubAreaBytes {unPubAreaBytes :: BS.ByteString}
  deriving newtype (Eq, Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation)
data Statement = Statement
  { x5c :: NE.NonEmpty X509.SignedCertificate,
    aikCert :: X509.Certificate,
    -- Combined aikCert public key and the "alg" statement key
    aikPubKeyAndAlg :: Cose.PublicKeyWithSignAlg,
    subjectAlternativeName :: SubjectAlternativeName,
    aaguidExt :: Maybe IdFidoGenCeAAGUID,
    extendedKeyUsage :: [X509.ExtKeyUsagePurpose],
    basicConstraintsCA :: Bool,
    sig :: Cose.Signature,
    certInfo :: TPMSAttest,
    certInfoRaw :: CertInfoBytes,
    pubArea :: TPMTPublic,
    pubAreaRaw :: PubAreaBytes,
    pubAreaKey :: Cose.PublicKey
  }
  deriving (Eq, Show)

instance ToJSON Statement where
  toJSON Statement {..} =
    object
      [ "ver" .= String "2.0",
        "alg" .= Cose.signAlg aikPubKeyAndAlg,
        "x5c" .= x5c,
        "sig" .= sig,
        "certInfo" .= certInfo,
        "pubArea" .= pubArea
      ]

-- | Verification errors specific to TPM attestation
data VerificationError
  = -- | The public key in the certificate is different from the on in the
    -- attested credential data
    PublicKeyMismatch
      { -- | The public key extracted from the certificate
        certificatePublicKey :: Cose.PublicKey,
        -- | The public key part of the credential data
        credentialDataPublicKey :: Cose.PublicKey
      }
  | -- | The magic number in certInfo was not set to TPM_GENERATED_VALUE (0xff544347)
    MagicNumberInvalid Word32
  | -- | The type in certInfo was not set to TPM_ST_ATTEST_CERTIFY (0x8017)
    TypeInvalid Word16
  | -- | The algorithm specified in the nameAlg field is unsupported or is not
    -- a valid name algorithm
    NameAlgorithmInvalid TPMAlgId
  | -- | The calulated name does not match the provided name.
    NameMismatch
      { -- | The name calculated from the TPMT_PUBLIC structure with the name
        -- algorithm.
        pubAreaName :: BS.ByteString,
        -- | The expected name from TPMS_CERTIFY_INFO of the TPMS_ATTEST
        -- structure
        certifyInfoName :: BS.ByteString
      }
  | -- | The public key in the certificate was invalid, either because the it
    -- had an unexpected algorithm, or because it was otherwise malformed
    PublicKeyInvalid Text
  | -- | The certificate didn't have the expected version-value (2)
    CertificateVersionInvalid Int
  | -- | The Public key cannot verify the signature over the authenticatorData
    -- and the clientDataHash.
    VerificationFailure Text
  | -- | The subject field was not empty
    SubjectFieldNotEmpty [(OID, X509.ASN1CharacterString)]
  | -- | The vendor was unknown
    VendorUnknown Text
  | -- | The Extended Key Usage did not contain the 2.23.133.8.3 OID
    ExtKeyOIDMissing
  | -- | The CA component of the basic constraints extension was set to True
    BasicConstraintsTrue
  | -- | The AAGUID in the attested credential data does not match the AAGUID
    -- in the fido certificate extension
    CertificateAAGUIDMismatch
      { -- | AAGUID from the id-fido-gen-ce-aaguid certificate extension
        certificateExtensionAAGUID :: AAGUID,
        -- | AAGUID from the attested credential data
        attestedCredentialDataAAGUID :: AAGUID
      }
  | -- | The (supposedly) ASN1 encoded certificate extension could not be
    -- decoded
    ASN1Error ASN1Error
  | -- | The certificate extension does not contain a AAGUID
    CredentialAAGUIDMissing
  | -- | The desired algorithm does not have a known associated hash function
    HashFunctionUnknown
  | -- | The calculated hash over the attToBeSigned does not match the received
    -- hash
    HashMismatch
      { -- | The hash of the concatenation of the @authenticatorData@ and
        -- @clientDataHash@ (@attToBeSigned@) calculated by the @alg@ specified in
        -- the @Statement@.
        calculatedHash :: BS.ByteString,
        -- | The extra data from the TPMS_ATTEST structure.
        extraData :: BS.ByteString
      }
  deriving (Show, Exception)

-- [(spec)](https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf)
-- The specifications specifies that the inner most objects of the ASN.1
-- encoding are individual sets of sequences. See notably page 35 of the spec.
-- However, in practice, we found that some TPM implementions interpreted this
-- as being a single set of individual sequences. We could attempt to parse
-- both, relying on the Alternative typeclass, or we could write our parser in
-- such a way that it is agnostic to whatever structure is chosen by searching
-- through the ASN.1 encoding for the desired OIDs.
--
-- We chose the second, since it can possibly also handle other interpretations
-- of the spec.
instance X509.Extension SubjectAlternativeName where
  extOID = const [2, 5, 29, 17]
  extHasNestedASN1 = const True
  extEncode = error "Unimplemented: This library does not implement encoding the SubjectAlternativeName extension"
  extDecode asn1 =
    first ("Could not decode ASN1 subject-alternative-name extension: " ++) $
      runParseASN1 decodeSubjectAlternativeName asn1
    where
      decodeSubjectAlternativeName :: ParseASN1 SubjectAlternativeName
      decodeSubjectAlternativeName =
        do
          map <- Map.fromList <$> decodeFields
          -- https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
          tpmManufacturer <- maybe (fail "manufacturer field not found in subject alternative name") pure $ Map.lookup [2, 23, 133, 2, 1] map
          tpmModel <- maybe (fail "model field not found in subject alternative name") pure $ Map.lookup [2, 23, 133, 2, 2] map
          tpmVersion <- maybe (fail "version field not found in subject alternative name") pure $ Map.lookup [2, 23, 133, 2, 3] map
          pure SubjectAlternativeName {..}

      decodeFields :: ParseASN1 [(OID, Text)]
      decodeFields = do
        next <- hasNext
        if next
          then do
            n <- getNext
            case n of
              OID oid -> do
                m <- getNext
                case m of
                  ASN1String asnString -> do
                    let text = decodeUtf8 $ X509.getCharacterStringRawData asnString
                    fields <- decodeFields
                    pure ((oid, text) : fields)
                  _ -> decodeFields
              _ -> decodeFields
          else pure []

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement

  asfIdentifier _ = "tpm"

  asfDecode _ xs =
    case (xs !? "ver", xs !? "alg", xs !? "x5c", xs !? "sig", xs !? "certInfo", xs !? "pubArea") of
      ( Just (CBOR.TString "2.0"),
        Just (CBOR.TInt algId),
        Just (CBOR.TList (NE.nonEmpty -> Just x5cRaw)),
        Just (CBOR.TBytes (Cose.Signature -> sig)),
        Just (CBOR.TBytes (CertInfoBytes -> certInfoRaw)),
        Just (CBOR.TBytes (PubAreaBytes -> pubAreaRaw))
        ) ->
          do
            x5c@(signedAikCert :| _) <- forM x5cRaw $ \case
              CBOR.TBytes certBytes ->
                first (("Failed to decode signed certificate: " <>) . Text.pack) (X509.decodeSignedCertificate certBytes)
              cert ->
                Left $ "Certificate CBOR value is not bytes: " <> Text.pack (show cert)
            alg <- Cose.toCoseSignAlg algId
            -- The get interface requires lazy bytestrings but we typically use
            -- strict bytestrings in the library, so we have to convert between
            -- them
            certInfo <- decodeCertInfoBytes certInfoRaw
            pubArea <- decodePubAreaBytes pubAreaRaw
            pubAreaKey <- extractPublicKey pubArea

            let aikCert = X509.getCertificate signedAikCert

            aikCertPubKey <- Cose.fromX509 $ X509.certPubKey aikCert
            aikPubKeyAndAlg <- Cose.makePublicKeyWithSignAlg aikCertPubKey alg

            subjectAlternativeName <- case X509.extensionGetE (X509.certExtensions aikCert) of
              Just (Right ext) -> pure ext
              Just (Left err) -> Left $ "Failed to decode certificate subject alternative name extension: " <> Text.pack err
              Nothing -> Left "Certificate subject alternative name extension is missing"
            aaguidExt <- case X509.extensionGetE (X509.certExtensions aikCert) of
              Just (Right ext) -> pure $ Just ext
              Just (Left err) -> Left $ "Failed to decode certificate aaguid extension: " <> Text.pack err
              Nothing -> pure Nothing
            X509.ExtExtendedKeyUsage extendedKeyUsage <- case X509.extensionGetE (X509.certExtensions aikCert) of
              Just (Right ext) -> pure ext
              Just (Left err) -> Left $ "Failed to decode certificate extended key usage extension: " <> Text.pack err
              Nothing -> Left "Certificate extended key usage extension is missing"
            X509.ExtBasicConstraints basicConstraintsCA _ <- case X509.extensionGetE (X509.certExtensions aikCert) of
              Just (Right ext) -> pure ext
              Just (Left err) -> Left $ "Failed to decode certificate basic constraints extension: " <> Text.pack err
              Nothing -> Left "Certificate basic constraints extension is missing"
            Right $ Statement {..}
      _ -> Left $ "CBOR map didn't have expected value types (ver: \"2.0\", alg: int, x5c: non-empty list, sig: bytes, certInfo: bytes, pubArea: bytes): " <> Text.pack (show xs)
    where
      decodeCertInfoBytes :: CertInfoBytes -> Either Text TPMSAttest
      decodeCertInfoBytes (CertInfoBytes bytes) =
        case Get.runGetOrFail getTPMAttest (LBS.fromStrict bytes) of
          Left (_, _, err) -> Left $ "Failed to decode certInfo: " <> Text.pack (show err)
          Right (_, _, res) -> pure res

      getTPMAttest :: Get.Get TPMSAttest
      getTPMAttest = do
        tpmsaMagic <- Get.getWord32be
        unless (tpmsaMagic == tpmGeneratedValue) $ fail "Invalid magic number"
        tpmsaType <- Get.getWord16be
        tpmsaQualifiedSigner <- getTPMByteString
        tpmsaExtraData <- getTPMByteString
        tpmsaClockInfo <- getClockInfo
        tpmsaFirmwareVersion <- Get.getWord64be
        tpmsaAttested <- getCertifyInfo
        True <- Get.isEmpty
        pure TPMSAttest {..}

      getClockInfo :: Get.Get TPMSClockInfo
      getClockInfo = do
        tpmsciClock <- Get.getWord64be
        tpmsciResetCount <- Get.getWord32be
        tpmsciRestartCount <- Get.getWord32be
        tpmsciSafe <- (== 1) <$> Get.getWord8
        pure TPMSClockInfo {..}

      getCertifyInfo :: Get.Get TPMSCertifyInfo
      getCertifyInfo = do
        tpmsciName <- getTPMByteString
        tpmsciQualifiedName <- getTPMByteString
        pure TPMSCertifyInfo {..}

      getTPMByteString :: Get.Get PrettyHexByteString
      getTPMByteString = do
        size <- Get.getWord16be
        PrettyHexByteString <$> Get.getByteString (fromIntegral size)

      decodePubAreaBytes :: PubAreaBytes -> Either Text TPMTPublic
      decodePubAreaBytes (PubAreaBytes bytes) =
        case Get.runGetOrFail getTPMTPublic (LBS.fromStrict bytes) of
          Left (_, _, err) -> Left $ "Failed to decode certInfo: " <> Text.pack (show err)
          Right (_, _, res) -> pure res

      getTPMTPublic :: Get.Get TPMTPublic
      getTPMTPublic = do
        tpmtpType <- toTPMAlgId =<< Get.getWord16be
        tpmtpNameAlgRaw <- Get.getWord16be
        tpmtpNameAlg <- toTPMAlgId tpmtpNameAlgRaw
        tpmtpObjectAttributes <- getTPMAObject
        tpmtpAuthPolicy <- getTPMByteString
        tpmtpParameters <- getTPMUPublicParms tpmtpType
        tpmtpUnique <- getTPMUPublicId tpmtpType
        True <- Get.isEmpty
        pure TPMTPublic {..}

      -- We don't need to inspect the bits in the object, so we skip parsing it
      getTPMAObject :: Get.Get TPMAObject
      getTPMAObject = Get.getWord32be

      getTPMUPublicParms :: TPMAlgId -> Get.Get TPMUPublicParms
      getTPMUPublicParms TPMAlgRSA = do
        tpmsrpSymmetric <- Get.getWord16be
        tpmsrpScheme <- Get.getWord16be
        tpmsrpKeyBits <- Get.getWord16be
        -- An exponent of zero indicates that the exponent is the default of 2^16 + 1
        tpmsrpExponent <- (\e -> if e == 0 then 65537 else e) <$> Get.getWord32be
        pure TPMSRSAParms {..}
      getTPMUPublicParms TPMAlgSHA1 = fail "SHA1 does not have public key parameters"
      getTPMUPublicParms TPMAlgSHA256 = fail "SHA256 does not have public key parameters"
      getTPMUPublicParms TPMAlgECC = do
        tpmsepSymmetric <- Get.getWord16be
        tpmsepScheme <- Get.getWord16be
        tpmsepCurveId <- toCurveId =<< Get.getWord16be
        tpmsepkdf <- Get.getWord16be
        pure TPMSECCParms {..}

      getTPMUPublicId :: TPMAlgId -> Get.Get TPMUPublicId
      getTPMUPublicId TPMAlgRSA = TPM2BPublicKeyRSA <$> getTPMByteString
      getTPMUPublicId TPMAlgSHA1 = fail "SHA1 does not have a public id"
      getTPMUPublicId TPMAlgSHA256 = fail "SHA256 does not have a public id"
      getTPMUPublicId TPMAlgECC = do
        tpmseX <- getTPMByteString
        tpmseY <- getTPMByteString
        pure TPMSECCPoint {..}

      extractPublicKey :: TPMTPublic -> Either Text Cose.PublicKey
      extractPublicKey
        TPMTPublic
          { tpmtpType = TPMAlgRSA,
            tpmtpParameters = TPMSRSAParms {..},
            tpmtpUnique = TPM2BPublicKeyRSA (PrettyHexByteString nb)
          } =
          Cose.checkPublicKey
            Cose.PublicKeyRSA
              { rsaN = os2ip nb,
                rsaE = toInteger tpmsrpExponent
              }
      extractPublicKey
        TPMTPublic
          { tpmtpType = TPMAlgECC,
            tpmtpParameters = TPMSECCParms {..},
            tpmtpUnique = TPMSECCPoint {tpmseX = PrettyHexByteString tpmseX, tpmseY = PrettyHexByteString tpmseY}
          } =
          Cose.checkPublicKey
            Cose.PublicKeyECDSA
              { ecdsaCurve = tpmsepCurveId,
                ecdsaX = os2ip tpmseX,
                ecdsaY = os2ip tpmseY
              }
      extractPublicKey key = Left $ "Unsupported TPM public key: " <> Text.pack (show key)

  asfEncode _ Statement {..} =
    CBOR.TMap
      [ (CBOR.TString "ver", CBOR.TString "2.0"),
        (CBOR.TString "alg", CBOR.TInt $ Cose.fromCoseSignAlg $ Cose.signAlg aikPubKeyAndAlg),
        ( CBOR.TString "x5c",
          CBOR.TList $ map (CBOR.TBytes . X509.encodeSignedObject) $ NE.toList x5c
        ),
        (CBOR.TString "sig", CBOR.TBytes $ Cose.unSignature sig),
        (CBOR.TString "certInfo", CBOR.TBytes $ unCertInfoBytes certInfoRaw),
        (CBOR.TString "pubArea", CBOR.TBytes $ unPubAreaBytes pubAreaRaw)
      ]

  type AttStmtVerificationError Format = VerificationError

  asfVerify
    _
    _
    Statement {..}
    M.AuthenticatorData {adRawData = M.WithRaw adRawData, ..}
    clientDataHash = do
      -- 1. Verify that attStmt is valid CBOR conforming to the syntax defined
      -- above and perform CBOR decoding on it to extract the contained fields.
      -- NOTE: This is done during decoding

      -- 2. Verify that the public key specified by the parameters and unique
      -- fields of pubArea is identical to the credentialPublicKey in the
      -- attestedCredentialData in authenticatorData.
      let pubKey = Cose.publicKey $ M.acdCredentialPublicKey adAttestedCredentialData
      unless (pubAreaKey == pubKey) . failure $ PublicKeyMismatch pubAreaKey pubKey

      -- 3. Concatenate authenticatorData and clientDataHash to form attToBeSigned.
      let attToBeSigned = adRawData <> BA.convert (M.unClientDataHash clientDataHash)

      -- 4. Validate that certInfo is valid:
      -- 4.1 Verify that magic is set to TPM_GENERATED_VALUE.
      let magic = tpmsaMagic certInfo
      unless (magic == tpmGeneratedValue) . failure $ MagicNumberInvalid magic

      -- 4.2 Verify that type is set to TPM_ST_ATTEST_CERTIFY.
      let typ = tpmsaType certInfo
      unless (typ == tpmStAttestCertify) . failure $ TypeInvalid typ

      -- 4.3 Verify that extraData is set to the hash of attToBeSigned using
      -- the hash algorithm employed in "alg".
      case hashWithCorrectAlgorithm (Cose.signAlg aikPubKeyAndAlg) attToBeSigned of
        Just attHash -> do
          let PrettyHexByteString extraData = tpmsaExtraData certInfo
          unless (attHash == extraData) . failure $ HashMismatch attHash extraData
          pure ()
        Nothing -> failure HashFunctionUnknown

      -- 4.5 Verify that attested contains a TPMS_CERTIFY_INFO structure as
      -- specified in [TPMv2-Part2] section 10.12.3, whose name field contains
      -- a valid Name for pubArea, as computed using the algorithm in the
      -- nameAlg field of pubArea using the procedure specified in
      -- [TPMv2-Part1] section 16.
      let mPubAreaHash = case tpmtpNameAlg pubArea of
            TPMAlgSHA1 -> Right $ BA.convert $ hashWith SHA1 $ unPubAreaBytes pubAreaRaw
            TPMAlgSHA256 -> Right $ BA.convert $ hashWith SHA256 $ unPubAreaBytes pubAreaRaw
            TPMAlgECC -> Left TPMAlgECC
            TPMAlgRSA -> Left TPMAlgRSA

      case mPubAreaHash of
        Right pubAreaHash -> do
          let pubName = LBS.toStrict $
                Put.runPut $ do
                  Put.putWord16be (tpmtpNameAlgRaw pubArea)
                  Put.putByteString pubAreaHash

          let PrettyHexByteString name = tpmsciName (tpmsaAttested certInfo)
          unless (name == pubName) . failure $ NameMismatch pubName name
          pure ()
        Left alg -> failure $ NameAlgorithmInvalid alg

      -- 4.6 Verify that x5c is present
      -- NOTE: Done in decoding

      -- 4.7 Note that the remaining fields in the "Standard Attestation Structure"
      -- [TPMv2-Part1] section 31.2, i.e., qualifiedSigner, clockInfo and
      -- firmwareVersion are ignored. These fields MAY be used as an input to
      -- risk engines.
      -- NOTE: We don't implement a risk engine

      -- 4.8 Verify the sig is a valid signature over certInfo using the
      -- attestation public key in aikCert with the algorithm specified in alg.
      case Cose.verify aikPubKeyAndAlg (Cose.Message $ unCertInfoBytes certInfoRaw) sig of
        Right () -> pure ()
        Left err -> failure $ VerificationFailure err

      -- 4.9 Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation
      -- Statement Certificate Requirements.

      -- 4.9.1 Version MUST be set to 3.
      -- Version ::= INTEGER { v1(0), v2(1), v3(2) }, see https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.1
      let version = X509.certVersion aikCert
      unless (version == 2) . failure $ CertificateVersionInvalid version
      -- 4.9.2. Subject field MUST be set to empty.
      let subject = X509.getDistinguishedElements $ X509.certSubjectDN aikCert
      unless (null subject) . failure $ SubjectFieldNotEmpty subject
      -- 4.9.3 The Subject Alternative Name extension MUST be set as defined in
      -- [TPMv2-EK-Profile] section 3.2.9.
      -- 4.9.3.1 The TPM manufacturer identifies the manufacturer of the TPM. This value MUST be the
      -- vendor ID defined in the TCG Vendor ID Registry[3]
      let vendor = tpmManufacturer subjectAlternativeName
      unless (Set.member vendor tpmManufacturers) . failure $ VendorUnknown vendor

      -- 4.9.4 The Extended Key Usage extension MUST contain the OID
      -- 2.23.133.8.3 ("joint-iso-itu-t(2) internationalorganizations(23) 133
      -- tcg-kp(8) tcg-kp-AIKCertificate(3)").
      unless (X509.KeyUsagePurpose_Unknown [2, 23, 133, 8, 3] `elem` extendedKeyUsage) $ failure ExtKeyOIDMissing

      -- 4.9.5 The Basic Constraints extension MUST have the CA component set
      -- to false.
      when basicConstraintsCA $ failure BasicConstraintsTrue

      -- 4.9.6 An Authority Information Access (AIA) extension with entry
      -- id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both
      -- OPTIONAL as the status of many attestation certificates is available
      -- through metadata services. See, for example, the FIDO Metadata Service
      -- [FIDOMetadataService].
      -- NOTE: CRL checking and AIA can be done in a more general way after
      -- this function. See also <https://github.com/tweag/webauthn/issues/23>

      -- If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4
      -- (id-fido-gen-ce-aaguid) verify that the value of this extension
      -- matches the aaguid in authenticatorData.
      let credentialAAGUID = M.acdAaguid adAttestedCredentialData
      case aaguidExt of
        Just (IdFidoGenCeAAGUID aaguid) -> do
          unless (aaguid == credentialAAGUID) . failure $ CertificateAAGUIDMismatch aaguid credentialAAGUID
        Nothing -> pure ()

      pure $
        M.SomeAttestationType $
          M.AttestationTypeVerifiable M.VerifiableAttestationTypeUncertain (M.Fido2Chain x5c)
      where
        hashWithCorrectAlgorithm :: (BA.ByteArrayAccess ba, BA.ByteArray bout) => Cose.CoseSignAlg -> ba -> Maybe bout
        hashWithCorrectAlgorithm Cose.CoseSignAlgEdDSA _ =
          Nothing
        hashWithCorrectAlgorithm (Cose.CoseSignAlgECDSA Cose.CoseHashAlgECDSASHA256) bytes =
          pure $ BA.convert (Hash.hashWith Hash.SHA256 bytes)
        hashWithCorrectAlgorithm (Cose.CoseSignAlgECDSA Cose.CoseHashAlgECDSASHA384) bytes =
          pure $ BA.convert (Hash.hashWith Hash.SHA384 bytes)
        hashWithCorrectAlgorithm (Cose.CoseSignAlgECDSA Cose.CoseHashAlgECDSASHA512) bytes =
          pure $ BA.convert (Hash.hashWith Hash.SHA512 bytes)
        hashWithCorrectAlgorithm (Cose.CoseSignAlgRSA Cose.CoseHashAlgRSASHA1) bytes =
          pure $ BA.convert (Hash.hashWith Hash.SHA1 bytes)
        hashWithCorrectAlgorithm (Cose.CoseSignAlgRSA Cose.CoseHashAlgRSASHA256) bytes =
          pure $ BA.convert (Hash.hashWith Hash.SHA256 bytes)
        hashWithCorrectAlgorithm (Cose.CoseSignAlgRSA Cose.CoseHashAlgRSASHA384) bytes =
          pure $ BA.convert (Hash.hashWith Hash.SHA384 bytes)
        hashWithCorrectAlgorithm (Cose.CoseSignAlgRSA Cose.CoseHashAlgRSASHA512) bytes =
          pure $ BA.convert (Hash.hashWith Hash.SHA512 bytes)

  asfTrustAnchors _ _ = rootCertificateStore

rootCertificateStore :: X509.CertificateStore
rootCertificateStore = X509.makeCertificateStore $ map snd rootCertificates

-- | All known TPM root certificates along with their vendors
rootCertificates :: [(Text, X509.SignedCertificate)]
rootCertificates = processEntry <$> $(embedDir "root-certs/tpm")
  where
    processEntry :: (FilePath, BS.ByteString) -> (Text, X509.SignedCertificate)
    processEntry (path, bytes) = case X509.decodeSignedCertificate bytes of
      Right cert -> (Text.takeWhile (/= '/') (Text.pack path), cert)
      Left err -> error $ "Error while decoding certificate " <> path <> ": " <> err

-- | Helper function that wraps the TPM format into the general
-- SomeAttestationStatementFormat type.
format :: M.SomeAttestationStatementFormat
format = M.SomeAttestationStatementFormat Format
