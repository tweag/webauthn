{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

-- | Stability: experimental
-- This module implements the
-- [Android SafetyNet Attestation Statement Format](https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation).
module Crypto.WebAuthn.AttestationStatementFormat.AndroidSafetyNet
  ( format,
    Format (..),
    Integrity (..),
    VerificationError (..),
  )
where

import Codec.CBOR.Term (Term (TBytes, TString))
import qualified Codec.CBOR.Term as CBOR
import Control.Lens ((^.), (^?))
import Control.Lens.Combinators (_Just)
import Control.Monad (unless, when)
import Control.Monad.Except (MonadError, runExcept, throwError)
import qualified Crypto.Hash as Hash
import qualified Crypto.JOSE as JOSE
import qualified Crypto.JWT as JOSE
import Crypto.WebAuthn.Internal.DateOrphans ()
import Crypto.WebAuthn.Internal.Utils (failure)
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Data.ASN1.Types.String as X509
import Data.Aeson ((.=))
import qualified Data.Aeson as Aeson
import Data.Bifunctor (Bifunctor (first))
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy as LBS
import Data.Fixed (Fixed (MkFixed), Milli)
import Data.HashMap.Lazy ((!?))
import qualified Data.Hourglass as HG
import qualified Data.List.NonEmpty as NE
import Data.String (IsString)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8)
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import GHC.Exception (Exception)
import GHC.Generics (Generic)

-- | [(spec)](https://developer.android.com/training/safetynet/attestation#potential-integrity-verdicts)
-- The integrity of an android device from which a SafetyNet message
-- originated.
data Integrity
  = -- | The device has no integrity, which is the case for an emulator, or it
    -- could be the case for a compromised device
    NoIntegrity
  | -- | The device must have passed the basic integrity check, which is e.g.
    -- the case for a device with a custom ROM but not rooted, or a certified
    -- device with an unlocked bootloader
    BasicIntegrity
  | -- | The device passed the [CTS](https://source.android.com/compatibility/cts/),
    -- it is genuine and verified
    CTSProfileIntegrity
  deriving (Enum, Bounded, Eq, Ord, Show)

-- | The Android SafetyKey Format. Allows configuration of the required level of
-- trust.
data Format = Format
  { -- | What level the integrity check of the originating Android device must
    -- have passed.
    requiredIntegrity :: Integrity,
    -- | The maximum time the received message may be old for it to still be
    -- considered valid.
    driftBackwardsTolerance :: HG.Duration,
    -- | The maximum time difference the received message may report being from
    -- the future for it to still be considered valid.
    driftForwardsTolerance :: HG.Duration
  }

instance Show Format where
  show = Text.unpack . M.asfIdentifier

-- | [(spec)](https://developer.android.com/training/safetynet/attestation.html#compat-check-response)
data Response = Response
  { timestampMs :: Milliseconds,
    nonce :: Text,
    apkPackageName :: Text,
    apkCertificateDigestSha256 :: [Text], -- [Base 64 encoded SHA256 hash]
    ctsProfileMatch :: Bool,
    basicIntegrity :: Bool,
    evaluationType :: Text
  }
  deriving (Eq, Show, Generic, Aeson.FromJSON, Aeson.ToJSON)

-- | Milliseconds represented as an 'Integer', used for @timestampMs@
newtype Milliseconds = Milliseconds Integer
  deriving (Eq, Show)
  deriving newtype (Aeson.FromJSON, Aeson.ToJSON)
  deriving (HG.Timeable) via Milli

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation)
data Statement = Statement
  { ver :: Text.Text,
    x5c :: NE.NonEmpty X509.SignedCertificate,
    response :: Response,
    responseRaw :: BS.ByteString
  }
  deriving (Eq, Show)

instance Aeson.ToJSON Statement where
  toJSON Statement {..} =
    Aeson.object
      [ "ver" .= ver,
        "x5c" .= x5c,
        "response" .= response
      ]

-- | Verification errors specific to Android SafetyNet
data VerificationError
  = -- | The receiced nonce was not set to the concatenation of the
    -- authenticator data and client data hash
    NonceMismatch
      { -- | Nonce from the AndroidSafetyNet response
        responseNonce :: Text,
        -- | Base64 encoding of the SHA-256 hash of the concatenation of
        -- authenticatorData and clientDataHash
        calculatedNonce :: Text
      }
  | -- | The response was created to far in the past or future
    ResponseTimeInvalid
      { -- | The UTC time minus the allowed drift specified in the `Format`.
        lowerBound :: HG.DateTime,
        -- | The UTC time plus the allowed drift specified in the `Format`.
        upperBound :: HG.DateTime,
        -- | The UTC time when the Android SafetyNet response was generated
        generatedtime :: HG.DateTime
      }
  | -- | The integrity check failed based on the required integrity from the
    -- format
    IntegrityCheckFailed Integrity
  deriving (Show, Exception)

androidHostName :: VerificationHostName
androidHostName = "attest.android.com"

newtype VerificationHostName = VerificationHostName {unVerificationHostName :: X509.HostName}
  deriving newtype (IsString)

-- | This instance doesn't actually perform any validation
instance MonadError JOSE.Error m => JOSE.VerificationKeyStore m (JOSE.JWSHeader ()) p VerificationHostName where
  getVerificationKeys header _ hostName = do
    chain <- case header ^? JOSE.x5c . _Just . JOSE.param of
      Nothing -> throwError JOSE.JWSInvalidSignature
      Just chain -> pure chain

    let leaf = NE.head chain
    case X509.asn1CharacterToString
      =<< ( X509.getDnElement X509.DnCommonName
              . X509.certSubjectDN
              . X509.getCertificate
              $ leaf
          ) of
      Nothing -> pure ()
      Just commonName ->
        unless (commonName == unVerificationHostName hostName)
          . throwError
          $ JOSE.JWSInvalidSignature

    -- Create a JWK from the leaf certificate, which is used to sign the payload
    pure <$> JOSE.fromX509Certificate leaf

instance M.AttestationStatementFormat Format where
  type AttStmt Format = Statement
  asfIdentifier _ = "android-safetynet"

  asfDecode _ xs =
    case (xs !? "ver", xs !? "response") of
      (Just (TString ver), Just (TBytes responseRaw)) -> do
        jws <-
          first (("Failed to decode compact JWT response blob: " <>) . Text.pack . show) $
            runExcept @JOSE.Error $
              JOSE.decodeCompact (LBS.fromStrict responseRaw)
        response <-
          first (("Failed to verify/decode JWT payload: " <>) . Text.pack . show) $
            JOSE.verifyJWSWithPayload
              (first JOSE.JSONDecodeError . Aeson.eitherDecode)
              (JOSE.defaultJWTValidationSettings (const True))
              androidHostName
              jws
        x5c <- extractX5C jws
        pure $ Statement {..}
      _ -> Left $ "CBOR map didn't have expected types (ver: string, response: bytes): " <> Text.pack (show xs)
    where
      extractX5C :: JOSE.CompactJWS JOSE.JWSHeader -> Either Text (NE.NonEmpty X509.SignedCertificate)
      extractX5C jws = do
        sig <- case jws ^? JOSE.signatures of
          Nothing -> Left "Can't extract x5c because the JWT contains no signatures"
          Just res -> pure res
        JOSE.HeaderParam () x5c <- case sig ^. JOSE.header . JOSE.x5c of
          Nothing -> Left "No x5c in the header of the first JWT signature"
          Just res -> pure res
        pure x5c

  asfEncode _ Statement {..} =
    CBOR.TMap
      [ (TString "ver", TString ver),
        (TString "response", TBytes responseRaw)
      ]

  type AttStmtVerificationError Format = VerificationError
  asfVerify Format {..} now Statement {..} M.AuthenticatorData {adRawData = M.WithRaw rawData} clientDataHash = do
    -- 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to
    -- extract the contained fields.
    -- NOTE: Done in decoding

    -- 2. Verify that response is a valid SafetyNet response of version ver by following the steps indicated by the
    -- SafetyNet online documentation. As of this writing, there is only one format of the SafetyNet response and ver
    -- is reserved for future use.
    -- NOTE: As stated above, only one version exists, which we assume during decoding

    -- 3. Verify that the nonce attribute in the payload of response is identical to the Base64 encoding of the SHA-256
    -- hash of the concatenation of authenticatorData and clientDataHash.
    let signedData = rawData <> BA.convert (M.unClientDataHash clientDataHash)
    let hashedData = Hash.hashWith Hash.SHA256 signedData
    let encodedData = decodeUtf8 . Base64.encode $ BA.convert hashedData
    let responseNonce = nonce response
    unless (responseNonce == encodedData) . failure $ NonceMismatch responseNonce encodedData

    -- 4. Verify that the SafetyNet response actually came from the SafetyNet service by following the steps in the
    -- SafetyNet online documentation.
    -- 4.1. Extract the SSL certificate chain from the JWS message.
    -- NOTE: Done during decoding

    -- 4.2. Validate the SSL certificate chain and use SSL hostname matching to verify that the leaf certificate was
    -- issued to the hostname attest.android.com.
    -- NOTE: Done during decoding

    -- 4.3. Use the certificate to verify the signature of the JWS message.
    -- NOTE: Done during decoding. The jose library forces us to do verification before we access the payload. Since we
    -- would like to decode the payload during decoding, this step is also done during decoding.

    -- 4.4. Check the data of the JWS message to make sure it matches the data within your original request. In particular,
    -- make sure that the timestamp has been validated and that the nonce, package name, and hashes of the app's
    -- signing certificate(s) match the expected values.
    -- NOTE: For WebAuthn, we need not care about the package name or the app's signing certificate. The Nonce as
    -- has already been dealt with.
    let generatedTime = HG.timeConvert $ timestampMs response
    let lowerBound = now `HG.timeAdd` negate (HG.toSeconds driftBackwardsTolerance)
    let upperBound = now `HG.timeAdd` driftForwardsTolerance
    when (generatedTime < lowerBound) $ failure $ ResponseTimeInvalid lowerBound upperBound generatedTime
    when (generatedTime > upperBound) $ failure $ ResponseTimeInvalid lowerBound upperBound generatedTime

    let integrity = case (basicIntegrity response, ctsProfileMatch response) of
          (_, True) -> CTSProfileIntegrity
          (True, False) -> BasicIntegrity
          (False, False) -> NoIntegrity
    unless (integrity >= requiredIntegrity) $
      failure $
        IntegrityCheckFailed integrity

    -- 5. If successful, return implementation-specific values representing attestation type Basic and attestation trust
    -- path x5c.
    pure $
      M.SomeAttestationType $
        M.AttestationTypeVerifiable M.VerifiableAttestationTypeBasic (M.Fido2Chain x5c)

  asfTrustAnchors _ _ = mempty

-- | The default SafetyNet format configuration. Requires full
-- CTSProfileIntegrity and allows for the SafetyNet message to be at most 60
-- seconds old. Does not allow any timedrift into the future.
format :: M.SomeAttestationStatementFormat
format =
  M.SomeAttestationStatementFormat $
    Format
      { requiredIntegrity = CTSProfileIntegrity,
        driftBackwardsTolerance = mempty {HG.durationSeconds = 60},
        driftForwardsTolerance = mempty
      }
