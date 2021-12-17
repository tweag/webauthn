{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.WebAuthn.Model.Binary.Decoding
  ( -- * Error types
    DecodingError (..),
    CreatedDecodingError (..),

    -- * Decoding from bytes
    decodeAuthenticatorData,
    decodeAttestationObject,
    decodeCollectedClientData,

    -- * Stripping raw fields
    stripRawPublicKeyCredential,
  )
where

import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.Serialise as CBOR
import Control.Exception (Exception, SomeException (SomeException))
import Control.Monad (forM, unless)
import qualified Crypto.Hash as Hash
import Crypto.WebAuthn.EncodingUtils (CustomJSON (CustomJSON), JSONEncoding)
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Model.JavaScript as JS
import Crypto.WebAuthn.PublicKey (decodePublicKey)
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.Bifunctor (first, second)
import qualified Data.Binary.Get as Binary
import qualified Data.Bits as Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as Base64Url
import qualified Data.ByteString.Lazy as LBS
import Data.HashMap.Strict (HashMap, (!?))
import qualified Data.HashMap.Strict as HashMap
import Data.Maybe (fromJust, fromMaybe)
import Data.Singletons (SingI, sing)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import qualified Data.UUID as UUID
import GHC.Generics (Generic)

-- | Decoding errors that can only occur when decoding a
-- 'M.AttestationObject' result with 'decodeAttestationObject'
data CreatedDecodingError
  = -- | Any of the below specified 'DecodingError's occured
    CreatedDecodingErrorCommon DecodingError
  | -- | The Attestation format could not be decoded because the provided
    -- format is not part of the webauthn specification or not supported by this
    -- library
    CreatedDecodingErrorUnknownAttestationStatementFormat Text
  | -- | A CBOR String was expected but a different type was encountered
    CreatedDecodingErrorUnexpectedAttestationStatementKey CBOR.Term
  | -- | An error was encountered during the decoding of the attestation
    -- statement format
    CreatedDecodingErrorAttestationStatement SomeException
  | -- | The CBOR-encoded attestation object did not contain the required
    -- "authData", "fmt" and "attStmt" fields, or their respective values were
    -- not the correct types
    CreatedDecodingErrorUnexpectedAttestationObjectValues (HashMap Text CBOR.Term)
  deriving (Show, Exception)

-- | Decoding errors that can occur when doing binary decoding of webauthn client
-- responses
data DecodingError
  = -- | The Client data could not be decoded for the provided reason
    DecodingErrorClientDataJSON String
  | -- | The Challenge could not be decoded from its Base64-based encoding for
    -- the provided reason
    DecodingErrorClientDataChallenge String
  | -- | The Client Data's Webauthn type did not match the expected one
    -- (first: expected, second: received)
    DecodingErrorUnexpectedWebauthnType IDL.DOMString IDL.DOMString
  | -- | The client data had the create type but the authenticator data's
    -- attested credential data flag was not set.
    DecodingErrorExpectedAttestedCredentialData
  | -- | The client data had the get type but the authenticator data's
    -- attested credential data flag was set.
    DecodingErrorUnexpectedAttestedCredentialData
  | -- | After decoding the authenticator data, the data in the error remained
    -- undecoded
    DecodingErrorNotAllInputUsed LBS.ByteString
  | -- | The given error occured during decoding of binary data
    DecodingErrorBinary String
  | -- | The given error occured during decoding of CBOR-encoded data
    DecodingErrorCBOR CBOR.DeserialiseFailure
  | -- | The decoded algorithm identifier does not match the desired algorithm
    DecodingErrorUnexpectedAlgorithmIdentifier JS.COSEAlgorithmIdentifier
  deriving (Show, Exception)

-- | Webauthn contains a mixture of binary formats. For one it's CBOR and
-- for another it's a custom format. For CBOR we wish to use the
-- [cborg](https://hackage.haskell.org/package/cborg) library
-- and for the custom binary format the [binary](https://hackage.haskell.org/package/binary)
-- library. However these two libraries don't interact nicely with each other.
-- Because of this we are specifying the decoders as a 'PartialBinaryDecoder DecodingError',
-- which is just a function that can partially consume a 'LBS.ByteString'.
-- Using this we can somewhat easily flip between the two libraries while
-- decoding without too much nastiness.
type PartialBinaryDecoder e a = LBS.ByteString -> Either e (LBS.ByteString, a)

-- | A 'PartialBinaryDecoder DecodingError' for a binary encoding specified using 'Binary.Get'
runBinary :: Binary.Get a -> PartialBinaryDecoder DecodingError a
runBinary get bytes = case Binary.runGetOrFail get bytes of
  Left (_rest, _offset, err) -> Left $ DecodingErrorBinary err
  Right (rest, _offset, result) -> Right (rest, result)

-- | A 'PartialBinaryDecoder DecodingError' for a CBOR encoding specified using the given Decoder
runCBOR :: (forall s. CBOR.Decoder s a) -> PartialBinaryDecoder DecodingError (LBS.ByteString, a)
runCBOR decoder bytes = case CBOR.deserialiseFromBytesWithSize decoder bytes of
  Left err -> Left $ DecodingErrorCBOR err
  Right (rest, consumed, a) -> return (rest, (LBS.take (fromIntegral consumed) bytes, a))

-- | Decodes a 'M.AuthenticatorData' from a 'BS.ByteString'.
-- This is needed to parse a webauthn clients
-- [authenticatorData](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata)
-- field in the [AuthenticatorAssertionResponse](https://www.w3.org/TR/webauthn-2/#iface-authenticatorassertionresponse)
-- structure
decodeAuthenticatorData ::
  forall t.
  SingI t =>
  BS.ByteString ->
  Either DecodingError (M.AuthenticatorData t 'True)
decodeAuthenticatorData strictBytes = do
  -- https://www.w3.org/TR/webauthn-2/#authenticator-data
  let bytes = LBS.fromStrict strictBytes
      adRawData = M.WithRaw strictBytes
  -- https://www.w3.org/TR/webauthn-2/#rpidhash
  (bytes, adRpIdHash) <-
    second (M.RpIdHash . fromJust . Hash.digestFromByteString)
      <$> runBinary (Binary.getByteString 32) bytes

  -- https://www.w3.org/TR/webauthn-2/#flags
  (bytes, bitFlags) <-
    runBinary Binary.getWord8 bytes
  let adFlags =
        M.AuthenticatorDataFlags
          { M.adfUserPresent = Bits.testBit bitFlags 0,
            M.adfUserVerified = Bits.testBit bitFlags 2
          }

  -- https://www.w3.org/TR/webauthn-2/#signcount
  (bytes, adSignCount) <-
    second M.SignatureCounter
      <$> runBinary Binary.getWord32be bytes

  -- https://www.w3.org/TR/webauthn-2/#attestedcredentialdata
  (bytes, adAttestedCredentialData) <- case (sing @t, Bits.testBit bitFlags 6) of
    -- For [attestation signatures](https://www.w3.org/TR/webauthn-2/#attestation-signature),
    -- the authenticator MUST set the AT [flag](https://www.w3.org/TR/webauthn-2/#flags)
    -- and include the `[attestedCredentialData](https://www.w3.org/TR/webauthn-2/#attestedcredentialdata)`.
    (M.SCreate, True) -> decodeAttestedCredentialData bytes
    (M.SCreate, False) -> Left DecodingErrorExpectedAttestedCredentialData
    -- For [assertion signatures](https://www.w3.org/TR/webauthn-2/#assertion-signature),
    -- the AT [flag](https://www.w3.org/TR/webauthn-2/#flags) MUST NOT be set and the
    -- `[attestedCredentialData](https://www.w3.org/TR/webauthn-2/#attestedcredentialdata)` MUST NOT be included.
    (M.SGet, False) -> pure (bytes, M.NoAttestedCredentialData)
    (M.SGet, True) -> Left DecodingErrorUnexpectedAttestedCredentialData

  -- https://www.w3.org/TR/webauthn-2/#authdataextensions
  (bytes, adExtensions) <-
    if Bits.testBit bitFlags 7
      then fmap Just <$> decodeExtensions bytes
      else pure (bytes, Nothing)

  if LBS.null bytes
    then pure M.AuthenticatorData {..}
    else Left $ DecodingErrorNotAllInputUsed bytes
  where
    decodeAttestedCredentialData :: PartialBinaryDecoder DecodingError (M.AttestedCredentialData 'M.Create 'True)
    decodeAttestedCredentialData bytes = do
      -- https://www.w3.org/TR/webauthn-2/#aaguid
      (bytes, acdAaguid) <-
        -- Note: fromJust is safe because UUID.fromByteString only returns
        -- nothing if there's not exactly 16 bytes
        second (M.AAGUID . fromJust . UUID.fromByteString)
          <$> runBinary (Binary.getLazyByteString 16) bytes

      -- https://www.w3.org/TR/webauthn-2/#credentialidlength
      (bytes, credentialLength) <-
        runBinary Binary.getWord16be bytes

      -- https://www.w3.org/TR/webauthn-2/#credentialid
      (bytes, acdCredentialId) <-
        second M.CredentialId
          <$> runBinary (Binary.getByteString (fromIntegral credentialLength)) bytes

      -- https://www.w3.org/TR/webauthn-2/#credentialpublickey
      (bytes, (usedBytes, acdCredentialPublicKey)) <-
        runCBOR decodePublicKey bytes
      let acdCredentialPublicKeyBytes = M.WithRaw $ LBS.toStrict usedBytes

      pure (bytes, M.AttestedCredentialData {..})

    decodeExtensions :: PartialBinaryDecoder DecodingError M.AuthenticatorExtensionOutputs
    decodeExtensions bytes = do
      -- TODO
      (bytes, (_, _extensions :: HashMap Text CBOR.Term)) <- runCBOR CBOR.decode bytes
      pure (bytes, M.AuthenticatorExtensionOutputs {})

-- | Decodes a 'M.AttestationObject' from a 'BS.ByteString'. This is needed
-- to parse a clients webauthn response for attestation only. This function takes
-- a 'M.SupportedAttestationStatementFormats' argument to indicate which
-- attestation statement formats are supported.
--
-- | Decodes a 'M.AttestationObject' from a 'BS.ByteString'.
-- This is needed to parse a webauthn clients
-- [attestationObject](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject)
-- field in the [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse)
-- structure
decodeAttestationObject :: M.SupportedAttestationStatementFormats -> BS.ByteString -> Either CreatedDecodingError (M.AttestationObject 'True)
decodeAttestationObject supportedFormats bytes = do
  -- https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object
  map :: HashMap Text CBOR.Term <- first (CreatedDecodingErrorCommon . DecodingErrorCBOR) $ CBOR.deserialiseOrFail $ LBS.fromStrict bytes
  case (map !? "authData", map !? "fmt", map !? "attStmt") of
    (Just (CBOR.TBytes authDataBytes), Just (CBOR.TString fmt), Just (CBOR.TMap attStmtPairs)) -> do
      aoAuthData <- first CreatedDecodingErrorCommon $ decodeAuthenticatorData authDataBytes

      case M.sasfLookup fmt supportedFormats of
        Nothing -> Left $ CreatedDecodingErrorUnknownAttestationStatementFormat fmt
        Just (M.SomeAttestationStatementFormat aoFmt) -> do
          attStmtMap <-
            HashMap.fromList <$> forM attStmtPairs \case
              (CBOR.TString text, term) -> pure (text, term)
              (nonString, _) -> Left $ CreatedDecodingErrorUnexpectedAttestationStatementKey nonString
          aoAttStmt <-
            first (CreatedDecodingErrorAttestationStatement . SomeException) $
              M.asfDecode aoFmt attStmtMap
          pure M.AttestationObject {..}
    _ -> Left $ CreatedDecodingErrorUnexpectedAttestationObjectValues map

--- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
--- Intermediate type used to extract the JSON structure stored in the
--- CBOR-encoded [clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson).
data ClientDataJSON = ClientDataJSON
  { littype :: IDL.DOMString,
    challenge :: IDL.DOMString,
    origin :: IDL.DOMString,
    crossOrigin :: Maybe IDL.Boolean
    -- TODO
    -- tokenBinding :: Maybe TokenBinding
  }
  deriving (Generic)
  -- Note: Encoding should NOT be derived via aeson. See the Encoding module instead
  deriving (Aeson.FromJSON) via JSONEncoding ClientDataJSON

-- | Decodes a 'M.CollectedClientData' from a 'BS.ByteString'. This is needed
-- to parse the [clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
-- field in the [AuthenticatorResponse](https://www.w3.org/TR/webauthn-2/#iface-authenticatorresponse)
-- structure, which is used for both attestation and assertion
decodeCollectedClientData :: forall t. SingI t => BS.ByteString -> Either DecodingError (M.CollectedClientData t 'True)
decodeCollectedClientData bytes = do
  -- https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data
  ClientDataJSON {..} <- first DecodingErrorClientDataJSON $ Aeson.eitherDecodeStrict bytes
  -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-challenge)
  -- This member contains the base64url encoding of the challenge provided by the
  -- [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party). See the
  -- [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
  -- security consideration.
  challenge <- first DecodingErrorClientDataChallenge $ Base64Url.decode (Text.encodeUtf8 challenge)
  -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type)
  -- This member contains the string "webauthn.create" when creating new credentials,
  -- and "webauthn.get" when getting an assertion from an existing credential.
  -- The purpose of this member is to prevent certain types of signature confusion
  -- attacks (where an attacker substitutes one legitimate signature for another).
  let expectedType = case sing @t of
        M.SCreate -> "webauthn.create"
        M.SGet -> "webauthn.get"
  unless (littype == expectedType) $ Left (DecodingErrorUnexpectedWebauthnType expectedType littype)
  pure
    M.CollectedClientData
      { ccdChallenge = M.Challenge challenge,
        ccdOrigin = M.Origin origin,
        ccdCrossOrigin = fromMaybe False crossOrigin,
        ccdRawData = M.WithRaw bytes
      }

-- | Removes all raw fields from a 'M.PublicKeyCredential', useful for
-- e.g. pretty-printing only the desired fields. This is the counterpart to
-- 'Crypto.WebAuthn.Model.Binary.Encoding.encodeRawPublicKeyCredential'
stripRawPublicKeyCredential :: forall t raw. SingI t => M.PublicKeyCredential t raw -> M.PublicKeyCredential t 'False
stripRawPublicKeyCredential M.PublicKeyCredential {..} =
  M.PublicKeyCredential
    { pkcResponse = case sing @t of
        M.SCreate -> stripRawAuthenticatorAttestationResponse pkcResponse
        M.SGet -> stripRawAuthenticatorAssertionResponse pkcResponse,
      ..
    }
  where
    stripRawAuthenticatorAssertionResponse :: M.AuthenticatorResponse 'M.Get raw -> M.AuthenticatorResponse 'M.Get 'False
    stripRawAuthenticatorAssertionResponse M.AuthenticatorAssertionResponse {..} =
      M.AuthenticatorAssertionResponse
        { argClientData = stripRawCollectedClientData argClientData,
          argAuthenticatorData = stripRawAuthenticatorData argAuthenticatorData,
          ..
        }

    stripRawAuthenticatorAttestationResponse :: M.AuthenticatorResponse 'M.Create raw -> M.AuthenticatorResponse 'M.Create 'False
    stripRawAuthenticatorAttestationResponse M.AuthenticatorAttestationResponse {..} =
      M.AuthenticatorAttestationResponse
        { arcClientData = stripRawCollectedClientData arcClientData,
          arcAttestationObject = stripRawAttestationObject arcAttestationObject,
          ..
        }

    stripRawAttestationObject :: M.AttestationObject raw -> M.AttestationObject 'False
    stripRawAttestationObject M.AttestationObject {..} =
      M.AttestationObject
        { aoAuthData = stripRawAuthenticatorData aoAuthData,
          ..
        }

    stripRawAuthenticatorData :: forall t raw. SingI t => M.AuthenticatorData t raw -> M.AuthenticatorData t 'False
    stripRawAuthenticatorData M.AuthenticatorData {..} =
      M.AuthenticatorData
        { adRawData = M.NoRaw,
          adAttestedCredentialData = stripRawAttestedCredentialData adAttestedCredentialData,
          ..
        }

    stripRawAttestedCredentialData :: forall t raw. SingI t => M.AttestedCredentialData t raw -> M.AttestedCredentialData t 'False
    stripRawAttestedCredentialData = case sing @t of
      M.SCreate -> \M.AttestedCredentialData {..} -> M.AttestedCredentialData {acdCredentialPublicKeyBytes = M.NoRaw, ..}
      M.SGet -> \M.NoAttestedCredentialData -> M.NoAttestedCredentialData

    stripRawCollectedClientData :: forall t raw. SingI t => M.CollectedClientData t raw -> M.CollectedClientData t 'False
    stripRawCollectedClientData M.CollectedClientData {..} = M.CollectedClientData {ccdRawData = M.NoRaw, ..}
