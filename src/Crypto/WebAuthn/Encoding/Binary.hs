{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Stability: experimental
-- Certain parts of the specification require that data is decoded\/encoded
-- from\/to a binary form. This module holds such functions.
module Crypto.WebAuthn.Encoding.Binary
  ( -- * 'M.CollectedClientData'
    encodeRawCollectedClientData,
    stripRawCollectedClientData,
    decodeCollectedClientData,

    -- * 'M.AttestedCredentialData'
    encodeRawAttestedCredentialData,
    stripRawAttestedCredentialData,

    -- * 'M.AuthenticatorData'
    encodeRawAuthenticatorData,
    stripRawAuthenticatorData,
    decodeAuthenticatorData,

    -- * 'M.AttestationObject'
    encodeRawAttestationObject,
    stripRawAttestationObject,
    encodeAttestationObject,
    decodeAttestationObject,

    -- * 'M.AuthenticatorResponse'
    encodeRawAuthenticatorResponse,
    stripRawAuthenticatorResponse,

    -- * 'M.Credential'
    encodeRawCredential,
    stripRawCredential,
  )
where

import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Write as CBOR
import Codec.Serialise (Serialise (decode), encode)
import Control.Monad (unless)
import Control.Monad.Except (throwError)
import Control.Monad.State (MonadState (get, put), StateT (runStateT))
import qualified Crypto.Hash as Hash
import Crypto.WebAuthn.Internal.Utils (jsonEncodingOptions)
import Crypto.WebAuthn.Model.Identifier (AAGUID (AAGUID), unAAGUID)
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Data.Aeson as Aeson
import qualified Data.Binary.Get as Binary
import qualified Data.Binary.Put as Binary
import Data.Bits ((.|.))
import qualified Data.Bits as Bits
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Base64.URL as Base64Url
import Data.ByteString.Builder (Builder, stringUtf8, toLazyByteString)
import qualified Data.ByteString.Lazy as LBS
import qualified Data.HashMap.Strict as HashMap
import Data.Maybe (fromJust, fromMaybe)
import Data.Singletons (SingI (sing))
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import qualified Data.UUID as UUID
import Data.Word (Word16, Word8)
import GHC.Generics (Generic)

{-
The functions in this module are grouped and named according to the
following conventions:

  * If the type is parametrized by @raw@, there should be @stripRaw@ and
  @encodeRaw@ functions
  * If the type is serializable there should be a @decode@
  * In addition, if the type has a raw field for its own encoding (implying
    that it's parametrized by @raw@), no other function needs to be provided
  * Alternatively, there should be an @encode@ that encodes the type, using
    any nested raw fields if available

If the type is parametrized by @raw@, this module should guarantee these
invariants for any @value :: TheType (raw ~ False)@:

  * @stripRaw@ doesn't change any fields: @stripRaw value = value@
  * @encodeRaw@ doesn't change any fields: @stripRaw (encodeRaw value) = value@
  * If the type is also serializable:
  * If the type has a raw field, @decode@ inverses @encodeRaw@ and
    @getEncoded@: @stripRaw (decode (getEncoded (encodeRaw value))) = value@
  * Alternatively, @decode@ inverses @encodeRaw@ and @encode@:
    @stripRaw (decode (encode (encodeRaw value))) = value@

If the type is only serializable then this invariant should hold for any
@value :: TheType@

  * @decode@ inverses @encode@: @decode (encode value) = value@

If any such functions are expected to be used only internally, they may not be
exported
-}

-- | Webauthn contains a mixture of binary formats. For one it's CBOR and for
-- another it's a custom format. For CBOR we wish to use the
-- [cborg](https://hackage.haskell.org/package/cborg) library and for the
-- custom binary format the
-- [binary](https://hackage.haskell.org/package/binary) library. However these
-- two libraries don't interact nicely with each other. Because of this we are
-- specifying decoders that don't consume all input as a @PartialBinaryDecoder@,
-- which is just a state monad transformer over an 'LBS.ByteString'.
-- Using this we can somewhat easily flip between the two
-- libraries while decoding without too much nastiness.
type PartialBinaryDecoder a = StateT LBS.ByteString (Either Text) a

-- | Runs a @PartialBinaryDecoder@ using a strict bytestring. Afterwards it
-- makes sure that no bytes are left, otherwise returns an error.
runPartialBinaryDecoder ::
  BS.ByteString ->
  PartialBinaryDecoder a ->
  Either Text a
runPartialBinaryDecoder bytes decoder =
  case runStateT decoder . LBS.fromStrict $ bytes of
    Left err -> Left err
    Right (result, rest)
      | LBS.null rest -> return result
      | otherwise ->
          Left $
            "Not all binary input used, rest in base64 format is: "
              <> decodeUtf8 (Base64.encode $ LBS.toStrict rest)

-- | A @PartialBinaryDecoder@ for a binary encoding specified using
-- 'Binary.Get'.
runBinary ::
  Binary.Get a ->
  PartialBinaryDecoder a
runBinary decoder = do
  bytes <- get
  case Binary.runGetOrFail decoder bytes of
    Left (_rest, _offset, err) ->
      throwError $ "Binary decoding error: " <> Text.pack err
    Right (rest, _offset, result) -> do
      put rest
      pure result

-- | A @PartialBinaryDecoder@ for a CBOR encoding specified using the given
-- 'CBOR.Decoder'.
runCBOR ::
  (forall s. CBOR.Decoder s a) ->
  PartialBinaryDecoder (LBS.ByteString, a)
runCBOR decoder = do
  bytes <- get
  case CBOR.deserialiseFromBytesWithSize decoder bytes of
    Left err ->
      throwError $ "CBOR decoding error: " <> Text.pack (show err)
    Right (rest, consumed, a) -> do
      put rest
      pure (LBS.take (fromIntegral consumed) bytes, a)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authdataextensions) Encodes
-- [authenticator extension
-- outputs](https://www.w3.org/TR/webauthn-2/#authenticator-extension-output)
-- as a CBOR map.
encodeExtensions ::
  M.AuthenticatorExtensionOutputs ->
  Builder
encodeExtensions M.AuthenticatorExtensionOutputs {} =
  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.
  CBOR.toBuilder $ CBOR.encodeTerm (CBOR.TMap [])

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authdataextensions) Decodes a
-- CBOR map as [authenticator extension
-- outputs](https://www.w3.org/TR/webauthn-2/#authenticator-extension-output).
decodeExtensions ::
  PartialBinaryDecoder M.AuthenticatorExtensionOutputs
decodeExtensions = do
  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.
  (_, _extensions :: CBOR.Term) <- runCBOR CBOR.decodeTerm
  pure M.AuthenticatorExtensionOutputs {}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
-- Intermediate type used to extract the JSON structure stored in the
-- CBOR-encoded
-- [clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson).
data ClientDataJSON = ClientDataJSON
  { littype :: Text,
    challenge :: Text,
    origin :: Text,
    crossOrigin :: Maybe Bool
    -- TODO: We do not implement TokenBinding, see the documentation of
    -- `CollectedClientData` for more information.
    -- tokenBinding :: Maybe TokenBinding
  }
  deriving (Generic)

-- Note: Encoding should NOT be derived via aeson, use
-- 'encodeRawCollectedClientData' instead
instance Aeson.FromJSON ClientDataJSON where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data) Encodes
-- all raw fields of a 'M.CollectedClientData' into 'M.ccdRawData' using the
-- [JSON-compatible serialization of client
-- data](https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data)
-- This function is useful for testing.
encodeRawCollectedClientData ::
  forall (c :: K.CeremonyKind) raw.
  (SingI c) =>
  M.CollectedClientData c raw ->
  M.CollectedClientData c 'True
encodeRawCollectedClientData M.CollectedClientData {..} =
  M.CollectedClientData {ccdRawData = M.WithRaw bytes, ..}
  where
    bytes = LBS.toStrict $ toLazyByteString builder

    -- https://www.w3.org/TR/webauthn-2/#clientdatajson-serialization
    builder :: Builder
    builder =
      stringUtf8 "{\"type\":"
        <> jsonBuilder typeValue
        <> stringUtf8 ",\"challenge\":"
        <> jsonBuilder challengeValue
        <> stringUtf8 ",\"origin\":"
        <> jsonBuilder originValue
        <> stringUtf8 ",\"crossOrigin\":"
        <> jsonBuilder crossOriginValue
        <> stringUtf8 "}"

    typeValue :: Text
    typeValue = case sing @c of
      K.SRegistration -> "webauthn.create"
      K.SAuthentication -> "webauthn.get"

    challengeValue :: Text
    challengeValue = decodeUtf8 (Base64Url.encode (M.unChallenge ccdChallenge))

    originValue :: Text
    originValue = M.unOrigin ccdOrigin

    crossOriginValue :: Bool
    -- > If crossOrigin is not present, or is false:
    -- > Append 0x66616c7365 (false) to result.
    crossOriginValue = fromMaybe False ccdCrossOrigin

    jsonBuilder :: (Aeson.ToJSON a) => a -> Builder
    jsonBuilder = Aeson.fromEncoding . Aeson.toEncoding

-- | Removes all raw fields of a 'M.CollectedClientData'.
stripRawCollectedClientData ::
  M.CollectedClientData c raw ->
  M.CollectedClientData c 'False
stripRawCollectedClientData M.CollectedClientData {..} =
  M.CollectedClientData {ccdRawData = M.NoRaw, ..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data) Decodes
-- a 'M.CollectedClientData' from a 'BS.ByteString'. This is needed to parse
-- the
-- [clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
-- field in the
-- [AuthenticatorResponse](https://www.w3.org/TR/webauthn-2/#iface-authenticatorresponse)
-- structure, which is used for both attestation and assertion.
decodeCollectedClientData ::
  forall (c :: K.CeremonyKind).
  (SingI c) =>
  BS.ByteString ->
  Either Text (M.CollectedClientData c 'True)
decodeCollectedClientData bytes = do
  -- <https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data>
  ClientDataJSON {..} <- case Aeson.eitherDecodeStrict bytes of
    Left err ->
      Left $
        "Collected client data JSON decoding error: "
          <> Text.pack err
    Right res -> pure res

  -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-challenge)
  -- This member contains the base64url encoding of the challenge provided by
  -- the [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party). See
  -- the [§ 13.4.3 Cryptographic
  -- Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
  -- security consideration.
  challenge <- case Base64Url.decode (encodeUtf8 challenge) of
    Left err ->
      Left $
        "Failed to base64url-decode challenge "
          <> challenge
          <> ": "
          <> Text.pack err
    Right res -> pure res

  -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type)
  -- This member contains the string "webauthn.create" when creating new
  -- credentials, and "webauthn.get" when getting an assertion from an existing
  -- credential. The purpose of this member is to prevent certain types of
  -- signature confusion attacks (where an attacker substitutes one legitimate
  -- signature for another).
  let expectedType = case sing @c of
        K.SRegistration -> "webauthn.create"
        K.SAuthentication -> "webauthn.get"
  unless (littype == expectedType) $
    Left $
      "Expected collected client data to have webauthn type "
        <> expectedType
        <> " but it is "
        <> littype
  pure
    M.CollectedClientData
      { ccdChallenge = M.Challenge challenge,
        ccdOrigin = M.Origin origin,
        ccdCrossOrigin = crossOrigin,
        ccdRawData = M.WithRaw bytes
      }

-- | Encodes all raw fields of a 'M.AttestedCredentialData', particularly
-- encodes 'M.acdCredentialPublicKey' using its 'Serialise' instance into
-- 'M.acdCredentialPublicKeyBytes', see
-- [@credentialPublicKey@](https://www.w3.org/TR/webauthn-2/#credentialpublickey).
encodeRawAttestedCredentialData ::
  M.AttestedCredentialData c raw ->
  M.AttestedCredentialData c 'True
encodeRawAttestedCredentialData M.AttestedCredentialData {..} =
  M.AttestedCredentialData
    { acdCredentialPublicKeyBytes = M.WithRaw $ LBS.toStrict bytes,
      ..
    }
  where
    bytes = CBOR.toLazyByteString $ encode acdCredentialPublicKey
encodeRawAttestedCredentialData M.NoAttestedCredentialData =
  M.NoAttestedCredentialData

-- | Removes all raw fields of a 'M.AttestedCredentialData'.
stripRawAttestedCredentialData ::
  M.AttestedCredentialData c raw ->
  M.AttestedCredentialData c 'False
stripRawAttestedCredentialData M.AttestedCredentialData {..} =
  M.AttestedCredentialData {acdCredentialPublicKeyBytes = M.NoRaw, ..}
stripRawAttestedCredentialData M.NoAttestedCredentialData =
  M.NoAttestedCredentialData

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data)
-- Encodes attested credential data into bytes, used by
-- 'encodeRawAuthenticatorData'.
encodeAttestedCredentialData ::
  M.AttestedCredentialData 'K.Registration 'True ->
  Builder
encodeAttestedCredentialData M.AttestedCredentialData {..} =
  Binary.execPut (Binary.putLazyByteString $ UUID.toByteString $ unAAGUID acdAaguid)
    <> Binary.execPut (Binary.putWord16be credentialLength)
    <> Binary.execPut (Binary.putByteString $ M.unCredentialId acdCredentialId)
    <> Binary.execPut (Binary.putByteString $ M.unRaw acdCredentialPublicKeyBytes)
  where
    credentialLength :: Word16
    credentialLength = fromIntegral $ BS.length $ M.unCredentialId acdCredentialId

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data)
-- Decodes attested credential data from bytes, used by
-- 'decodeAuthenticatorData'.
decodeAttestedCredentialData ::
  PartialBinaryDecoder (M.AttestedCredentialData 'K.Registration 'True)
decodeAttestedCredentialData = do
  -- https://www.w3.org/TR/webauthn-2/#aaguid
  acdAaguid <-
    -- Note: fromJust is safe because UUID.fromByteString only returns
    -- nothing if there's not exactly 16 bytes
    AAGUID . fromJust . UUID.fromByteString
      <$> runBinary (Binary.getLazyByteString 16)

  -- https://www.w3.org/TR/webauthn-2/#credentialidlength
  credentialLength <-
    runBinary Binary.getWord16be

  -- https://www.w3.org/TR/webauthn-2/#credentialid
  acdCredentialId <-
    M.CredentialId
      <$> runBinary (Binary.getByteString (fromIntegral credentialLength))

  -- https://www.w3.org/TR/webauthn-2/#credentialpublickey
  (usedBytes, acdCredentialPublicKey) <- runCBOR decode
  let acdCredentialPublicKeyBytes = M.WithRaw $ LBS.toStrict usedBytes

  pure M.AttestedCredentialData {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticator-data)
-- Encodes all raw-containing fields of a 'M.AuthenticatorData', particularly
-- 'M.adAttestedCredentialData', and the 'M.AuthenticatorData' itself into
-- 'M.adRawData'. This function is needed for an authenticator implementation.
encodeRawAuthenticatorData ::
  forall (c :: K.CeremonyKind) raw.
  (SingI c) =>
  M.AuthenticatorData c raw ->
  M.AuthenticatorData c 'True
encodeRawAuthenticatorData M.AuthenticatorData {..} =
  M.AuthenticatorData
    { adRawData = M.WithRaw bytes,
      adAttestedCredentialData = rawAttestedCredentialData,
      ..
    }
  where
    rawAttestedCredentialData =
      encodeRawAttestedCredentialData adAttestedCredentialData

    bytes :: BS.ByteString
    bytes = LBS.toStrict $ toLazyByteString builder

    -- https://www.w3.org/TR/webauthn-2/#flags
    flags :: Word8
    flags =
      userPresentFlag
        .|. userVerifiedFlag
        .|. attestedCredentialDataPresentFlag
        .|. extensionsPresentFlag
      where
        userPresentFlag = if M.adfUserPresent adFlags then Bits.bit 0 else 0
        userVerifiedFlag = if M.adfUserVerified adFlags then Bits.bit 2 else 0
        attestedCredentialDataPresentFlag = case sing @c of
          K.SRegistration -> Bits.bit 6
          K.SAuthentication -> 0
        extensionsPresentFlag = case adExtensions of
          Just _ -> Bits.bit 7
          Nothing -> 0

    -- https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
    builder :: Builder
    builder =
      Binary.execPut (Binary.putByteString $ convert $ M.unRpIdHash adRpIdHash)
        <> Binary.execPut (Binary.putWord8 flags)
        <> Binary.execPut (Binary.putWord32be $ M.unSignatureCounter adSignCount)
        <> ( case sing @c of
               K.SRegistration ->
                 encodeAttestedCredentialData rawAttestedCredentialData
               K.SAuthentication ->
                 mempty
           )
        <> maybe mempty encodeExtensions adExtensions

-- | Removes all raw fields from a 'M.AuthenticatorData'.
stripRawAuthenticatorData ::
  M.AuthenticatorData c raw ->
  M.AuthenticatorData c 'False
stripRawAuthenticatorData M.AuthenticatorData {..} =
  M.AuthenticatorData
    { adRawData = M.NoRaw,
      adAttestedCredentialData =
        stripRawAttestedCredentialData adAttestedCredentialData,
      ..
    }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticator-data) Decodes a
-- 'M.AuthenticatorData' from a 'BS.ByteString'. This is needed to parse a
-- webauthn clients
-- [authenticatorData](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata)
-- field in the
-- [AuthenticatorAssertionResponse](https://www.w3.org/TR/webauthn-2/#iface-authenticatorassertionresponse)
-- structure.
decodeAuthenticatorData ::
  forall (c :: K.CeremonyKind).
  (SingI c) =>
  BS.ByteString ->
  Either Text (M.AuthenticatorData c 'True)
decodeAuthenticatorData strictBytes = runPartialBinaryDecoder strictBytes $ do
  -- https://www.w3.org/TR/webauthn-2/#authenticator-data
  let adRawData = M.WithRaw strictBytes

  -- https://www.w3.org/TR/webauthn-2/#rpidhash
  adRpIdHash <-
    M.RpIdHash . fromJust . Hash.digestFromByteString
      <$> runBinary (Binary.getByteString 32)

  -- https://www.w3.org/TR/webauthn-2/#flags
  bitFlags <- runBinary Binary.getWord8
  let adFlags =
        M.AuthenticatorDataFlags
          { M.adfUserPresent = Bits.testBit bitFlags 0,
            M.adfUserVerified = Bits.testBit bitFlags 2
          }

  -- https://www.w3.org/TR/webauthn-2/#signcount
  adSignCount <- M.SignatureCounter <$> runBinary Binary.getWord32be

  -- https://www.w3.org/TR/webauthn-2/#attestedcredentialdata
  adAttestedCredentialData <- case (sing @c, Bits.testBit bitFlags 6) of
    -- For [attestation
    -- signatures](https://www.w3.org/TR/webauthn-2/#attestation-signature),
    -- the authenticator MUST set the AT
    -- [flag](https://www.w3.org/TR/webauthn-2/#flags) and include the
    -- `[attestedCredentialData](https://www.w3.org/TR/webauthn-2/#attestedcredentialdata)`.
    (K.SRegistration, True) ->
      decodeAttestedCredentialData
    (K.SRegistration, False) ->
      throwError "Expected attested credential data, but there is none"
    -- For [assertion
    -- signatures](https://www.w3.org/TR/webauthn-2/#assertion-signature), the
    -- AT [flag](https://www.w3.org/TR/webauthn-2/#flags) MUST NOT be set and
    -- the
    -- `[attestedCredentialData](https://www.w3.org/TR/webauthn-2/#attestedcredentialdata)`
    -- MUST NOT be included.
    (K.SAuthentication, False) ->
      pure M.NoAttestedCredentialData
    (K.SAuthentication, True) ->
      throwError "Expected no attested credential data, but there is"

  -- https://www.w3.org/TR/webauthn-2/#authdataextensions
  adExtensions <-
    if Bits.testBit bitFlags 7
      then Just <$> decodeExtensions
      else pure Nothing

  pure M.AuthenticatorData {..}

-- | Encodes all raw fields of an 'M.AttestationObject'.
encodeRawAttestationObject ::
  M.AttestationObject raw ->
  M.AttestationObject 'True
encodeRawAttestationObject M.AttestationObject {..} =
  M.AttestationObject
    { aoAuthData = encodeRawAuthenticatorData aoAuthData,
      ..
    }

-- | Removes all raw fields of an 'M.AttestationObject'.
stripRawAttestationObject ::
  M.AttestationObject raw ->
  M.AttestationObject 'False
stripRawAttestationObject M.AttestationObject {..} =
  M.AttestationObject
    { aoAuthData = stripRawAuthenticatorData aoAuthData,
      ..
    }

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
-- Encodes an 'M.AttestationObject' as a 'BS.ByteString'. This is needed by
-- the client side to generate a valid JSON response.
encodeAttestationObject ::
  M.AttestationObject 'True ->
  BS.ByteString
encodeAttestationObject M.AttestationObject {..} =
  CBOR.toStrictByteString $ CBOR.encodeTerm term
  where
    -- https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object
    term :: CBOR.Term
    term =
      CBOR.TMap
        [ (CBOR.TString "authData", CBOR.TBytes $ M.unRaw $ M.adRawData aoAuthData),
          (CBOR.TString "fmt", CBOR.TString $ M.asfIdentifier aoFmt),
          (CBOR.TString "attStmt", M.asfEncode aoFmt aoAttStmt)
        ]

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
-- Decodes a 'M.AttestationObject' from a 'BS.ByteString'. This is needed to
-- parse a webauthn clients
-- [attestationObject](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject)
-- field in the
-- [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse)
-- structure This function takes a 'M.SupportedAttestationStatementFormats'
-- argument to indicate which attestation statement formats are supported.
-- structure.
decodeAttestationObject ::
  M.SupportedAttestationStatementFormats ->
  BS.ByteString ->
  Either Text (M.AttestationObject 'True)
decodeAttestationObject supportedFormats bytes = do
  (_consumed, result) <-
    runPartialBinaryDecoder bytes (runCBOR CBOR.decodeTerm)
  pairs <- case result of
    CBOR.TMap pairs -> return pairs
    _ ->
      Left $
        "The attestation object should be a CBOR map, but it's not: "
          <> Text.pack (show result)

  -- https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object
  case ( CBOR.TString "authData" `lookup` pairs,
         CBOR.TString "fmt" `lookup` pairs,
         CBOR.TString "attStmt" `lookup` pairs
       ) of
    ( Just (CBOR.TBytes authDataBytes),
      Just (CBOR.TString fmt),
      Just (CBOR.TMap attStmtPairs)
      ) -> do
        aoAuthData <- decodeAuthenticatorData authDataBytes

        case M.lookupAttestationStatementFormat fmt supportedFormats of
          Nothing -> Left $ "Unknown attestation statement format: " <> fmt
          Just (M.SomeAttestationStatementFormat aoFmt) -> do
            attStmtMap <-
              HashMap.fromList
                <$> traverse textKeyPairs attStmtPairs
            aoAttStmt <- M.asfDecode aoFmt attStmtMap
            pure M.AttestationObject {..}
    _ ->
      Left $
        "The attestation object doesn't have the expected structure of "
          <> "(authData: bytes, fmt: string, attStmt: map): "
          <> Text.pack (show result)
  where
    textKeyPairs (CBOR.TString text, term) = pure (text, term)
    textKeyPairs (nonString, _) =
      Left $
        "Unexpected non-string attestation statement key: "
          <> Text.pack (show nonString)

-- | Encode all raw fields of an 'M.AuthenticatorResponse'.
encodeRawAuthenticatorResponse ::
  M.AuthenticatorResponse c raw ->
  M.AuthenticatorResponse c 'True
encodeRawAuthenticatorResponse M.AuthenticatorResponseRegistration {..} =
  M.AuthenticatorResponseRegistration
    { arrClientData = encodeRawCollectedClientData arrClientData,
      arrAttestationObject = encodeRawAttestationObject arrAttestationObject,
      ..
    }
encodeRawAuthenticatorResponse M.AuthenticatorResponseAuthentication {..} =
  M.AuthenticatorResponseAuthentication
    { araClientData = encodeRawCollectedClientData araClientData,
      araAuthenticatorData = encodeRawAuthenticatorData araAuthenticatorData,
      ..
    }

-- | Removes all raw fields of an 'M.AuthenticatorResponse'.
stripRawAuthenticatorResponse ::
  M.AuthenticatorResponse c raw ->
  M.AuthenticatorResponse c 'False
stripRawAuthenticatorResponse M.AuthenticatorResponseRegistration {..} =
  M.AuthenticatorResponseRegistration
    { arrClientData = stripRawCollectedClientData arrClientData,
      arrAttestationObject = stripRawAttestationObject arrAttestationObject,
      ..
    }
stripRawAuthenticatorResponse M.AuthenticatorResponseAuthentication {..} =
  M.AuthenticatorResponseAuthentication
    { araClientData = stripRawCollectedClientData araClientData,
      araAuthenticatorData = stripRawAuthenticatorData araAuthenticatorData,
      ..
    }

-- | Encodes all raw fields of an 'M.Credential'.
encodeRawCredential ::
  M.Credential c raw ->
  M.Credential c 'True
encodeRawCredential M.Credential {..} =
  M.Credential
    { cResponse = encodeRawAuthenticatorResponse cResponse,
      ..
    }

-- | Removes all raw fields of an 'M.Credential'.
stripRawCredential ::
  M.Credential c raw ->
  M.Credential c 'False
stripRawCredential M.Credential {..} =
  M.Credential
    { cResponse = stripRawAuthenticatorResponse cResponse,
      ..
    }
