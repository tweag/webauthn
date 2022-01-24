{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Stability: internal
-- Certain parts of the specification require that data is decoded from a
-- binary form. This module holds such functions.
module Crypto.WebAuthn.Model.WebIDL.Internal.Binary.Decoding
  ( -- * Decoding from bytes
    decodeAuthenticatorData,
    decodeAttestationObject,
    decodeCollectedClientData,
  )
where

import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import Codec.Serialise (decode)
import Control.Monad (forM, unless)
import Control.Monad.Except (MonadError (throwError))
import Control.Monad.State (MonadState (get, put), StateT (runStateT))
import qualified Crypto.Hash as Hash
import Crypto.WebAuthn.Internal.Utils (jsonEncodingOptions)
import Crypto.WebAuthn.Model.Identifier (AAGUID (AAGUID))
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import Data.Bifunctor (first)
import qualified Data.Binary.Get as Binary
import qualified Data.Bits as Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Base64.URL as Base64Url
import qualified Data.ByteString.Lazy as LBS
import qualified Data.HashMap.Strict as HashMap
import Data.Maybe (fromJust, fromMaybe)
import Data.Singletons (SingI, sing)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.UUID as UUID
import GHC.Generics (Generic)

-- | Webauthn contains a mixture of binary formats. For one it's CBOR and
-- for another it's a custom format. For CBOR we wish to use the
-- [cborg](https://hackage.haskell.org/package/cborg) library
-- and for the custom binary format the [binary](https://hackage.haskell.org/package/binary)
-- library. However these two libraries don't interact nicely with each other.
-- Because of this we are specifying the decoders as a 'PartialBinaryDecoder DecodingError',
-- which is just a function that can partially consume a 'LBS.ByteString'.
-- Using this we can somewhat easily flip between the two libraries while
-- decoding without too much nastiness.
type PartialBinaryDecoder a = StateT LBS.ByteString (Either Text) a

-- | Runs a 'PartialBinaryDecoder' using a strict bytestring. Afterwards it
-- makes sure that no bytes are left, otherwise returns an error
runPartialBinaryDecoder :: BS.ByteString -> PartialBinaryDecoder a -> Either Text a
runPartialBinaryDecoder bytes decoder = case runStateT decoder . LBS.fromStrict $ bytes of
  Left err -> Left err
  Right (result, rest)
    | LBS.null rest -> return result
    | otherwise -> Left $ "Not all binary input used, rest in base64 format is: " <> Text.decodeUtf8 (Base64.encode $ LBS.toStrict rest)

-- | A 'PartialBinaryDecoder DecodingError' for a binary encoding specified using 'Binary.Get'
runBinary :: Binary.Get a -> PartialBinaryDecoder a
runBinary decoder = do
  bytes <- get
  case Binary.runGetOrFail decoder bytes of
    Left (_rest, _offset, err) ->
      throwError $ "Binary decoding error: " <> Text.pack err
    Right (rest, _offset, result) -> do
      put rest
      pure result

-- | A 'PartialBinaryDecoder DecodingError' for a CBOR encoding specified using the given Decoder
runCBOR :: (forall s. CBOR.Decoder s a) -> PartialBinaryDecoder (LBS.ByteString, a)
runCBOR decoder = do
  bytes <- get
  case CBOR.deserialiseFromBytesWithSize decoder bytes of
    Left err ->
      throwError $ "CBOR decoding error: " <> Text.pack (show err)
    Right (rest, consumed, a) -> do
      put rest
      pure (LBS.take (fromIntegral consumed) bytes, a)

-- | Decodes a 'M.AuthenticatorData' from a 'BS.ByteString'.
-- This is needed to parse a webauthn clients
-- [authenticatorData](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata)
-- field in the [AuthenticatorAssertionResponse](https://www.w3.org/TR/webauthn-2/#iface-authenticatorassertionresponse)
-- structure
decodeAuthenticatorData ::
  forall c.
  SingI c =>
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
    -- For [attestation signatures](https://www.w3.org/TR/webauthn-2/#attestation-signature),
    -- the authenticator MUST set the AT [flag](https://www.w3.org/TR/webauthn-2/#flags)
    -- and include the `[attestedCredentialData](https://www.w3.org/TR/webauthn-2/#attestedcredentialdata)`.
    (K.SRegistration, True) -> decodeAttestedCredentialData
    (K.SRegistration, False) -> throwError "Expected attested credential data, but there is none"
    -- For [assertion signatures](https://www.w3.org/TR/webauthn-2/#assertion-signature),
    -- the AT [flag](https://www.w3.org/TR/webauthn-2/#flags) MUST NOT be set and the
    -- `[attestedCredentialData](https://www.w3.org/TR/webauthn-2/#attestedcredentialdata)` MUST NOT be included.
    (K.SAuthentication, False) -> pure M.NoAttestedCredentialData
    (K.SAuthentication, True) -> throwError "Expected no attested credential data, but there is"

  -- https://www.w3.org/TR/webauthn-2/#authdataextensions
  adExtensions <-
    if Bits.testBit bitFlags 7
      then Just <$> decodeExtensions
      else pure Nothing

  pure M.AuthenticatorData {..}
  where
    decodeAttestedCredentialData :: PartialBinaryDecoder (M.AttestedCredentialData 'K.Registration 'True)
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

    decodeExtensions :: PartialBinaryDecoder M.AuthenticatorExtensionOutputs
    decodeExtensions = do
      -- TODO: Extensions are not implemented by this library, see the TODO in the
      -- module documentation of `Crypto.WebAuthn.Model` for more information.
      (_, _extensions :: CBOR.Term) <- runCBOR CBOR.decodeTerm
      pure M.AuthenticatorExtensionOutputs {}

-- | Decodes a 'M.AttestationObject' from a 'BS.ByteString'.
-- This is needed to parse a webauthn clients
-- [attestationObject](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject)
-- field in the [AuthenticatorAttestationResponse](https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse)
-- structure This function takes a 'M.SupportedAttestationStatementFormats'
-- argument to indicate which attestation statement formats are supported.
-- structure
decodeAttestationObject :: M.SupportedAttestationStatementFormats -> BS.ByteString -> Either Text (M.AttestationObject 'True)
decodeAttestationObject supportedFormats bytes = do
  (_consumed, result) <- runPartialBinaryDecoder bytes (runCBOR CBOR.decodeTerm)
  pairs <- case result of
    CBOR.TMap pairs -> return pairs
    _ -> Left $ "The attestation object should be a CBOR map, but it's not: " <> Text.pack (show result)

  -- https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object
  case (CBOR.TString "authData" `lookup` pairs, CBOR.TString "fmt" `lookup` pairs, CBOR.TString "attStmt" `lookup` pairs) of
    (Just (CBOR.TBytes authDataBytes), Just (CBOR.TString fmt), Just (CBOR.TMap attStmtPairs)) -> do
      aoAuthData <- decodeAuthenticatorData authDataBytes

      case M.lookupAttestationStatementFormat fmt supportedFormats of
        Nothing -> Left $ "Unknown attestation statement format: " <> fmt
        Just (M.SomeAttestationStatementFormat aoFmt) -> do
          attStmtMap <-
            HashMap.fromList
              <$> forM
                attStmtPairs
                ( \case
                    (CBOR.TString text, term) -> pure (text, term)
                    (nonString, _) -> Left $ "Unexpected non-string attestation statement key: " <> Text.pack (show nonString)
                )
          aoAttStmt <- M.asfDecode aoFmt attStmtMap
          pure M.AttestationObject {..}
    _ -> Left $ "The attestation object doesn't have the expected structure of (authData: bytes, fmt: string, attStmt: map): " <> Text.pack (show result)

--- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
--- Intermediate type used to extract the JSON structure stored in the
--- CBOR-encoded [clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson).
data ClientDataJSON = ClientDataJSON
  { littype :: IDL.DOMString,
    challenge :: IDL.DOMString,
    origin :: IDL.DOMString,
    crossOrigin :: Maybe IDL.Boolean
    -- TODO: We do not implement TokenBinding, see the documentation of
    -- `CollectedClientData` for more information.
    -- tokenBinding :: Maybe TokenBinding
  }
  deriving (Generic)

-- Note: Encoding should NOT be derived via aeson. See the Encoding module instead
instance Aeson.FromJSON ClientDataJSON where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

-- | Decodes a 'M.CollectedClientData' from a 'BS.ByteString'. This is needed
-- to parse the [clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
-- field in the [AuthenticatorResponse](https://www.w3.org/TR/webauthn-2/#iface-authenticatorresponse)
-- structure, which is used for both attestation and assertion
decodeCollectedClientData :: forall c. SingI c => BS.ByteString -> Either Text (M.CollectedClientData c 'True)
decodeCollectedClientData bytes = do
  -- https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data
  ClientDataJSON {..} <-
    first (("Collected client data JSON decoding error: " <>) . Text.pack) $
      Aeson.eitherDecodeStrict bytes
  -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-challenge)
  -- This member contains the base64url encoding of the challenge provided by the
  -- [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party). See the
  -- [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
  -- security consideration.
  challenge <-
    first ((("Failed to base64url-decode challenge " <> challenge <> ": ") <>) . Text.pack) $
      Base64Url.decode (Text.encodeUtf8 challenge)
  -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type)
  -- This member contains the string "webauthn.create" when creating new credentials,
  -- and "webauthn.get" when getting an assertion from an existing credential.
  -- The purpose of this member is to prevent certain types of signature confusion
  -- attacks (where an attacker substitutes one legitimate signature for another).
  let expectedType = case sing @c of
        K.SRegistration -> "webauthn.create"
        K.SAuthentication -> "webauthn.get"
  unless (littype == expectedType) $
    Left $
      "Expected collected client data to have webauthn type " <> expectedType <> " but it is " <> littype
  pure
    M.CollectedClientData
      { ccdChallenge = M.Challenge challenge,
        ccdOrigin = M.Origin origin,
        ccdCrossOrigin = fromMaybe False crossOrigin,
        ccdRawData = M.WithRaw bytes
      }
