{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Model.JavaScript.Decoding
  ( SomeAttestationStatementFormat (..),
    DecodingAttestationStatementFormat (..),
    SupportedFormats,
    mkSupportedFormats,
    decodeCreatedPublicKeyCredential,
    decodeRequestedPublicKeyCredential,
    DecodingError (..),
    CreatedDecodingError (..),
    RequestedDecodingError (..),
  )
where

import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.Serialise as CBOR
import Control.Exception (Exception, SomeException (SomeException))
import Control.Monad (forM, unless)
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import Crypto.Fido2.Model.JavaScript.Types (Convert (JS))
import Crypto.Fido2.Model.WebauthnType (SWebauthnType (SCreate, SGet), SingI (sing))
import qualified Crypto.Hash as Hash
import qualified Data.Aeson as Aeson
import Data.Bifunctor (first, second)
import qualified Data.Binary.Get as Binary
import qualified Data.Bits as Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy as LBS
import Data.Coerce (Coercible, coerce)
import Data.HashMap.Strict (HashMap, (!?))
import qualified Data.HashMap.Strict as HashMap
import Data.Kind (Type)
import Data.Maybe (fromJust)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import qualified Deriving.Aeson as Aeson
import GHC.Generics (Generic)

data DecodingError
  = DecodingErrorClientDataJSON String
  | DecodingErrorClientDataChallenge String
  | DecodingErrorUnexpectedWebauthnType JS.DOMString JS.DOMString
  | DecodingErrorExpectedAttestedCredentialData
  | DecodingErrorUnexpectedAttestedCredentialData
  | DecodingErrorNotAllInputUsed LBS.ByteString
  | DecodingErrorBinary String
  | DecodingErrorCBOR CBOR.DeserialiseFailure
  deriving (Show, Exception)

data CreatedDecodingError
  = CreatedDecodingErrorCommon DecodingError
  | CreatedDecodingErrorCBOR CBOR.DeserialiseFailure
  | CreatedDecodingErrorUnknownAttestationStatementFormat Text
  | CreatedDecodingErrorUnexpectedAttestationStatementKey CBOR.Term
  | CreatedDecodingErrorAttestationStatement SomeException
  | CreatedDecodingErrorUnexpectedAttestationObjectValues (Maybe CBOR.Term, Maybe CBOR.Term, Maybe CBOR.Term)
  deriving (Show, Exception)

newtype RequestedDecodingError = RequestedDecodingErrorCommon DecodingError

decodeCreatedPublicKeyCredential ::
  SupportedFormats ->
  JS.CreatedPublicKeyCredential ->
  Either CreatedDecodingError (M.PublicKeyCredential 'M.Create)
decodeCreatedPublicKeyCredential = decodeCreated

decodeRequestedPublicKeyCredential ::
  JS.RequestedPublicKeyCredential ->
  Either RequestedDecodingError (M.PublicKeyCredential 'M.Get)
decodeRequestedPublicKeyCredential = decodeRequested

class Convert a => Decode a where
  decode :: JS a -> Either DecodingError a
  default decode :: Coercible (JS a) a => JS a -> Either DecodingError a
  decode = pure . coerce

-- | @'Decode' hs@ indicates that the Haskell-specific type @hs@ can be
-- decoded from the more generic JavaScript type @'JS' hs@ with the 'decode' function.
class Convert a => DecodeRequested a where
  decodeRequested :: JS a -> Either RequestedDecodingError a

-- | @'Decode' hs@ indicates that the Haskell-specific type @hs@ can be
-- decoded from the more generic JavaScript type @'JS' hs@ with the 'decode' function.
class Convert a => DecodeCreated a where
  decodeCreated :: SupportedFormats -> JS a -> Either CreatedDecodingError a

instance Decode a => Decode (Maybe a) where
  decode Nothing = pure Nothing
  decode (Just a) = Just <$> decode a

instance Decode M.CredentialId

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
-- Intermediate type used to extract the JSON structure stored in the
-- CBOR-encoded [clientDataJSON](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson).
data ClientDataJSON = ClientDataJSON
  { typ :: JS.DOMString,
    challenge :: JS.DOMString,
    origin :: JS.DOMString,
    crossOrigin :: Maybe Bool
    -- TODO
    -- tokenBinding :: Maybe TokenBinding
  }
  deriving (Show, Eq, Generic)
  -- Note: Encoding can NOT be derived automatically, and most likely not even
  -- be provided correctly with the Aeson.ToJSON class, because it is only a
  -- JSON-_compatible_ encoding, but it also contains some extra structure
  -- allowing for verification without a full JSON parser
  -- See <https://www.w3.org/TR/webauthn-2/#clientdatajson-serialization>
  deriving (Aeson.FromJSON) via Aeson.CustomJSON '[Aeson.OmitNothingFields, Aeson.FieldLabelModifier (Aeson.Rename "typ" "type")] ClientDataJSON

instance SingI t => Decode (M.CollectedClientData t) where
  decode (JS.URLEncodedBase64 bytes) = do
    -- https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data
    ClientDataJSON {..} <- first DecodingErrorClientDataJSON $ Aeson.eitherDecodeStrict bytes
    -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-challenge)
    -- This member contains the base64url encoding of the challenge provided by the
    -- [Relying Party](https://www.w3.org/TR/webauthn-2/#relying-party). See the
    -- [§ 13.4.3 Cryptographic Challenges](https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges)
    -- security consideration.
    challenge <- first DecodingErrorClientDataChallenge $ Base64.decode (Text.encodeUtf8 challenge)
    -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type)
    -- This member contains the string "webauthn.create" when creating new credentials,
    -- and "webauthn.get" when getting an assertion from an existing credential.
    -- The purpose of this member is to prevent certain types of signature confusion
    -- attacks (where an attacker substitutes one legitimate signature for another).

    let expectedType = case sing @t of
          SCreate -> "webauthn.create"
          SGet -> "webauthn.get"
    unless (typ == expectedType) $ Left (DecodingErrorUnexpectedWebauthnType expectedType typ)
    pure
      M.CollectedClientData
        { ccdChallenge = M.Challenge challenge,
          ccdOrigin = M.Origin origin,
          ccdCrossOrigin = crossOrigin,
          ccdHash = M.ClientDataHash $ Hash.hash bytes
        }

instance DecodeCreated M.AttestationObject where
  decodeCreated attestationStatementFormatMap (JS.URLEncodedBase64 bytes) = decodeAttestationObject attestationStatementFormatMap (LBS.fromStrict bytes)

instance DecodeCreated (M.AuthenticatorResponse 'M.Create) where
  decodeCreated attestationStatementFormatMap JS.AuthenticatorAttestationResponse {..} = do
    arcClientData <- first CreatedDecodingErrorCommon $ decode clientDataJSON
    arcAttestationObject <- decodeCreated attestationStatementFormatMap attestationObject
    -- TODO
    let arcTransports = Set.empty
    pure $ M.AuthenticatorAttestationResponse {..}

instance Decode (M.AuthenticatorData 'M.Get) where
  decode (JS.URLEncodedBase64 bytes) = decodeAuthenticatorData bytes

instance Decode M.AssertionSignature

instance Decode M.UserHandle

instance Decode (M.AuthenticatorResponse 'M.Get) where
  decode JS.AuthenticatorAssertionResponse {..} = do
    argClientData <- decode clientDataJSON
    argAuthenticatorData <- decode authenticatorData
    argSignature <- decode signature
    argUserHandle <- decode userHandle
    pure $ M.AuthenticatorAssertionResponse {..}

instance Decode M.AuthenticationExtensionsClientOutputs where
  -- TODO: Implement extension support
  decode _ = pure M.AuthenticationExtensionsClientOutputs {}

instance DecodeCreated (M.PublicKeyCredential 'M.Create) where
  decodeCreated attestationStatementFormatMap JS.PublicKeyCredential {..} = do
    pkcIdentifier <- first CreatedDecodingErrorCommon $ decode rawId
    pkcResponse <- decodeCreated attestationStatementFormatMap response
    pkcClientExtensionResults <- first CreatedDecodingErrorCommon $ decode clientExtensionResults
    pure $ M.PublicKeyCredential {..}

instance Decode (M.PublicKeyCredential 'M.Get) where
  decode JS.PublicKeyCredential {..} = do
    pkcIdentifier <- decode rawId
    pkcResponse <- decode response
    pkcClientExtensionResults <- decode clientExtensionResults
    pure $ M.PublicKeyCredential {..}

instance DecodeRequested (M.PublicKeyCredential 'M.Get) where
  decodeRequested js = first RequestedDecodingErrorCommon $ decode js

-- * Binary formats

-- | Webauthn contains a mixture of binary formats. For one it's CBOR and
-- for another it's a custom format. For CBOR we wish to use the cborg library
-- and for the custom binary format the binary library. However these two
-- libraries don't interact nicely with each other. Because of this we are
-- specifying the decoders as a 'PartialBinaryDecoder', which is just a
-- function that can partially consume a 'LBS.ByteString'. Using this we can
-- somewhat easily flip between the two libraries while decoding without too
-- much nastiness.
type PartialBinaryDecoder a = LBS.ByteString -> Either DecodingError (LBS.ByteString, a)

mkSupportedFormats :: [SomeAttestationStatementFormat] -> SupportedFormats
mkSupportedFormats formats =
  SupportedFormats (HashMap.fromList (map withIdentifier formats))
  where
    withIdentifier someFormat@(SomeAttestationStatementFormat format) =
      (M.attestationStatementFormatIdentifier format, someFormat)

class
  ( M.AttestationStatementFormat a,
    Exception (AttStmtDecodingError a)
  ) =>
  DecodingAttestationStatementFormat a
  where
  type AttStmtDecodingError a :: Type

  attestationStatementFormatDecode ::
    a ->
    HashMap Text CBOR.Term ->
    Either (AttStmtDecodingError a) (M.AttStmt a)

data SomeAttestationStatementFormat
  = forall a.
    DecodingAttestationStatementFormat a =>
    SomeAttestationStatementFormat a

newtype SupportedFormats = SupportedFormats (HashMap Text SomeAttestationStatementFormat)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
decodeAttestationObject :: SupportedFormats -> LBS.ByteString -> Either CreatedDecodingError M.AttestationObject
decodeAttestationObject (SupportedFormats formats) bytes = do
  map :: HashMap Text CBOR.Term <- first CreatedDecodingErrorCBOR $ CBOR.deserialiseOrFail bytes
  case (map !? "authData", map !? "fmt", map !? "attStmt") of
    (Just (CBOR.TBytes authDataBytes), Just (CBOR.TString fmt), Just (CBOR.TMap attStmtPairs)) -> do
      aoAuthData <- first CreatedDecodingErrorCommon $ decodeAuthenticatorData authDataBytes

      case formats !? fmt of
        Nothing -> Left $ CreatedDecodingErrorUnknownAttestationStatementFormat fmt
        Just (SomeAttestationStatementFormat aoFmt) -> do
          attStmtMap <-
            HashMap.fromList <$> forM attStmtPairs \case
              (CBOR.TString text, term) -> pure (text, term)
              (nonString, _) -> Left $ CreatedDecodingErrorUnexpectedAttestationStatementKey nonString
          aoAttStmt <-
            first (CreatedDecodingErrorAttestationStatement . SomeException) $
              attestationStatementFormatDecode aoFmt attStmtMap
          pure $ M.AttestationObject {..}
    terms -> Left $ CreatedDecodingErrorUnexpectedAttestationObjectValues terms

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticator-data)
decodeAuthenticatorData ::
  forall t.
  SingI t =>
  BS.ByteString ->
  Either DecodingError (M.AuthenticatorData t)
decodeAuthenticatorData adRawData = do
  let bytes = LBS.fromStrict adRawData
  -- https://www.w3.org/TR/webauthn-2/#rpidhash
  (bytes, adRpIdHash) <-
    second (M.RpIdHash . fromJust . Hash.digestFromByteString)
      <$> runBinary (Binary.getByteString 32) bytes

  -- https://www.w3.org/TR/webauthn-2/#flags
  (bytes, bitFlags) <-
    runBinary Binary.getWord8 bytes
  let adFlags =
        M.AuthenticatorDataFlags
          { adfUserPresent = Bits.testBit bitFlags 0,
            adfUserVerified = Bits.testBit bitFlags 2
          }

  -- https://www.w3.org/TR/webauthn-2/#signcount
  (bytes, adSignCount) <-
    runBinary Binary.getWord32be bytes

  -- https://www.w3.org/TR/webauthn-2/#attestedcredentialdata
  (bytes, adAttestedCredentialData) <- case (sing @t, Bits.testBit bitFlags 6) of
    -- For [attestation signatures](https://www.w3.org/TR/webauthn-2/#attestation-signature),
    -- the authenticator MUST set the AT [flag](https://www.w3.org/TR/webauthn-2/#flags)
    -- and include the `[attestedCredentialData](https://www.w3.org/TR/webauthn-2/#attestedcredentialdata)`.
    (SCreate, True) -> decodeAttestedCredentialData bytes
    (SCreate, False) -> Left DecodingErrorExpectedAttestedCredentialData
    -- For [assertion signatures](https://www.w3.org/TR/webauthn-2/#assertion-signature),
    -- the AT [flag](https://www.w3.org/TR/webauthn-2/#flags) MUST NOT be set and the
    -- `[attestedCredentialData](https://www.w3.org/TR/webauthn-2/#attestedcredentialdata)` MUST NOT be included.
    (SGet, False) -> pure (bytes, M.NoAttestedCredentialData)
    (SGet, True) -> Left DecodingErrorUnexpectedAttestedCredentialData

  -- https://www.w3.org/TR/webauthn-2/#authdataextensions
  (bytes, adExtensions) <-
    if Bits.testBit bitFlags 7
      then fmap Just <$> decodeExtensions bytes
      else pure (bytes, Nothing)

  if LBS.null bytes
    then pure M.AuthenticatorData {..}
    else Left $ DecodingErrorNotAllInputUsed bytes

decodeAttestedCredentialData :: PartialBinaryDecoder (M.AttestedCredentialData 'M.Create)
decodeAttestedCredentialData bytes = do
  -- https://www.w3.org/TR/webauthn-2/#aaguid
  (bytes, acdAaguid) <-
    second M.AAGUID
      <$> runBinary (Binary.getByteString 16) bytes

  -- https://www.w3.org/TR/webauthn-2/#credentialidlength
  (bytes, credentialLength) <-
    runBinary Binary.getWord16be bytes

  -- https://www.w3.org/TR/webauthn-2/#credentialid
  (bytes, acdCredentialId) <-
    second M.CredentialId
      <$> runBinary (Binary.getByteString (fromIntegral credentialLength)) bytes

  -- https://www.w3.org/TR/webauthn-2/#credentialpublickey
  (bytes, acdCredentialPublicKey) <-
    runCBOR bytes

  pure (bytes, M.AttestedCredentialData {..})

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authdataextensions)
decodeExtensions :: PartialBinaryDecoder M.AuthenticatorExtensionOutputs
decodeExtensions bytes = do
  -- TODO
  (bytes, _extensions :: HashMap Text CBOR.Term) <- runCBOR bytes
  pure (bytes, M.AuthenticatorExtensionOutputs {})

-- ** Utils

runBinary :: Binary.Get a -> PartialBinaryDecoder a
runBinary get bytes = case Binary.runGetOrFail get bytes of
  Left (_rest, _offset, err) -> Left $ DecodingErrorBinary err
  Right (rest, _offset, result) -> Right (rest, result)

runCBOR :: CBOR.Serialise a => PartialBinaryDecoder a
runCBOR bytes = first DecodingErrorCBOR $ CBOR.deserialiseFromBytes CBOR.decode bytes
