{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Client.Conversion
  ( encodePublicKeyCredentialCreationOptions,
    encodePublicKeyCredentialRequestOptions,
    decodeCreatedPublicKeyCredential,
    decodeRequestedPublicKeyCredential,
    DecodingError (..),
    CreatedDecodingError (..),
    RequestedDecodingError (..),
    SupportedFormats,
    mkSupportedFormats,
    DecodingAttestationStatementFormat (..),
    SomeAttestationStatementFormat (..),
  )
where

import qualified Codec.CBOR.Read as CBOR
import Codec.CBOR.Term (Term (TBytes, TMap, TString))
import qualified Codec.CBOR.Term as CBOR
import Codec.Serialise (DeserialiseFailure, Serialise)
import qualified Codec.Serialise as Serialise
import Control.Exception (Exception, SomeException (SomeException))
import Control.Monad (forM, unless)
import qualified Crypto.Fido2.Client.Haskell as HS
import qualified Crypto.Fido2.Client.JavaScript as JS
import Crypto.Fido2.Client.WebauthnType (SWebauthnType (SCreate, SGet), SingI, sing)
import qualified Crypto.Hash as Hash
import qualified Data.Aeson as Aeson
import Data.Bifunctor (Bifunctor (second), first)
import qualified Data.Binary.Get as Binary
import qualified Data.Bits as Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Lazy as LBS
import Data.Coerce (Coercible, coerce)
import Data.HashMap.Strict (HashMap, (!?))
import qualified Data.HashMap.Strict as HashMap
import Data.Kind (Type)
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Deriving.Aeson (CustomJSON (CustomJSON), FieldLabelModifier, OmitNothingFields, Rename)
import GHC.Generics (Generic)

encodePublicKeyCredentialCreationOptions ::
  HS.PublicKeyCredentialOptions 'HS.Create ->
  JS.PublicKeyCredentialCreationOptions
encodePublicKeyCredentialCreationOptions = encode

encodePublicKeyCredentialRequestOptions ::
  HS.PublicKeyCredentialOptions 'HS.Get ->
  JS.PublicKeyCredentialRequestOptions
encodePublicKeyCredentialRequestOptions = encode

data DecodingError
  = DecodingErrorClientDataJSON String
  | DecodingErrorClientDataChallenge String
  | DecodingErrorUnexpectedWebauthnType JS.DOMString JS.DOMString
  | DecodingErrorExpectedAttestedCredentialData
  | DecodingErrorUnexpectedAttestedCredentialData
  | DecodingErrorNotAllInputUsed LBS.ByteString
  | DecodingErrorBinary String
  | DecodingErrorCBOR DeserialiseFailure
  deriving (Show, Exception)

data CreatedDecodingError
  = CreatedDecodingErrorCommon DecodingError
  | CreatedDecodingErrorCBOR DeserialiseFailure
  | CreatedDecodingErrorUnknownAttestationStatementFormat Text
  | CreatedDecodingErrorUnexpectedAttestationStatementKey Term
  | CreatedDecodingErrorAttestationStatement SomeException
  | CreatedDecodingErrorUnexpectedAttestationObjectValues (Maybe Term, Maybe Term, Maybe Term)
  deriving (Show, Exception)

newtype RequestedDecodingError = RequestedDecodingErrorCommon DecodingError

decodeCreatedPublicKeyCredential ::
  SupportedFormats ->
  JS.CreatedPublicKeyCredential ->
  Either CreatedDecodingError (HS.PublicKeyCredential 'HS.Create)
decodeCreatedPublicKeyCredential = decodeCreated

decodeRequestedPublicKeyCredential ::
  JS.RequestedPublicKeyCredential ->
  Either RequestedDecodingError (HS.PublicKeyCredential 'HS.Get)
decodeRequestedPublicKeyCredential = decodeRequested

-- | @'Convert' hs@ indicates that the Haskell-specific type @hs@ has a more
-- general JavaScript-specific type associated with it, which can be accessed with 'JS'.
class Convert hs where
  type JS hs :: *

instance Convert hs => Convert (Maybe hs) where
  type JS (Maybe hs) = Maybe (JS hs)

instance Convert a => Convert [a] where
  type JS [a] = [JS a]

instance Convert HS.RpId where
  type JS HS.RpId = JS.DOMString

instance Convert HS.RelyingPartyName where
  type JS HS.RelyingPartyName = JS.DOMString

instance Convert HS.PublicKeyCredentialRpEntity where
  type JS HS.PublicKeyCredentialRpEntity = JS.PublicKeyCredentialRpEntity

instance Convert HS.UserHandle where
  type JS HS.UserHandle = JS.BufferSource

instance Convert HS.UserAccountDisplayName where
  type JS HS.UserAccountDisplayName = JS.DOMString

instance Convert HS.UserAccountName where
  type JS HS.UserAccountName = JS.DOMString

instance Convert HS.PublicKeyCredentialUserEntity where
  type JS HS.PublicKeyCredentialUserEntity = JS.PublicKeyCredentialUserEntity

instance Convert HS.Challenge where
  type JS HS.Challenge = JS.BufferSource

instance Convert HS.PublicKeyCredentialType where
  type JS HS.PublicKeyCredentialType = JS.DOMString

instance Convert HS.COSEAlgorithmIdentifier where
  type JS HS.COSEAlgorithmIdentifier = JS.COSEAlgorithmIdentifier

instance Convert HS.PublicKeyCredentialParameters where
  type JS HS.PublicKeyCredentialParameters = JS.PublicKeyCredentialParameters

instance Convert HS.Timeout where
  type JS HS.Timeout = JS.UnsignedLong

instance Convert HS.CredentialId where
  type JS HS.CredentialId = JS.BufferSource

instance Convert HS.AuthenticatorTransport where
  type JS HS.AuthenticatorTransport = JS.DOMString

instance Convert HS.PublicKeyCredentialDescriptor where
  type JS HS.PublicKeyCredentialDescriptor = JS.PublicKeyCredentialDescriptor

instance Convert HS.AuthenticatorAttachment where
  type JS HS.AuthenticatorAttachment = JS.DOMString

instance Convert HS.ResidentKeyRequirement where
  type JS HS.ResidentKeyRequirement = JS.DOMString

instance Convert HS.UserVerificationRequirement where
  type JS HS.UserVerificationRequirement = JS.DOMString

instance Convert HS.AuthenticatorSelectionCriteria where
  type JS HS.AuthenticatorSelectionCriteria = JS.AuthenticatorSelectionCriteria

instance Convert HS.AttestationConveyancePreference where
  type JS HS.AttestationConveyancePreference = JS.DOMString

instance Convert HS.AuthenticationExtensionsClientInputs where
  type JS HS.AuthenticationExtensionsClientInputs = Map Text Aeson.Value

instance Convert (HS.PublicKeyCredentialOptions 'HS.Create) where
  type JS (HS.PublicKeyCredentialOptions 'HS.Create) = JS.PublicKeyCredentialCreationOptions

instance Convert (HS.PublicKeyCredentialOptions 'HS.Get) where
  type JS (HS.PublicKeyCredentialOptions 'HS.Get) = JS.PublicKeyCredentialRequestOptions

instance Convert (HS.PublicKeyCredential 'HS.Create) where
  type JS (HS.PublicKeyCredential 'HS.Create) = JS.PublicKeyCredential JS.AuthenticatorAttestationResponse

instance Convert (HS.AuthenticatorResponse 'HS.Create) where
  type JS (HS.AuthenticatorResponse 'HS.Create) = JS.AuthenticatorAttestationResponse

instance Convert (HS.PublicKeyCredential 'HS.Get) where
  type JS (HS.PublicKeyCredential 'HS.Get) = JS.PublicKeyCredential JS.AuthenticatorAssertionResponse

instance Convert (HS.AuthenticatorResponse 'HS.Get) where
  type JS (HS.AuthenticatorResponse 'HS.Get) = JS.AuthenticatorAssertionResponse

instance Convert HS.AuthenticationExtensionsClientOutputs where
  type JS HS.AuthenticationExtensionsClientOutputs = Map Text Aeson.Value

instance Convert (HS.CollectedClientData t) where
  type JS (HS.CollectedClientData t) = JS.ArrayBuffer

instance Convert HS.AttestationObject where
  type JS HS.AttestationObject = JS.ArrayBuffer

instance Convert HS.AssertionSignature where
  type JS HS.AssertionSignature = JS.ArrayBuffer

instance Convert (HS.AuthenticatorData 'HS.Get) where
  type JS (HS.AuthenticatorData 'HS.Get) = JS.ArrayBuffer

-- | @'Encode' hs@ indicates that the Haskell-specific type @hs@ can be
-- encoded to the more generic JavaScript type @'JS' hs@ with the 'encode' function.
class Encode hs where
  encode :: hs -> JS hs
  default encode :: Coercible hs (JS hs) => hs -> JS hs
  encode = coerce

instance Encode HS.RpId

instance Encode HS.RelyingPartyName

instance Encode HS.UserHandle

instance Encode HS.UserAccountDisplayName

instance Encode HS.UserAccountName

instance Encode HS.Challenge

instance Encode HS.Timeout

instance Encode HS.CredentialId

instance Encode hs => Encode (Maybe hs) where
  encode Nothing = Nothing
  encode (Just hs) = Just $ encode hs

instance Encode a => Encode [a] where
  encode = fmap encode

instance Encode HS.PublicKeyCredentialRpEntity where
  encode HS.PublicKeyCredentialRpEntity {..} =
    JS.PublicKeyCredentialRpEntity
      { id = encode pkcreId,
        name = encode pkcreName
      }

instance Encode HS.PublicKeyCredentialUserEntity where
  encode HS.PublicKeyCredentialUserEntity {..} =
    JS.PublicKeyCredentialUserEntity
      { id = encode pkcueId,
        displayName = encode pkcueDisplayName,
        name = encode pkcueName
      }

instance Encode HS.PublicKeyCredentialParameters where
  encode HS.PublicKeyCredentialParameters {..} =
    JS.PublicKeyCredentialParameters
      { typ = encode pkcpTyp,
        alg = encode pkcpAlg
      }

instance Encode HS.PublicKeyCredentialDescriptor where
  encode HS.PublicKeyCredentialDescriptor {..} =
    JS.PublicKeyCredentialDescriptor
      { typ = encode pkcdTyp,
        id = encode pkcdId,
        transports = encode pkcdTransports
      }

instance Encode HS.AuthenticatorSelectionCriteria where
  encode HS.AuthenticatorSelectionCriteria {..} =
    JS.AuthenticatorSelectionCriteria
      { authenticatorAttachment = encode ascAuthenticatorAttachment,
        residentKey = Just $ encode ascResidentKey,
        -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
        -- Relying Parties SHOULD set it to true if, and only if, residentKey is set to required.
        requireResidentKey = Just (ascResidentKey == HS.ResidentKeyRequirementRequired),
        userVerification = Just $ encode ascUserVerification
      }

instance Encode (HS.PublicKeyCredentialOptions 'HS.Create) where
  encode HS.PublicKeyCredentialCreationOptions {..} =
    JS.PublicKeyCredentialCreationOptions
      { rp = encode pkcocRp,
        user = encode pkcocUser,
        challenge = encode pkcocChallenge,
        pubKeyCredParams = encode pkcocPubKeyCredParams,
        timeout = encode pkcocTimeout,
        excludeCredentials = Just $ encode pkcocExcludeCredentials,
        authenticatorSelection = encode pkcocAuthenticatorSelection,
        attestation = Just $ encode pkcocAttestation,
        extensions = encode pkcocExtensions
      }

instance Encode (HS.PublicKeyCredentialOptions 'HS.Get) where
  encode HS.PublicKeyCredentialRequestOptions {..} =
    JS.PublicKeyCredentialRequestOptions
      { challenge = encode pkcogChallenge,
        timeout = encode pkcogTimeout,
        rpId = encode pkcogRpId,
        allowCredentials = Just $ encode pkcogAllowCredentials,
        userVerification = Just $ encode pkcogUserVerification,
        extensions = Just $ encode pkcogExtensions
      }

instance Encode HS.AuthenticationExtensionsClientInputs where
  -- TODO: Implement extension support
  encode HS.AuthenticationExtensionsClientInputs {} = Map.empty

-- | <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
instance Encode HS.COSEAlgorithmIdentifier where
  encode HS.COSEAlgorithmIdentifierES512 = -36
  encode HS.COSEAlgorithmIdentifierES384 = -35
  encode HS.COSEAlgorithmIdentifierEdDSA = -8
  encode HS.COSEAlgorithmIdentifierES256 = -7

-- | <https://www.w3.org/TR/webauthn-2/#enum-credentialType>
instance Encode HS.PublicKeyCredentialType where
  encode HS.PublicKeyCredentialTypePublicKey = "public-key"

-- | <https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport>
instance Encode HS.AuthenticatorTransport where
  encode HS.AuthenticatorTransportUSB = "usb"
  encode HS.AuthenticatorTransportNFC = "nfc"
  encode HS.AuthenticatorTransportBLE = "ble"
  encode HS.AuthenticatorTransportInternal = "internal"

-- | <https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment>
instance Encode HS.AuthenticatorAttachment where
  encode HS.AuthenticatorAttachmentPlatform = "platform"
  encode HS.AuthenticatorAttachmentCrossPlatform = "cross-platform"

-- | <https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement>
instance Encode HS.ResidentKeyRequirement where
  encode HS.ResidentKeyRequirementDiscouraged = "discouraged"
  encode HS.ResidentKeyRequirementPreferred = "preferred"
  encode HS.ResidentKeyRequirementRequired = "required"

-- | <https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement>
instance Encode HS.UserVerificationRequirement where
  encode HS.UserVerificationRequirementRequired = "required"
  encode HS.UserVerificationRequirementPreferred = "preferred"
  encode HS.UserVerificationRequirementDiscouraged = "discouraged"

-- | <https://www.w3.org/TR/webauthn-2/#enum-attestation-convey>
instance Encode HS.AttestationConveyancePreference where
  encode HS.AttestationConveyancePreferenceNone = "none"
  encode HS.AttestationConveyancePreferenceIndirect = "indirect"
  encode HS.AttestationConveyancePreferenceDirect = "direct"
  encode HS.AttestationConveyancePreferenceEnterprise = "enterprise"

class Decode hs where
  decode :: JS hs -> Either DecodingError hs
  default decode :: Coercible (JS hs) hs => JS hs -> Either DecodingError hs
  decode = pure . coerce

-- | @'Decode' hs@ indicates that the Haskell-specific type @hs@ can be
-- decoded from the more generic JavaScript type @'JS' hs@ with the 'decode' function.
class DecodeRequested hs where
  decodeRequested :: JS hs -> Either RequestedDecodingError hs

-- | @'Decode' hs@ indicates that the Haskell-specific type @hs@ can be
-- decoded from the more generic JavaScript type @'JS' hs@ with the 'decode' function.
class DecodeCreated hs where
  decodeCreated :: SupportedFormats -> JS hs -> Either CreatedDecodingError hs

instance Decode a => Decode (Maybe a) where
  decode Nothing = pure Nothing
  decode (Just a) = Just <$> decode a

instance Decode HS.CredentialId

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
  deriving (Aeson.FromJSON) via CustomJSON '[OmitNothingFields, FieldLabelModifier (Rename "typ" "type")] ClientDataJSON

instance SingI t => Decode (HS.CollectedClientData t) where
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
      HS.CollectedClientData
        { ccdChallenge = HS.Challenge challenge,
          ccdOrigin = HS.Origin origin,
          ccdCrossOrigin = crossOrigin,
          ccdHash = HS.ClientDataHash $ Hash.hash bytes
        }

instance DecodeCreated HS.AttestationObject where
  decodeCreated attestationStatementFormatMap (JS.URLEncodedBase64 bytes) = decodeAttestationObject attestationStatementFormatMap (LBS.fromStrict bytes)

instance DecodeCreated (HS.AuthenticatorResponse 'HS.Create) where
  decodeCreated attestationStatementFormatMap JS.AuthenticatorAttestationResponse {..} = do
    arcClientData <- first CreatedDecodingErrorCommon $ decode clientDataJSON
    arcAttestationObject <- decodeCreated attestationStatementFormatMap attestationObject
    -- TODO
    let arcTransports = Set.empty
    pure $ HS.AuthenticatorAttestationResponse {..}

instance Decode (HS.AuthenticatorData 'HS.Get) where
  decode (JS.URLEncodedBase64 bytes) = decodeAuthenticatorData bytes

instance Decode HS.AssertionSignature

instance Decode HS.UserHandle

instance Decode (HS.AuthenticatorResponse 'HS.Get) where
  decode JS.AuthenticatorAssertionResponse {..} = do
    argClientData <- decode clientDataJSON
    argAuthenticatorData <- decode authenticatorData
    argSignature <- decode signature
    argUserHandle <- decode userHandle
    pure $ HS.AuthenticatorAssertionResponse {..}

instance Decode HS.AuthenticationExtensionsClientOutputs where
  -- TODO: Implement extension support
  decode _ = pure HS.AuthenticationExtensionsClientOutputs {}

instance DecodeCreated (HS.PublicKeyCredential 'HS.Create) where
  decodeCreated attestationStatementFormatMap JS.PublicKeyCredential {..} = do
    pkcIdentifier <- first CreatedDecodingErrorCommon $ decode rawId
    pkcResponse <- decodeCreated attestationStatementFormatMap response
    pkcClientExtensionResults <- first CreatedDecodingErrorCommon $ decode clientExtensionResults
    pure $ HS.PublicKeyCredential {..}

instance Decode (HS.PublicKeyCredential 'HS.Get) where
  decode JS.PublicKeyCredential {..} = do
    pkcIdentifier <- decode rawId
    pkcResponse <- decode response
    pkcClientExtensionResults <- decode clientExtensionResults
    pure $ HS.PublicKeyCredential {..}

instance DecodeRequested (HS.PublicKeyCredential 'HS.Get) where
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
      (HS.attestationStatementFormatIdentifier format, someFormat)

class
  ( HS.AttestationStatementFormat a,
    Exception (AttStmtDecodingError a)
  ) =>
  DecodingAttestationStatementFormat a
  where
  type AttStmtDecodingError a :: Type

  attestationStatementFormatDecode ::
    a ->
    HashMap Text CBOR.Term ->
    Either (AttStmtDecodingError a) (HS.AttStmt a)

data SomeAttestationStatementFormat
  = forall a.
    DecodingAttestationStatementFormat a =>
    SomeAttestationStatementFormat a

newtype SupportedFormats = SupportedFormats (HashMap Text SomeAttestationStatementFormat)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
decodeAttestationObject :: SupportedFormats -> LBS.ByteString -> Either CreatedDecodingError HS.AttestationObject
decodeAttestationObject (SupportedFormats formats) bytes = do
  map :: HashMap Text Term <- first CreatedDecodingErrorCBOR $ Serialise.deserialiseOrFail bytes
  case (map !? "authData", map !? "fmt", map !? "attStmt") of
    (Just (TBytes authDataBytes), Just (TString fmt), Just (TMap attStmtPairs)) -> do
      aoAuthData <- first CreatedDecodingErrorCommon $ decodeAuthenticatorData authDataBytes

      case formats !? fmt of
        Nothing -> Left $ CreatedDecodingErrorUnknownAttestationStatementFormat fmt
        Just (SomeAttestationStatementFormat aoFmt) -> do
          attStmtMap <-
            HashMap.fromList <$> forM attStmtPairs \case
              (TString text, term) -> pure (text, term)
              (nonString, _) -> Left $ CreatedDecodingErrorUnexpectedAttestationStatementKey nonString
          aoAttStmt <-
            first (CreatedDecodingErrorAttestationStatement . SomeException) $
              attestationStatementFormatDecode aoFmt attStmtMap
          pure $ HS.AttestationObject {..}
    terms -> Left $ CreatedDecodingErrorUnexpectedAttestationObjectValues terms

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticator-data)
decodeAuthenticatorData ::
  forall t.
  SingI t =>
  BS.ByteString ->
  Either DecodingError (HS.AuthenticatorData t)
decodeAuthenticatorData adRawData = do
  let bytes = LBS.fromStrict adRawData
  -- https://www.w3.org/TR/webauthn-2/#rpidhash
  (bytes, adRpIdHash) <-
    second (HS.RpIdHash . fromJust . Hash.digestFromByteString)
      <$> runBinary (Binary.getByteString 32) bytes

  -- https://www.w3.org/TR/webauthn-2/#flags
  (bytes, bitFlags) <-
    runBinary Binary.getWord8 bytes
  let adFlags =
        HS.AuthenticatorDataFlags
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
    (SGet, False) -> pure (bytes, HS.NoAttestedCredentialData)
    (SGet, True) -> Left DecodingErrorUnexpectedAttestedCredentialData

  -- https://www.w3.org/TR/webauthn-2/#authdataextensions
  (bytes, adExtensions) <-
    if Bits.testBit bitFlags 7
      then fmap Just <$> decodeExtensions bytes
      else pure (bytes, Nothing)

  if LBS.null bytes
    then pure HS.AuthenticatorData {..}
    else Left $ DecodingErrorNotAllInputUsed bytes

decodeAttestedCredentialData :: PartialBinaryDecoder (HS.AttestedCredentialData 'HS.Create)
decodeAttestedCredentialData bytes = do
  -- https://www.w3.org/TR/webauthn-2/#aaguid
  (bytes, acdAaguid) <-
    second HS.AAGUID
      <$> runBinary (Binary.getByteString 16) bytes

  -- https://www.w3.org/TR/webauthn-2/#credentialidlength
  (bytes, credentialLength) <-
    runBinary Binary.getWord16be bytes

  -- https://www.w3.org/TR/webauthn-2/#credentialid
  (bytes, acdCredentialId) <-
    second HS.CredentialId
      <$> runBinary (Binary.getByteString (fromIntegral credentialLength)) bytes

  -- https://www.w3.org/TR/webauthn-2/#credentialpublickey
  (bytes, acdCredentialPublicKey) <-
    runCBOR bytes

  pure (bytes, HS.AttestedCredentialData {..})

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authdataextensions)
decodeExtensions :: PartialBinaryDecoder HS.AuthenticatorExtensionOutputs
decodeExtensions bytes = do
  -- TODO
  (bytes, _extensions :: HashMap Text CBOR.Term) <- runCBOR bytes
  pure (bytes, HS.AuthenticatorExtensionOutputs {})

-- ** Utils

runBinary :: Binary.Get a -> PartialBinaryDecoder a
runBinary get bytes = case Binary.runGetOrFail get bytes of
  Left (_rest, _offset, err) -> Left $ DecodingErrorBinary err
  Right (rest, _offset, result) -> Right (rest, result)

runCBOR :: Serialise a => PartialBinaryDecoder a
runCBOR bytes = first DecodingErrorCBOR $ CBOR.deserialiseFromBytes Serialise.decode bytes
