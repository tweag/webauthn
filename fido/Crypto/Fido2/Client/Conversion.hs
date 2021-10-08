{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Crypto.Fido2.Client.Conversion
  ( Convert (..),
    Encode (..),
    Decode (..),
    DecodingError (..),
  )
where

import qualified Codec.CBOR.Read as CBOR
import Codec.CBOR.Term (Term (TBytes, TMap, TString))
import qualified Codec.CBOR.Term as CBOR
import Codec.Serialise (DeserialiseFailure, Serialise)
import qualified Codec.Serialise as Serialise
import qualified Crypto.Fido2.Client.Haskell as HS
import qualified Crypto.Fido2.Client.JavaScript as JS
import qualified Crypto.Hash as Hash
import qualified Data.Aeson as Aeson
import Data.Bifunctor (Bifunctor (second), first)
import qualified Data.Binary.Get as Binary
import qualified Data.Bits as Bits
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Lazy as LBS
import Data.Coerce (Coercible, coerce)
import Data.HashMap.Strict (HashMap, (!?))
import Data.Maybe (fromJust)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Deriving.Aeson (CustomJSON (CustomJSON), FieldLabelModifier, OmitNothingFields, Rename)
import GHC.Generics (Generic)

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
  type JS HS.AuthenticationExtensionsClientInputs = JS.AuthenticationExtensionsClientInputs

instance Convert HS.PublicKeyCredentialCreationOptions where
  type JS HS.PublicKeyCredentialCreationOptions = JS.PublicKeyCredentialCreationOptions

instance Convert HS.PublicKeyCredentialRequestOptions where
  type JS HS.PublicKeyCredentialRequestOptions = JS.PublicKeyCredentialRequestOptions

instance Convert (HS.PublicKeyCredential 'HS.Create) where
  type JS (HS.PublicKeyCredential 'HS.Create) = JS.PublicKeyCredential JS.AuthenticatorAttestationResponse

instance Convert (HS.AuthenticatorResponse 'HS.Create) where
  type JS (HS.AuthenticatorResponse 'HS.Create) = JS.AuthenticatorAttestationResponse

instance Convert (HS.PublicKeyCredential 'HS.Get) where
  type JS (HS.PublicKeyCredential 'HS.Get) = JS.PublicKeyCredential JS.AuthenticatorAssertionResponse

instance Convert (HS.AuthenticatorResponse 'HS.Get) where
  type JS (HS.AuthenticatorResponse 'HS.Get) = JS.AuthenticatorAssertionResponse

instance Convert HS.AuthenticationExtensionsClientOutputs where
  type JS HS.AuthenticationExtensionsClientOutputs = JS.AuthenticationExtensionsClientOutputs

instance Convert HS.CollectedClientData where
  type JS HS.CollectedClientData = JS.ArrayBuffer

instance Convert HS.AttestationObject where
  type JS HS.AttestationObject = JS.ArrayBuffer

instance Convert HS.AssertionSignature where
  type JS HS.AssertionSignature = JS.ArrayBuffer

instance Convert HS.AuthenticatorData where
  type JS HS.AuthenticatorData = JS.ArrayBuffer

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
      { id = encode id,
        name = encode name
      }

instance Encode HS.PublicKeyCredentialUserEntity where
  encode HS.PublicKeyCredentialUserEntity {..} =
    JS.PublicKeyCredentialUserEntity
      { id = encode id,
        displayName = encode displayName,
        name = encode name
      }

instance Encode HS.PublicKeyCredentialParameters where
  encode HS.PublicKeyCredentialParameters {..} =
    JS.PublicKeyCredentialParameters
      { typ = encode typ,
        alg = encode alg
      }

instance Encode HS.PublicKeyCredentialDescriptor where
  encode HS.PublicKeyCredentialDescriptor {..} =
    JS.PublicKeyCredentialDescriptor
      { typ = encode typ,
        id = encode id,
        transports = encode transports
      }

instance Encode HS.AuthenticatorSelectionCriteria where
  encode HS.AuthenticatorSelectionCriteria {..} =
    JS.AuthenticatorSelectionCriteria
      { authenticatorAttachment = encode authenticatorAttachment,
        residentKey = Just $ encode residentKey,
        -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
        -- Relying Parties SHOULD set it to true if, and only if, residentKey is set to required.
        requireResidentKey = Just (residentKey == HS.ResidentKeyRequirementRequired),
        userVerification = Just $ encode userVerification
      }

instance Encode HS.PublicKeyCredentialCreationOptions where
  encode HS.PublicKeyCredentialCreationOptions {..} =
    JS.PublicKeyCredentialCreationOptions
      { rp = encode rp,
        user = encode user,
        challenge = encode challenge,
        pubKeyCredParams = encode pubKeyCredParams,
        timeout = encode timeout,
        excludeCredentials = Just $ encode excludeCredentials,
        authenticatorSelection = encode authenticatorSelection,
        attestation = Just $ encode attestation,
        extensions = encode extensions
      }

instance Encode HS.PublicKeyCredentialRequestOptions where
  encode HS.PublicKeyCredentialRequestOptions {..} =
    JS.PublicKeyCredentialRequestOptions
      { challenge = encode challenge,
        timeout = encode timeout,
        rpId = encode rpId,
        allowCredentials = Just $ encode allowCredentials,
        userVerification = Just $ encode userVerification,
        extensions = Just $ encode extensions
      }

instance Encode HS.AuthenticationExtensionsClientInputs where
  encode HS.AuthenticationExtensionsClientInputs {} =
    JS.AuthenticationExtensionsClientInputs {}

-- | <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
instance Encode HS.COSEAlgorithmIdentifier where
  encode HS.ES512 = -36
  encode HS.ES384 = -35
  encode HS.EdDSA = -8
  encode HS.ES256 = -7

-- | <https://www.w3.org/TR/webauthn-2/#enum-credentialType>
instance Encode HS.PublicKeyCredentialType where
  encode HS.PublicKeyCredentialTypePublicKey = "public-key"

-- | <https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport>
instance Encode HS.AuthenticatorTransport where
  encode HS.USB = "usb"
  encode HS.NFC = "nfc"
  encode HS.BLE = "ble"
  encode HS.Internal = "internal"

-- | <https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment>
instance Encode HS.AuthenticatorAttachment where
  encode HS.Platform = "platform"
  encode HS.CrossPlatform = "cross-platform"

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

-- | Errors that can occur during decoding of client data
data DecodingError
  = DecodingErrorClientDataJSON String
  | DecodingErrorUnknownWebauthnType JS.DOMString
  | DecodingErrorClientDataChallenge String
  | DecodingErrorCBOR DeserialiseFailure
  | DecodingErrorBinary String
  | DecodingErrorNotAllInputUsed LBS.ByteString
  | DecodingErrorStatement Text [(Term, Term)]
  | DecodingErrorUnknownAttestationStatementFormat Text
  | DecodingErrorUnexpectedAttestationObjectValues (Maybe Term, Maybe Term, Maybe Term)

-- | @'Decode' hs@ indicates that the Haskell-specific type @hs@ can be
-- decoded from the more generic JavaScript type @'JS' hs@ with the 'decode' function.
class Decode hs where
  decode :: JS hs -> Either DecodingError hs
  default decode :: Coercible (JS hs) hs => JS hs -> Either DecodingError hs
  decode = pure . coerce

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

instance Decode HS.CollectedClientData where
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
    typ <- case typ of
      "webauthn.create" -> pure HS.Create
      "webauthn.get" -> pure HS.Get
      unknown -> Left $ DecodingErrorUnknownWebauthnType unknown
    pure
      HS.CollectedClientData
        { typ = typ,
          challenge = HS.Challenge challenge,
          origin = HS.Origin origin,
          crossOrigin = crossOrigin,
          hash = HS.ClientDataHash $ Hash.hash bytes
        }

instance Decode HS.AttestationObject where
  decode (JS.URLEncodedBase64 bytes) = decodeAttestationObject (LBS.fromStrict bytes)

instance Decode (HS.AuthenticatorResponse 'HS.Create) where
  decode JS.AuthenticatorAttestationResponse {..} = do
    attestationClientData <- decode clientDataJSON
    attestationObject <- decode attestationObject
    -- TODO
    let transports = Set.empty
    pure $ HS.AuthenticatorAttestationResponse {..}

instance Decode HS.AuthenticatorData where
  decode (JS.URLEncodedBase64 bytes) = useAllInput (LBS.fromStrict bytes) decodeAuthenticatorData

instance Decode HS.AssertionSignature

instance Decode HS.UserHandle

instance Decode (HS.AuthenticatorResponse 'HS.Get) where
  decode JS.AuthenticatorAssertionResponse {..} = do
    assertionClientData <- decode clientDataJSON
    authenticatorData <- decode authenticatorData
    signature <- decode signature
    userHandle <- decode userHandle
    pure $ HS.AuthenticatorAssertionResponse {..}

instance Decode HS.AuthenticationExtensionsClientOutputs where
  decode JS.AuthenticationExtensionsClientOutputs {} =
    pure HS.AuthenticationExtensionsClientOutputs {}

instance Decode (HS.PublicKeyCredential 'HS.Create) where
  decode JS.PublicKeyCredential {..} = do
    identifier <- decode rawId
    response <- decode response
    clientExtensionResults <- decode clientExtensionResults
    pure $ HS.PublicKeyCredential {..}

instance Decode (HS.PublicKeyCredential 'HS.Get) where
  decode JS.PublicKeyCredential {..} = do
    identifier <- decode rawId
    response <- decode response
    clientExtensionResults <- decode clientExtensionResults
    pure $ HS.PublicKeyCredential {..}

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

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
decodeAttestationObject :: LBS.ByteString -> Either DecodingError HS.AttestationObject
decodeAttestationObject bytes = do
  map :: HashMap Text Term <- first DecodingErrorCBOR $ Serialise.deserialiseOrFail bytes
  case (map !? "authData", map !? "fmt", map !? "attStmt") of
    (Just (TBytes authDataBytes), Just (TString fmt), Just (TMap attStmtPairs)) -> do
      authData <- useAllInput (LBS.fromStrict authDataBytes) decodeAuthenticatorData
      attStmt <- decodeAttestationStatement fmt attStmtPairs
      pure HS.AttestationObject {..}
    terms -> Left $ DecodingErrorUnexpectedAttestationObjectValues terms

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authenticator-data)
decodeAuthenticatorData :: PartialBinaryDecoder HS.AuthenticatorData
decodeAuthenticatorData bytes = do
  -- https://www.w3.org/TR/webauthn-2/#rpidhash
  (bytes, rpIdHash) <-
    second (HS.RpIdHash . fromJust . Hash.digestFromByteString)
      <$> runBinary (Binary.getByteString 32) bytes

  -- https://www.w3.org/TR/webauthn-2/#flags
  (bytes, bitFlags) <-
    runBinary Binary.getWord8 bytes
  let flags =
        HS.AuthenticatorDataFlags
          { userPresent = Bits.testBit bitFlags 0,
            userVerified = Bits.testBit bitFlags 2
          }

  -- https://www.w3.org/TR/webauthn-2/#signcount
  (bytes, signCount) <-
    runBinary Binary.getWord32be bytes

  -- https://www.w3.org/TR/webauthn-2/#attestedcredentialdata
  (bytes, attestedCredentialData) <-
    if Bits.testBit bitFlags 6
      then fmap Just <$> decodeAttestedCredentialData bytes
      else pure (bytes, Nothing)

  -- https://www.w3.org/TR/webauthn-2/#authdataextensions
  (bytes, extensions) <-
    if Bits.testBit bitFlags 7
      then fmap Just <$> decodeExtensions bytes
      else pure (bytes, Nothing)

  pure (bytes, HS.AuthenticatorData {..})

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#attested-credential-data)
decodeAttestedCredentialData :: PartialBinaryDecoder HS.AttestedCredentialData
decodeAttestedCredentialData bytes = do
  -- https://www.w3.org/TR/webauthn-2/#aaguid
  (bytes, aaguid) <-
    second HS.AAGUID
      <$> runBinary (Binary.getByteString 16) bytes

  -- https://www.w3.org/TR/webauthn-2/#credentialidlength
  (bytes, credentialLength) <-
    runBinary Binary.getWord16be bytes

  -- https://www.w3.org/TR/webauthn-2/#credentialid
  (bytes, credentialId) <-
    second HS.CredentialId
      <$> runBinary (Binary.getByteString (fromIntegral credentialLength)) bytes

  -- https://www.w3.org/TR/webauthn-2/#credentialpublickey
  (bytes, credentialPublicKey) <-
    runCBOR bytes

  pure (bytes, HS.AttestedCredentialData {..})

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authdataextensions)
decodeExtensions :: PartialBinaryDecoder HS.AuthenticatorExtensionOutputs
decodeExtensions bytes = do
  -- TODO
  (bytes, _extensions :: HashMap Text CBOR.Term) <- runCBOR bytes
  pure (bytes, HS.AuthenticatorExtensionOutputs {})

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats)
decodeAttestationStatement :: Text -> [(Term, Term)] -> Either DecodingError HS.AttestationStatement
-- https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
decodeAttestationStatement "none" pairs
  -- Contains an empty map
  | null pairs = pure HS.AttestationStatementNone
  | otherwise = Left $ DecodingErrorStatement "none" pairs
-- TODO
decodeAttestationStatement unknown _ = Left $ DecodingErrorUnknownAttestationStatementFormat unknown

-- ** Utils

useAllInput :: LBS.ByteString -> PartialBinaryDecoder a -> Either DecodingError a
useAllInput bytes decoder = case decoder bytes of
  Left err -> Left err
  Right (rest, result)
    | LBS.null rest -> Left $ DecodingErrorNotAllInputUsed rest
    | otherwise -> Right result

runBinary :: Binary.Get a -> PartialBinaryDecoder a
runBinary get bytes = case Binary.runGetOrFail get bytes of
  Left (_rest, _offset, err) -> Left $ DecodingErrorBinary err
  Right (rest, _offset, result) -> Right (rest, result)

runCBOR :: Serialise a => PartialBinaryDecoder a
runCBOR bytes = first DecodingErrorCBOR $ CBOR.deserialiseFromBytes Serialise.decode bytes
