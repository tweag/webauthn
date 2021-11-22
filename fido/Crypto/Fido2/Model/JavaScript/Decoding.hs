{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | This module handles the decoding of structures returned by the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- and [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- methods while [Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- and [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion) respectively.
module Crypto.Fido2.Model.JavaScript.Decoding
  ( -- * Decoding PublicKeyCredential results
    DecodingError (..),
    CreatedDecodingError (..),
    decodeCreatedPublicKeyCredential,
    decodeRequestedPublicKeyCredential,
    decodePublicKeyCredentialCreationOptions,
    decodePublicKeyCredentialRequestOptions,
    decodeCreateCollectedClientData,
    decodeGetCollectedClientData,
  )
where

import qualified Codec.CBOR.Decoding as CBOR
import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Term as CBOR
import qualified Codec.Serialise as CBOR
import Control.Exception (Exception, SomeException (SomeException))
import Control.Monad (forM, unless)
import Crypto.Fido2.Model
  ( AttestationStatementFormat (asfDecode),
    SomeAttestationStatementFormat (SomeAttestationStatementFormat),
    SupportedAttestationStatementFormats,
    sasfLookup,
  )
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import Crypto.Fido2.Model.JavaScript.Types (Convert (JS))
import qualified Crypto.Fido2.Model.JavaScript.Types as JS
import Crypto.Fido2.Model.WebauthnType (SWebauthnType (SCreate, SGet), SingI (sing))
import Crypto.Fido2.PublicKey (decodePublicKey)
import qualified Crypto.Fido2.PublicKey as PublicKey
import qualified Crypto.Hash as Hash
import qualified Data.Aeson as Aeson
import Data.Bifunctor (first, second)
import qualified Data.Binary.Get as Binary
import qualified Data.Bits as Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Lazy as LBS
import Data.Coerce (Coercible, coerce)
import Data.HashMap.Strict (HashMap, (!?))
import qualified Data.HashMap.Strict as HashMap
import Data.Maybe (catMaybes, fromJust, mapMaybe)
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text.Encoding as Text

-- | Decoding errors that can only occur when decoding a
-- 'JS.CreatedPublicKeyCredential' result with 'decodeCreatedPublicKeyCredential'
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

-- | Decoding errors that can occur when decoding either a
-- 'JS.CreatedPublicKeyCredential' result with 'decodeCreatedPublicKeyCredential'
-- or a 'JS.RequestedPublicKeyCredential' result with 'decodeRequestedPublicKeyCredential'
data DecodingError
  = -- | The Client data could not be decoded for the provided reason
    DecodingErrorClientDataJSON String
  | -- | The Challenge could not be decoded from its Base64-based encoding for
    -- the provided reason
    DecodingErrorClientDataChallenge String
  | -- | The Client Data's Webauthn type did not match the expected one
    -- (first: expected, second: received)
    DecodingErrorUnexpectedWebauthnType JS.DOMString JS.DOMString
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
-- Because of this we are specifying the decoders as a 'PartialBinaryDecoder',
-- which is just a function that can partially consume a 'LBS.ByteString'.
-- Using this we can somewhat easily flip between the two libraries while
-- decoding without too much nastiness.
type PartialBinaryDecoder a = LBS.ByteString -> Either DecodingError (LBS.ByteString, a)

-- | A 'PartialBinaryDecoder' for a binary encoding specified using 'Binary.Get'
runBinary :: Binary.Get a -> PartialBinaryDecoder a
runBinary get bytes = case Binary.runGetOrFail get bytes of
  Left (_rest, _offset, err) -> Left $ DecodingErrorBinary err
  Right (rest, _offset, result) -> Right (rest, result)

-- | A 'PartialBinaryDecoder' for a CBOR encoding specified using the given Decoder
runCBOR :: (forall s. CBOR.Decoder s a) -> PartialBinaryDecoder (LBS.ByteString, a)
runCBOR decoder bytes = case CBOR.deserialiseFromBytesWithSize decoder bytes of
  Left err -> Left $ DecodingErrorCBOR err
  Right (rest, consumed, a) -> return (rest, (LBS.take (fromIntegral consumed) bytes, a))

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
    second M.SignatureCounter
      <$> runBinary Binary.getWord32be bytes

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
  (bytes, (usedBytes, acdCredentialPublicKey)) <-
    runCBOR decodePublicKey bytes
  let acdCredentialPublicKeyBytes = M.PublicKeyBytes $ LBS.toStrict usedBytes

  pure (bytes, M.AttestedCredentialData {..})

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#authdataextensions)
decodeExtensions :: PartialBinaryDecoder M.AuthenticatorExtensionOutputs
decodeExtensions bytes = do
  -- TODO
  (bytes, (_, _extensions :: HashMap Text CBOR.Term)) <- runCBOR CBOR.decode bytes
  pure (bytes, M.AuthenticatorExtensionOutputs {})

-- | @'Decode' a@ indicates that the Haskell-specific type @a@ can be
-- decoded from the more generic JavaScript type @'JS' a@ with the 'decode' function.
class Convert a => Decode a where
  decode :: JS a -> Either DecodingError a
  default decode :: Coercible (JS a) a => JS a -> Either DecodingError a
  decode = pure . coerce

-- | Like 'Decode', but with a 'decodeCreated' function that also takes a
-- 'SupportedAttestationStatementFormats' in order to allow decoding to depend
-- on the supported attestation formats. This function also throws a
-- 'CreatedDecodingError' instead of a 'DecodingError.
class Convert a => DecodeCreated a where
  decodeCreated :: SupportedAttestationStatementFormats -> JS a -> Either CreatedDecodingError a

instance Decode a => Decode (Maybe a) where
  decode Nothing = pure Nothing
  decode (Just a) = Just <$> decode a

instance Decode M.CredentialId

instance Decode M.AssertionSignature

instance Decode M.UserHandle

instance Decode M.AuthenticationExtensionsClientOutputs where
  -- TODO: Implement extension support
  decode _ = pure M.AuthenticationExtensionsClientOutputs {}

instance SingI t => Decode (M.CollectedClientData t) where
  decode (JS.URLEncodedBase64 bytes) = do
    -- https://www.w3.org/TR/webauthn-2/#collectedclientdata-json-compatible-serialization-of-client-data
    JS.ClientDataJSON {..} <- first DecodingErrorClientDataJSON $ Aeson.eitherDecodeStrict bytes
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

instance Decode (M.AuthenticatorData 'M.Get) where
  decode (JS.URLEncodedBase64 bytes) = decodeAuthenticatorData bytes

instance Decode (M.AuthenticatorResponse 'M.Get) where
  decode JS.AuthenticatorAssertionResponse {..} = do
    argClientData <- decode clientDataJSON
    argAuthenticatorData <- decode authenticatorData
    argSignature <- decode signature
    argUserHandle <- decode userHandle
    pure $ M.AuthenticatorAssertionResponse {..}

instance Decode (M.PublicKeyCredential 'M.Get) where
  decode JS.PublicKeyCredential {..} = do
    pkcIdentifier <- decode rawId
    pkcResponse <- decode response
    pkcClientExtensionResults <- decode clientExtensionResults
    pure $ M.PublicKeyCredential {..}

instance Decode M.RpId

instance Decode M.RelyingPartyName

instance Decode M.PublicKeyCredentialRpEntity where
  decode JS.PublicKeyCredentialRpEntity {..} = do
    pkcreId <- decode id
    pkcreName <- decode name
    pure $ M.PublicKeyCredentialRpEntity {..}

instance Decode M.UserAccountDisplayName

instance Decode M.UserAccountName

instance Decode M.PublicKeyCredentialUserEntity where
  decode JS.PublicKeyCredentialUserEntity {..} = do
    pkcueId <- decode id
    pkcueDisplayName <- decode displayName
    pkcueName <- decode name
    pure $ M.PublicKeyCredentialUserEntity {..}

instance Decode M.Challenge

instance Decode PublicKey.COSEAlgorithmIdentifier where
  -- The specification does not inspect the algorithm until
  -- assertion/attestation. We implement the check here to go to a Haskell
  -- type. Erring on the side of caution by failing to parse if an unsupported
  -- alg was encountered.
  decode n = maybe (Left $ DecodingErrorUnexpectedAlgorithmIdentifier n) Right $ PublicKey.toAlg n

instance Decode M.Timeout

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-transport)
instance Decode [M.AuthenticatorTransport] where
  decode = pure . mapMaybe decodeTransport
    where
      decodeTransport "usb" = Just M.AuthenticatorTransportUSB
      decodeTransport "nfc" = Just M.AuthenticatorTransportNFC
      decodeTransport "ble" = Just M.AuthenticatorTransportBLE
      decodeTransport "internal" = Just M.AuthenticatorTransportInternal
      decodeTransport _ = Nothing

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-descriptor)
-- [The type] member contains the type of the public key credential the caller
-- is referring to. The value SHOULD be a member of
-- PublicKeyCredentialType but client platforms MUST ignore any
-- PublicKeyCredentialDescriptor with an unknown type.
instance Decode [M.PublicKeyCredentialDescriptor] where
  decode Nothing = pure []
  decode (Just xs) = catMaybes <$> traverse decodeDescriptor xs
    where
      decodeDescriptor :: JS.PublicKeyCredentialDescriptor -> Either DecodingError (Maybe M.PublicKeyCredentialDescriptor)
      decodeDescriptor JS.PublicKeyCredentialDescriptor {typ = "public-key", id, transports} = do
        let pkcdTyp = M.PublicKeyCredentialTypePublicKey
        pkcdId <- decode id
        pkcdTransports <- decode transports
        pure . Just $ M.PublicKeyCredentialDescriptor {..}
      decodeDescriptor _ = pure Nothing

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enum-userVerificationRequirement)
-- The value SHOULD be a member of UserVerificationRequirement but client
-- platforms MUST ignore unknown values, treating an unknown value as if the
-- member does not exist. The default is "preferred".
instance Decode M.UserVerificationRequirement where
  decode (Just "discouraged") = Right M.UserVerificationRequirementDiscouraged
  decode (Just "preferred") = Right M.UserVerificationRequirementPreferred
  decode (Just "required") = Right M.UserVerificationRequirementRequired
  decode _ = Right M.UserVerificationRequirementPreferred

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-authenticatorSelection)
instance Decode M.AuthenticatorSelectionCriteria where
  decode JS.AuthenticatorSelectionCriteria {..} = do
    let ascAuthenticatorAttachment = decodeAttachment =<< authenticatorAttachment
        ascResidentKey = decodeResidentKey residentKey
    ascUserVerification <- decode userVerification
    pure $ M.AuthenticatorSelectionCriteria {..}
    where
      -- Any unknown values must be ignored, treating them as if the member does not exist
      decodeAttachment "platform" = Just M.AuthenticatorAttachmentPlatform
      decodeAttachment "cross-platform" = Just M.AuthenticatorAttachmentCrossPlatform
      decodeAttachment _ = Nothing

      -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
      -- The value SHOULD be a member of ResidentKeyRequirement but client platforms
      -- MUST ignore unknown values, treating an unknown value as if the member does not
      -- exist. If no value is given then the effective value is required if
      -- requireResidentKey is true or discouraged if it is false or absent.
      decodeResidentKey :: Maybe JS.DOMString -> M.ResidentKeyRequirement
      decodeResidentKey (Just "discouraged") = M.ResidentKeyRequirementDiscouraged
      decodeResidentKey (Just "preferred") = M.ResidentKeyRequirementPreferred
      decodeResidentKey (Just "required") = M.ResidentKeyRequirementRequired
      decodeResidentKey _ = case requireResidentKey of
        Just True -> M.ResidentKeyRequirementRequired
        _ -> M.ResidentKeyRequirementDiscouraged

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-attestationconveyancepreference)
-- Its values SHOULD be members of AttestationConveyancePreference. Client
-- platforms MUST ignore unknown values, treating an unknown value as if the
-- member does not exist. Its default value is "none".
instance Decode M.AttestationConveyancePreference where
  decode (Just "none") = Right M.AttestationConveyancePreferenceNone
  decode (Just "indirect") = Right M.AttestationConveyancePreferenceIndirect
  decode (Just "direct") = Right M.AttestationConveyancePreferenceDirect
  decode (Just "enterprise") = Right M.AttestationConveyancePreferenceEnterprise
  decode _ = Right M.AttestationConveyancePreferenceNone

-- [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialparameters)
-- [The type] member specifies the type of credential to be created. The value SHOULD
-- be a member of PublicKeyCredentialType but client platforms MUST ignore
-- unknown values, ignoring any PublicKeyCredentialParameters with an unknown
-- type.
instance Decode [M.PublicKeyCredentialParameters] where
  decode xs = catMaybes <$> traverse decodeParam xs
    where
      decodeParam :: JS.PublicKeyCredentialParameters -> Either DecodingError (Maybe M.PublicKeyCredentialParameters)
      decodeParam JS.PublicKeyCredentialParameters {typ = "public-key", alg} = do
        let pkcpTyp = M.PublicKeyCredentialTypePublicKey
        pkcpAlg <- decode alg
        pure . Just $ M.PublicKeyCredentialParameters {..}
      decodeParam _ = pure Nothing

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
instance Decode (M.PublicKeyCredentialOptions 'M.Create) where
  decode JS.PublicKeyCredentialCreationOptions {..} = do
    pkcocRp <- decode rp
    pkcocUser <- decode user
    pkcocChallenge <- decode challenge
    pkcocPubKeyCredParams <- decode pubKeyCredParams
    pkcocTimeout <- decode timeout
    pkcocExcludeCredentials <- decode excludeCredentials
    pkcocAuthenticatorSelection <- decode authenticatorSelection
    pkcocAttestation <- decode attestation
    let pkcocExtensions = M.AuthenticationExtensionsClientInputs {} <$ extensions
    pure $ M.PublicKeyCredentialCreationOptions {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
instance Decode (M.PublicKeyCredentialOptions 'M.Get) where
  decode JS.PublicKeyCredentialRequestOptions {..} = do
    pkcogChallenge <- decode challenge
    pkcogTimeout <- decode timeout
    pkcogRpId <- decode rpId
    pkcogAllowCredentials <- decode allowCredentials
    pkcogUserVerification <- decode userVerification
    let pkcogExtensions = M.AuthenticationExtensionsClientInputs {} <$ extensions
    pure $ M.PublicKeyCredentialRequestOptions {..}

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object)
instance DecodeCreated M.AttestationObject where
  decodeCreated supportedFormats (JS.URLEncodedBase64 bytes) = do
    map :: HashMap Text CBOR.Term <- first (CreatedDecodingErrorCommon . DecodingErrorCBOR) $ CBOR.deserialiseOrFail $ LBS.fromStrict bytes
    case (map !? "authData", map !? "fmt", map !? "attStmt") of
      (Just (CBOR.TBytes authDataBytes), Just (CBOR.TString fmt), Just (CBOR.TMap attStmtPairs)) -> do
        aoAuthData <- first CreatedDecodingErrorCommon $ decodeAuthenticatorData authDataBytes

        case sasfLookup fmt supportedFormats of
          Nothing -> Left $ CreatedDecodingErrorUnknownAttestationStatementFormat fmt
          Just (SomeAttestationStatementFormat aoFmt) -> do
            attStmtMap <-
              HashMap.fromList <$> forM attStmtPairs \case
                (CBOR.TString text, term) -> pure (text, term)
                (nonString, _) -> Left $ CreatedDecodingErrorUnexpectedAttestationStatementKey nonString
            aoAttStmt <-
              first (CreatedDecodingErrorAttestationStatement . SomeException) $
                asfDecode aoFmt attStmtMap
            pure $ M.AttestationObject {..}
      _ -> Left $ CreatedDecodingErrorUnexpectedAttestationObjectValues map

instance DecodeCreated (M.AuthenticatorResponse 'M.Create) where
  decodeCreated asfMap JS.AuthenticatorAttestationResponse {..} = do
    arcClientData <- first CreatedDecodingErrorCommon $ decode clientDataJSON
    arcAttestationObject <- decodeCreated asfMap attestationObject
    -- TODO: The webauthn-json library doesn't currently pass the transports
    let arcTransports = Set.empty
    pure $ M.AuthenticatorAttestationResponse {..}

instance DecodeCreated (M.PublicKeyCredential 'M.Create) where
  decodeCreated asfMap JS.PublicKeyCredential {..} = do
    pkcIdentifier <- first CreatedDecodingErrorCommon $ decode rawId
    pkcResponse <- decodeCreated asfMap response
    pkcClientExtensionResults <- first CreatedDecodingErrorCommon $ decode clientExtensionResults
    pure $ M.PublicKeyCredential {..}

-- | Decodes a 'JS.CreatedPublicKeyCredential' result, corresponding to the
-- [`PublicKeyCredential` interface](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- as returned by the [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- method while [Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
decodeCreatedPublicKeyCredential ::
  SupportedAttestationStatementFormats ->
  JS.CreatedPublicKeyCredential ->
  Either CreatedDecodingError (M.PublicKeyCredential 'M.Create)
decodeCreatedPublicKeyCredential = decodeCreated

-- | Decodes a 'JS.RequestedPublicKeyCredential' result, corresponding to the
-- [`PublicKeyCredential` interface](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
-- as returned by the [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get)
-- method while [Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
decodeRequestedPublicKeyCredential ::
  JS.RequestedPublicKeyCredential ->
  Either DecodingError (M.PublicKeyCredential 'M.Get)
decodeRequestedPublicKeyCredential = decode

decodePublicKeyCredentialCreationOptions ::
  JS.PublicKeyCredentialCreationOptions ->
  Either DecodingError (M.PublicKeyCredentialOptions 'M.Create)
decodePublicKeyCredentialCreationOptions = decode

decodePublicKeyCredentialRequestOptions ::
  JS.PublicKeyCredentialRequestOptions ->
  Either DecodingError (M.PublicKeyCredentialOptions 'M.Get)
decodePublicKeyCredentialRequestOptions = decode

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
decodeCreateCollectedClientData :: JS.ArrayBuffer -> Either DecodingError (M.CollectedClientData 'M.Create)
decodeCreateCollectedClientData = decode

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
decodeGetCollectedClientData :: JS.ArrayBuffer -> Either DecodingError (M.CollectedClientData 'M.Get)
decodeGetCollectedClientData = decode
