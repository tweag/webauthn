{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

-- | Stability: experimental
-- This module models direct representations of JavaScript objects interacting with the
-- [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create)
-- and [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) methods, as used by [Webauthn2](https://www.w3.org/TR/webauthn-2).
-- Note that these types don't encode the semantics of their values. E.g. if the JavaScript object has a @DOMString@
-- field, but only values @"foo"@ and @"bar"@ are possible, the type is still encoded as a generic 'IDL.DOMString'.
-- This allows us to match the specification very closely, deferring decoding of these values to another module.
-- This module also implements 'Aeson.FromJSON' and 'Aeson.ToJSON' instances of its types, which are compatible with
-- [webauthn-json](https://github.com/github/webauthn-json)'s JSON schema.
--
-- The defined types are
--
-- - 'PublicKeyCredentialCreationOptions' and all its subtypes. Passed as the
--   [publicKey](https://www.w3.org/TR/webauthn-2/#dom-credentialcreationoptions-publickey) field to the
--   [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) method
--   in step 2 of [§ 7.1 Registering a New Credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- - 'PublicKeyCredentialRequestOptions' and all its subtypes. Passed as the
--   [publicKey](https://www.w3.org/TR/webauthn-2/#dom-credentialrequestoptions-publickey) field to the
--   [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) method
--   in step 2 of [§ 7.2 Verifying an Authentication Assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion)
-- - @'PublicKeyCredential' response@ and all its subtypes. Responses of the
--   [create()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create) (in which case @response ~ 'AuthenticatorAttestationResponse'@) and
--   [get()](https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get) (in which case @response ~ 'AuthenticatorAssertionResponse'@ methods.
module Crypto.WebAuthn.Encoding.WebAuthnJson
  ( -- * Top-level types
    PublicKeyCredentialCreationOptions (..),
    PublicKeyCredentialRequestOptions (..),
    PublicKeyCredential (..),

    -- * Nested types
    AuthenticatorAttestationResponse (..),
    AuthenticatorAssertionResponse (..),
    PublicKeyCredentialRpEntity (..),
    PublicKeyCredentialUserEntity (..),
    PublicKeyCredentialParameters (..),
    COSEAlgorithmIdentifier,
    PublicKeyCredentialDescriptor (..),
    AuthenticatorSelectionCriteria (..),
  )
where

import Control.Monad.Except (MonadError, liftEither, throwError)
import Control.Monad.Reader (MonadReader (ask))
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import qualified Crypto.WebAuthn.Encoding.Binary.Decoding as B
import qualified Crypto.WebAuthn.Encoding.Binary.Encoding as B
import Crypto.WebAuthn.Internal.Utils (jsonEncodingOptions)
import qualified Crypto.WebAuthn.Model.Defaults as D
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as T
import qualified Crypto.WebAuthn.WebIDL as IDL
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as Base64Url
import Data.Coerce (Coercible, coerce)
import Data.Int (Int32)
import Data.Kind (Type)
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Singletons (SingI)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Data.Word (Word32)
import GHC.Generics (Generic)

-- Design notes:
-- Why not a multi-param type class? Because then we can't implement `Encode a => Encode (Maybe a)` without UndecidableInstances
--

class Encode a where
  type JSON a :: Type
  encode :: a -> JSON a
  default encode :: Coercible a (JSON a) => a -> JSON a
  encode = coerce

class Encode a => Decode m a where
  decode :: MonadError Text m => JSON a -> m a
  default decode :: (MonadError Text m, Coercible (JSON a) a) => JSON a -> m a
  decode = pure . coerce

decodeWithDefault :: (MonadError Text m, Decode m a) => a -> Maybe (JSON a) -> m a
decodeWithDefault def Nothing = pure def
decodeWithDefault _ (Just value) = decode value

instance (Functor f, Encode a) => Encode (f a) where
  type JSON (f a) = f (JSON a)
  encode = fmap encode

instance (Traversable f, Decode m a) => Decode m (f a) where
  decode = traverse decode

instance Encode T.Timeout where
  type JSON T.Timeout = Word32

instance Decode m T.Timeout

instance Encode T.RpId where
  type JSON T.RpId = Text

instance Decode m T.RpId

instance Encode T.RelyingPartyName where
  type JSON T.RelyingPartyName = Text

instance Decode m T.RelyingPartyName

instance Encode T.UserHandle where
  type JSON T.UserHandle = Base64UrlString

instance Decode m T.UserHandle

instance Encode T.UserAccountDisplayName where
  type JSON T.UserAccountDisplayName = Text

instance Decode m T.UserAccountDisplayName

instance Encode T.UserAccountName where
  type JSON T.UserAccountName = Text

instance Decode m T.UserAccountName

instance Encode T.Challenge where
  type JSON T.Challenge = Base64UrlString

instance Decode m T.Challenge

instance Encode T.CredentialId where
  type JSON T.CredentialId = Base64UrlString

instance Decode m T.CredentialId

{-
Note: The spec often mentions that _client platforms_ must ignore unknown
values, but since we implement a RP, we don't need to concern ourselves with
that.

The only place where we do need to concern ourselves with it is the
[transports](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-transports-slot)
field returned from the client, which in Level 2 of the spec mentions:

> The values SHOULD be members of
> `[AuthenticatorTransport](https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport)`
> but [Relying Parties](https://www.w3.org/TR/webauthn-2/#relying-party) MUST
> ignore unknown values.

However that doesn't say what should happen in case of unknown values. This has
been fixed in a more recent version of the spec, see
https://github.com/w3c/webauthn/issues/1587. It will say this in the future:

> The values SHOULD be members of AuthenticatorTransport but Relying Parties
> SHOULD accept and store unknown values.
-}

instance Encode T.CredentialType where
  type JSON T.CredentialType = Text
  encode T.CredentialTypePublicKey = "public-key"

instance Decode m T.CredentialType where
  decode "public-key" = pure T.CredentialTypePublicKey
  decode str = throwError $ "Unknown PublicKeyCredentialType string: " <> str

instance Encode T.UserVerificationRequirement where
  type JSON T.UserVerificationRequirement = Text
  encode T.UserVerificationRequirementRequired = "required"
  encode T.UserVerificationRequirementPreferred = "preferred"
  encode T.UserVerificationRequirementDiscouraged = "discouraged"

instance Decode m T.UserVerificationRequirement where
  decode "discouraged" = pure T.UserVerificationRequirementDiscouraged
  decode "preferred" = pure T.UserVerificationRequirementPreferred
  decode "required" = pure T.UserVerificationRequirementRequired
  decode key = throwError $ "Unknown UserVerificationRequirement string: " <> key

instance Encode T.AuthenticatorAttachment where
  type JSON T.AuthenticatorAttachment = Text
  encode T.AuthenticatorAttachmentPlatform = "platform"
  encode T.AuthenticatorAttachmentCrossPlatform = "cross-platform"

instance Decode m T.AuthenticatorAttachment where
  decode "platform" = pure T.AuthenticatorAttachmentPlatform
  decode "cross-platform" = pure T.AuthenticatorAttachmentCrossPlatform
  decode key = throwError $ "Unknown AuthenticatorAttachment string: " <> key

instance Encode T.ResidentKeyRequirement where
  type JSON T.ResidentKeyRequirement = Text
  encode T.ResidentKeyRequirementDiscouraged = "discouraged"
  encode T.ResidentKeyRequirementPreferred = "preferred"
  encode T.ResidentKeyRequirementRequired = "required"

instance Decode m T.ResidentKeyRequirement where
  decode "discouraged" = pure T.ResidentKeyRequirementDiscouraged
  decode "preferred" = pure T.ResidentKeyRequirementPreferred
  decode "required" = pure T.ResidentKeyRequirementRequired
  decode key = throwError $ "Unknown ResidentKeyRequirement string: " <> key

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#enumdef-attestationconveyancepreference)
instance Encode T.AttestationConveyancePreference where
  type JSON T.AttestationConveyancePreference = Text
  encode T.AttestationConveyancePreferenceNone = "none"
  encode T.AttestationConveyancePreferenceIndirect = "indirect"
  encode T.AttestationConveyancePreferenceDirect = "direct"
  encode T.AttestationConveyancePreferenceEnterprise = "enterprise"

instance Decode m T.AttestationConveyancePreference where
  decode "none" = pure T.AttestationConveyancePreferenceNone
  decode "indirect" = pure T.AttestationConveyancePreferenceIndirect
  decode "direct" = pure T.AttestationConveyancePreferenceDirect
  decode "enterprise" = pure T.AttestationConveyancePreferenceEnterprise
  decode key = throwError $ "Unknown AttestationConveyancePreference string: " <> key

instance Encode T.AuthenticatorTransport where
  type JSON T.AuthenticatorTransport = Text
  encode T.AuthenticatorTransportUSB = "usb"
  encode T.AuthenticatorTransportNFC = "nfc"
  encode T.AuthenticatorTransportBLE = "ble"
  encode T.AuthenticatorTransportInternal = "internal"
  encode (T.AuthenticatorTransportUnknown str) = str

instance Decode m T.AuthenticatorTransport where
  decode "usb" = pure T.AuthenticatorTransportUSB
  decode "nfc" = pure T.AuthenticatorTransportNFC
  decode "ble" = pure T.AuthenticatorTransportBLE
  decode "internal" = pure T.AuthenticatorTransportInternal
  decode str = pure $ T.AuthenticatorTransportUnknown str

instance Encode Cose.CoseSignAlg where
  type JSON Cose.CoseSignAlg = Int32
  encode = Cose.fromCoseSignAlg

instance Decode m Cose.CoseSignAlg where
  decode = liftEither . Cose.toCoseSignAlg

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-params)
instance Encode T.CredentialParameters where
  type JSON T.CredentialParameters = PublicKeyCredentialParameters
  encode T.CredentialParameters {..} =
    PublicKeyCredentialParameters
      { littype = encode cpTyp,
        alg = encode cpAlg
      }

instance Decode m T.CredentialParameters where
  decode PublicKeyCredentialParameters {..} = do
    cpTyp <- decode littype
    cpAlg <- decode alg
    pure T.CredentialParameters {..}

instance Encode T.AuthenticatorSelectionCriteria where
  type JSON T.AuthenticatorSelectionCriteria = AuthenticatorSelectionCriteria
  encode T.AuthenticatorSelectionCriteria {..} =
    AuthenticatorSelectionCriteria
      { authenticatorAttachment = encode ascAuthenticatorAttachment,
        residentKey = Just $ encode ascResidentKey,
        -- [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
        -- Relying Parties SHOULD set it to true if, and only if, residentKey is set to required.
        requireResidentKey = Just (ascResidentKey == T.ResidentKeyRequirementRequired),
        userVerification = Just $ encode ascUserVerification
      }

instance Decode m T.AuthenticatorSelectionCriteria where
  decode AuthenticatorSelectionCriteria {..} = do
    ascAuthenticatorAttachment <- decode authenticatorAttachment
    ascResidentKey <- decodeWithDefault (D.ascResidentKeyDefault requireResidentKey) residentKey
    ascUserVerification <- decodeWithDefault D.ascUserVerificationDefault userVerification
    pure $ T.AuthenticatorSelectionCriteria {..}

instance Encode T.AuthenticationExtensionsClientInputs where
  type JSON T.AuthenticationExtensionsClientInputs = Map Text Aeson.Value

  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.
  encode T.AuthenticationExtensionsClientInputs {} = Map.empty

instance Decode m T.AuthenticationExtensionsClientInputs where
  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.
  decode _ = pure T.AuthenticationExtensionsClientInputs {}

instance Encode (T.CredentialOptions 'K.Registration) where
  type JSON (T.CredentialOptions 'K.Registration) = PublicKeyCredentialCreationOptions
  encode T.CredentialOptionsRegistration {..} =
    PublicKeyCredentialCreationOptions
      { rp = encode corRp,
        user = encode corUser,
        challenge = encode corChallenge,
        pubKeyCredParams = encode corPubKeyCredParams,
        timeout = encode corTimeout,
        excludeCredentials = Just $ encode corExcludeCredentials,
        authenticatorSelection = encode corAuthenticatorSelection,
        attestation = Just $ encode corAttestation,
        extensions = encode corExtensions
      }

instance Decode m (T.CredentialOptions 'K.Registration) where
  decode PublicKeyCredentialCreationOptions {..} = do
    corRp <- decode rp
    corUser <- decode user
    corChallenge <- decode challenge
    corPubKeyCredParams <- decode pubKeyCredParams
    corTimeout <- decode timeout
    corExcludeCredentials <- decodeWithDefault D.corExcludeCredentialsDefault excludeCredentials
    corAuthenticatorSelection <- decode authenticatorSelection
    corAttestation <- decodeWithDefault D.corAttestationDefault attestation
    corExtensions <- decode extensions
    pure $ T.CredentialOptionsRegistration {..}

instance Encode (T.CredentialOptions 'K.Authentication) where
  type JSON (T.CredentialOptions 'K.Authentication) = PublicKeyCredentialRequestOptions
  encode T.CredentialOptionsAuthentication {..} =
    PublicKeyCredentialRequestOptions
      { challenge = encode coaChallenge,
        timeout = encode coaTimeout,
        rpId = encode coaRpId,
        allowCredentials = Just $ encode coaAllowCredentials,
        userVerification = Just $ encode coaUserVerification,
        extensions = encode coaExtensions
      }

instance Decode m (T.CredentialOptions 'K.Authentication) where
  decode PublicKeyCredentialRequestOptions {..} = do
    coaChallenge <- decode challenge
    coaTimeout <- decode timeout
    coaRpId <- decode rpId
    coaAllowCredentials <- decodeWithDefault D.coaAllowCredentialsDefault allowCredentials
    coaUserVerification <- decodeWithDefault D.coaUserVerificationDefault userVerification
    coaExtensions <- decode extensions
    pure $ T.CredentialOptionsAuthentication {..}

instance SingI c => Encode (T.CollectedClientData (c :: K.CeremonyKind) 'True) where
  type JSON (T.CollectedClientData c 'True) = Base64UrlString
  encode = Base64UrlString . B.encodeCollectedClientData

instance SingI c => Decode m (T.CollectedClientData (c :: K.CeremonyKind) 'True) where
  decode = liftEither . B.decodeCollectedClientData . unBase64UrlString

instance Encode (T.AttestationObject 'True) where
  type JSON (T.AttestationObject 'True) = Base64UrlString
  encode = Base64UrlString . B.encodeAttestationObject

instance MonadReader T.SupportedAttestationStatementFormats m => Decode m (T.AttestationObject 'True) where
  decode (Base64UrlString bytes) = do
    supportedFormats <- ask
    liftEither $ B.decodeAttestationObject supportedFormats bytes

instance Encode (T.AuthenticatorResponse 'K.Registration 'True) where
  type JSON (T.AuthenticatorResponse 'K.Registration 'True) = AuthenticatorAttestationResponse
  encode T.AuthenticatorResponseRegistration {..} =
    AuthenticatorAttestationResponse
      { clientDataJSON = encode arrClientData,
        attestationObject = encode arrAttestationObject,
        transports = Just $ encode arrTransports
      }

instance MonadReader T.SupportedAttestationStatementFormats m => Decode m (T.AuthenticatorResponse 'K.Registration 'True) where
  decode AuthenticatorAttestationResponse {..} = do
    arrClientData <- decode clientDataJSON
    arrAttestationObject <- decode attestationObject
    arrTransports <- case transports of
      Nothing -> pure []
      Just t -> decode t
    pure $ T.AuthenticatorResponseRegistration {..}

instance Encode T.AuthenticationExtensionsClientOutputs where
  type JSON T.AuthenticationExtensionsClientOutputs = Map Text Aeson.Value

  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.
  encode T.AuthenticationExtensionsClientOutputs {} = Map.empty

instance Decode m T.AuthenticationExtensionsClientOutputs where
  -- TODO: Extensions are not implemented by this library, see the TODO in the
  -- module documentation of `Crypto.WebAuthn.Model` for more information.
  decode _ = pure T.AuthenticationExtensionsClientOutputs {}

instance Encode (T.Credential 'K.Registration 'True) where
  type JSON (T.Credential 'K.Registration 'True) = PublicKeyCredential AuthenticatorAttestationResponse
  encode T.Credential {..} =
    PublicKeyCredential
      { rawId = encode cIdentifier,
        response = encode cResponse,
        clientExtensionResults = encode cClientExtensionResults
      }

instance MonadReader T.SupportedAttestationStatementFormats m => Decode m (T.Credential 'K.Registration 'True) where
  decode PublicKeyCredential {..} = do
    cIdentifier <- decode rawId
    cResponse <- decode response
    cClientExtensionResults <- decode clientExtensionResults
    pure $ T.Credential {..}

instance Encode T.CredentialDescriptor where
  type JSON T.CredentialDescriptor = PublicKeyCredentialDescriptor
  encode T.CredentialDescriptor {..} =
    PublicKeyCredentialDescriptor
      { littype = encode cdTyp,
        id = encode cdId,
        transports = encode cdTransports
      }

instance Decode m T.CredentialDescriptor where
  decode PublicKeyCredentialDescriptor {..} = do
    cdTyp <- decode littype
    cdId <- decode id
    cdTransports <- decode transports
    pure T.CredentialDescriptor {..}

instance Encode T.CredentialRpEntity where
  type JSON T.CredentialRpEntity = PublicKeyCredentialRpEntity
  encode T.CredentialRpEntity {..} =
    PublicKeyCredentialRpEntity
      { id = encode creId,
        name = encode creName
      }

instance Decode m T.CredentialRpEntity where
  decode PublicKeyCredentialRpEntity {..} = do
    creId <- decode id
    creName <- decode name
    pure $ T.CredentialRpEntity {..}

instance Encode T.CredentialUserEntity where
  type JSON T.CredentialUserEntity = PublicKeyCredentialUserEntity
  encode T.CredentialUserEntity {..} =
    PublicKeyCredentialUserEntity
      { id = encode cueId,
        displayName = encode cueDisplayName,
        name = encode cueName
      }

instance Decode m T.CredentialUserEntity where
  decode PublicKeyCredentialUserEntity {..} = do
    cueId <- decode id
    cueDisplayName <- decode displayName
    cueName <- decode name
    pure $ T.CredentialUserEntity {..}

newtype Base64UrlString = -- | base64url encoded buffersource as done by https://github.com/github/webauthn-json
  Base64UrlString {unBase64UrlString :: BS.ByteString}
  deriving (Show, Eq)

instance Aeson.FromJSON Base64UrlString where
  parseJSON = Aeson.withText "base64url" $ \t ->
    either fail (pure . Base64UrlString) (Base64Url.decode $ Text.encodeUtf8 t)

instance Aeson.ToJSON Base64UrlString where
  toJSON (Base64UrlString bs) = Aeson.String . Text.decodeUtf8 . Base64Url.encodeUnpadded $ bs

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
data PublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-rp)
    rp :: PublicKeyCredentialRpEntity,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-user)
    user :: PublicKeyCredentialUserEntity,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-challenge)
    challenge :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-pubkeycredparams)
    pubKeyCredParams :: [PublicKeyCredentialParameters],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-timeout)
    timeout :: Maybe Word32,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials)
    excludeCredentials :: Maybe [PublicKeyCredentialDescriptor],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-authenticatorselection)
    authenticatorSelection :: Maybe AuthenticatorSelectionCriteria,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-attestation)
    attestation :: Maybe Text,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-extensions)
    extensions :: Maybe (Map Text Aeson.Value)
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON PublicKeyCredentialCreationOptions where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON PublicKeyCredentialCreationOptions where
  toJSON = Aeson.genericToJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-rp-credential-params)
data PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrpentity-id)
    id :: Maybe Text,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    name :: Text
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON PublicKeyCredentialRpEntity where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON PublicKeyCredentialRpEntity where
  toJSON = Aeson.genericToJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-user-credential-params)
data PublicKeyCredentialUserEntity = PublicKeyCredentialUserEntity
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-id)
    id :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialuserentity-displayname)
    displayName :: Text,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialentity-name)
    name :: Text
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON PublicKeyCredentialUserEntity where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON PublicKeyCredentialUserEntity where
  toJSON = Aeson.genericToJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-credential-params)
data PublicKeyCredentialParameters = PublicKeyCredentialParameters
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-type)
    littype :: Text,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialparameters-alg)
    alg :: COSEAlgorithmIdentifier
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON PublicKeyCredentialParameters where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON PublicKeyCredentialParameters where
  toJSON = Aeson.genericToJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier)
type COSEAlgorithmIdentifier = Int32

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor)
data PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-type)
    littype :: Text,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-id)
    id :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialdescriptor-transports)
    transports :: Maybe [Text]
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON PublicKeyCredentialDescriptor where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON PublicKeyCredentialDescriptor where
  toJSON = Aeson.genericToJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria)
data AuthenticatorSelectionCriteria = AuthenticatorSelectionCriteria
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-authenticatorattachment)
    authenticatorAttachment :: Maybe Text,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
    residentKey :: Maybe Text,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
    requireResidentKey :: Maybe IDL.Boolean,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification)
    userVerification :: Maybe Text
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON AuthenticatorSelectionCriteria where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON AuthenticatorSelectionCriteria where
  toJSON = Aeson.genericToJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options)
data PublicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-challenge)
    challenge :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-timeout)
    timeout :: Maybe IDL.UnsignedLong,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-rpid)
    rpId :: Maybe Text,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials)
    allowCredentials :: Maybe [PublicKeyCredentialDescriptor],
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-userverification)
    userVerification :: Maybe Text,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-extensions)
    extensions :: Maybe (Map Text Aeson.Value)
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON PublicKeyCredentialRequestOptions where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON PublicKeyCredentialRequestOptions where
  toJSON = Aeson.genericToJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-pkcredential)
data PublicKeyCredential response = PublicKeyCredential
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-identifier-slot)
    rawId :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-response)
    response :: response,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredential-getclientextensionresults)
    clientExtensionResults :: Map Text Aeson.Value
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON response => Aeson.FromJSON (PublicKeyCredential response) where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON response => Aeson.ToJSON (PublicKeyCredential response) where
  toJSON = Aeson.genericToJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorattestationresponse)
data AuthenticatorAttestationResponse = AuthenticatorAttestationResponse
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
    clientDataJSON :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-attestationobject)
    attestationObject :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-transports-slot)
    -- This field is only being propagated by webauthn-json [since recently](https://github.com/github/webauthn-json/pull/44),
    -- which is why we allow absence of this value
    transports :: Maybe [IDL.DOMString]
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON AuthenticatorAttestationResponse where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON AuthenticatorAttestationResponse where
  toJSON = Aeson.genericToJSON jsonEncodingOptions

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#iface-authenticatorassertionresponse)
data AuthenticatorAssertionResponse = AuthenticatorAssertionResponse
  { -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson)
    clientDataJSON :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata)
    authenticatorData :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-signature)
    signature :: Base64UrlString,
    -- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-userhandle)
    userHandle :: Maybe Base64UrlString
  }
  deriving (Eq, Show, Generic)

instance Aeson.FromJSON AuthenticatorAssertionResponse where
  parseJSON = Aeson.genericParseJSON jsonEncodingOptions

instance Aeson.ToJSON AuthenticatorAssertionResponse where
  toJSON = Aeson.genericToJSON jsonEncodingOptions
