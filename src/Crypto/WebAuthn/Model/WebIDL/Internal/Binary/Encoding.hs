{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Stability: internal
-- Certain parts of the specification require that data is encoded to a
-- binary form. This module holds such functions.
module Crypto.WebAuthn.Model.WebIDL.Internal.Binary.Encoding
  ( -- * Encoding raw fields
    encodeRawCredential,
    encodeRawAuthenticatorData,
    encodeRawCollectedClientData,

    -- * Encoding structures to bytes
    encodeAttestationObject,
    encodeCollectedClientData,
  )
where

import qualified Codec.CBOR.Term as CBOR
import qualified Codec.CBOR.Write as CBOR
import Codec.Serialise (Serialise (encode))
import Crypto.WebAuthn.Model.Identifier (AAGUID (unAAGUID))
import qualified Crypto.WebAuthn.Model.Kinds as K
import qualified Crypto.WebAuthn.Model.Types as M
import qualified Data.Aeson as Aeson
import qualified Data.Binary.Put as Binary
import Data.Bits ((.|.))
import qualified Data.Bits as Bits
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as Base64Url
import Data.ByteString.Builder (Builder, stringUtf8, toLazyByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Singletons (SingI, sing)
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8)
import qualified Data.UUID as UUID
import Data.Word (Word16, Word8)

-- | Encodes all raw fields of a 'M.Credential'. This function is
-- mainly useful for testing that the encoding/decoding functions are correct.
-- The counterpart to this function is 'Crypto.WebAuthn.Model.Binary.Decoding.stripRawCredential'
encodeRawCredential :: forall c raw. SingI c => M.Credential c raw -> M.Credential c 'True
encodeRawCredential M.Credential {..} =
  M.Credential
    { cResponse = case sing @c of
        K.SRegistration -> encodeRawAuthenticatorResponseRegistration cResponse
        K.SAuthentication -> encodeRawAuthenticatorResponseAuthentication cResponse,
      ..
    }
  where
    encodeRawAuthenticatorResponseAuthentication :: M.AuthenticatorResponse 'K.Authentication raw -> M.AuthenticatorResponse 'K.Authentication 'True
    encodeRawAuthenticatorResponseAuthentication M.AuthenticatorResponseAuthentication {..} =
      M.AuthenticatorResponseAuthentication
        { araClientData = encodeRawCollectedClientData araClientData,
          araAuthenticatorData = encodeRawAuthenticatorData araAuthenticatorData,
          ..
        }

    encodeRawAuthenticatorResponseRegistration :: M.AuthenticatorResponse 'K.Registration raw -> M.AuthenticatorResponse 'K.Registration 'True
    encodeRawAuthenticatorResponseRegistration M.AuthenticatorResponseRegistration {..} =
      M.AuthenticatorResponseRegistration
        { arrClientData = encodeRawCollectedClientData arrClientData,
          arrAttestationObject = encodeRawAttestationObject arrAttestationObject,
          ..
        }

    encodeRawAttestationObject :: M.AttestationObject raw -> M.AttestationObject 'True
    encodeRawAttestationObject M.AttestationObject {..} =
      M.AttestationObject
        { aoAuthData = encodeRawAuthenticatorData aoAuthData,
          ..
        }

-- | Encodes all raw fields of a 'M.AuthenticatorData'. This function is needed
-- for an authenticator implementation
encodeRawAuthenticatorData :: forall c raw. SingI c => M.AuthenticatorData c raw -> M.AuthenticatorData c 'True
encodeRawAuthenticatorData M.AuthenticatorData {..} =
  M.AuthenticatorData
    { adRawData = M.WithRaw bytes,
      adAttestedCredentialData = rawAttestedCredentialData,
      ..
    }
  where
    rawAttestedCredentialData = encodeRawAttestedCredentialData adAttestedCredentialData

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
               K.SRegistration -> encodeAttestedCredentialData rawAttestedCredentialData
               K.SAuthentication -> mempty
           )
        <> maybe mempty encodeExtensions adExtensions

    encodeExtensions :: M.AuthenticatorExtensionOutputs -> Builder
    encodeExtensions M.AuthenticatorExtensionOutputs {} = CBOR.toBuilder $ CBOR.encodeTerm (CBOR.TMap [])

    -- https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
    encodeAttestedCredentialData :: M.AttestedCredentialData 'K.Registration 'True -> Builder
    encodeAttestedCredentialData M.AttestedCredentialData {..} =
      Binary.execPut (Binary.putLazyByteString $ UUID.toByteString $ unAAGUID acdAaguid)
        <> Binary.execPut (Binary.putWord16be credentialLength)
        <> Binary.execPut (Binary.putByteString $ M.unCredentialId acdCredentialId)
        <> Binary.execPut (Binary.putByteString $ M.unRaw acdCredentialPublicKeyBytes)
      where
        credentialLength :: Word16
        credentialLength = fromIntegral $ BS.length $ M.unCredentialId acdCredentialId

    encodeRawAttestedCredentialData :: forall c raw. SingI c => M.AttestedCredentialData c raw -> M.AttestedCredentialData c 'True
    encodeRawAttestedCredentialData = case sing @c of
      K.SRegistration -> \M.AttestedCredentialData {..} ->
        M.AttestedCredentialData
          { acdCredentialPublicKeyBytes =
              M.WithRaw $ LBS.toStrict $ CBOR.toLazyByteString $ encode acdCredentialPublicKey,
            ..
          }
      K.SAuthentication -> \M.NoAttestedCredentialData -> M.NoAttestedCredentialData

-- | Encodes all raw fields of a 'M.CollectedClientData'. This function is
-- needed for a client implementation
encodeRawCollectedClientData :: forall c raw. SingI c => M.CollectedClientData c raw -> M.CollectedClientData c 'True
encodeRawCollectedClientData M.CollectedClientData {..} = M.CollectedClientData {..}
  where
    ccdRawData = M.WithRaw $ LBS.toStrict $ toLazyByteString builder

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
    crossOriginValue = ccdCrossOrigin

    jsonBuilder :: Aeson.ToJSON a => a -> Builder
    jsonBuilder = Aeson.fromEncoding . Aeson.toEncoding

-- | Encodes an 'M.AttestationObject' as a 'BS.ByteString'. This is needed by
-- the client side to generate a valid JSON response
encodeAttestationObject :: M.AttestationObject 'True -> BS.ByteString
encodeAttestationObject M.AttestationObject {..} = CBOR.toStrictByteString $ CBOR.encodeTerm term
  where
    -- https://www.w3.org/TR/webauthn-2/#sctn-generating-an-attestation-object
    term :: CBOR.Term
    term =
      CBOR.TMap
        [ (CBOR.TString "authData", CBOR.TBytes $ M.unRaw $ M.adRawData aoAuthData),
          (CBOR.TString "fmt", CBOR.TString $ M.asfIdentifier aoFmt),
          (CBOR.TString "attStmt", M.asfEncode aoFmt aoAttStmt)
        ]

-- | Encodes an 'M.CollectedClientData' as a 'BS.ByteString'. This is needed by
-- the client side to generate a valid JSON response
encodeCollectedClientData :: forall c. SingI c => M.CollectedClientData c 'True -> BS.ByteString
encodeCollectedClientData M.CollectedClientData {..} = M.unRaw ccdRawData
