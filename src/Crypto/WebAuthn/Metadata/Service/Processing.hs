{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

module Crypto.WebAuthn.Metadata.Service.Processing
  ( RootCertificate (..),
    getPayload,
    jsonToPayload,
  )
where

import Control.Lens ((^.), (^?), _Just)
import Control.Monad.Except (ExceptT, throwError)
import Control.Monad.IO.Class (liftIO)
import Crypto.JOSE (fromX509Certificate)
import Crypto.JOSE.JWK.Store (VerificationKeyStore (getVerificationKeys))
import Crypto.JWT (Error (JWSInvalidSignature), HasX5c (x5c), JWSHeader, JWTError (JWSError), SignedJWT, decodeCompact, defaultJWTValidationSettings, param, unregisteredClaims, verifyClaims)
import Crypto.WebAuthn.Metadata.Service.Decode (decodeMetadataPayload)
import qualified Crypto.WebAuthn.Metadata.Service.Types as Service
import Data.Aeson (Value (Object))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LBS
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509

data RootCertificate = RootCertificate
  { -- | The root certificate itself
    rootCertificate :: X509.SignedCertificate,
    -- | The hostname it is for
    rootCertificateHostName :: X509.HostName
  }

instance VerificationKeyStore (ExceptT JWTError IO) (JWSHeader ()) p RootCertificate where
  getVerificationKeys header _ (RootCertificate rootCert hostName) = do
    -- TODO: Implement step 4 of the spec, which says to try to get the chain from x5u first before trying x5c
    -- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules
    chain <- case header ^? x5c . _Just . param of
      Nothing ->
        -- FIXME: Return a better error here, but we can't modify the jose libraries error type
        throwError $ JWSError JWSInvalidSignature
      Just chain -> return chain

    validationErrors <-
      liftIO $
        -- TODO: Check CRLs, see https://github.com/tweag/haskell-fido2/issues/23
        X509.validate
          -- TODO: Does the SHA256 choice matter here?
          -- I think it's probably only for the cache, which we don't use
          X509.HashSHA256
          X509.defaultHooks
          X509.defaultChecks
          (X509.makeCertificateStore [rootCert])
          (X509.exceptionValidationCache [])
          (hostName, "")
          (X509.CertificateChain (NE.toList chain))

    case validationErrors of
      [] -> do
        -- Create a JWK from the leaf certificate, which is used to sign the payload
        jwk <- fromX509Certificate (NE.head chain)
        return [jwk]
      _errors ->
        -- FIXME: We're currently discarding these errors by necessity, because we're bound by the JOSE libraries error type
        throwError $ JWSError JWSInvalidSignature

-- | Decodes and verifies a FIDO Metadata Service blob according to https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
getPayload ::
  -- | The bytes of the blob
  LBS.ByteString ->
  -- | The root certificate the blob is signed with
  RootCertificate ->
  ExceptT JWTError IO Value
getPayload blob rootCert = do
  jwt :: SignedJWT <- decodeCompact blob
  claims <- verifyClaims (defaultJWTValidationSettings (const True)) rootCert jwt
  return $ Object (claims ^. unregisteredClaims)

-- | Decodes a FIDO Metadata payload JSON value to a 'Service.MetadataPayload',
-- returning an error when the JSON is invalid, and ignoring any entries not
-- relevant for webauthn
jsonToPayload :: Value -> Either Text Service.MetadataPayload
jsonToPayload value = case Aeson.fromJSON value of
  Aeson.Error err -> Left $ Text.pack err
  Aeson.Success payload -> case decodeMetadataPayload payload of
    Left err -> Left err
    Right result -> pure result
