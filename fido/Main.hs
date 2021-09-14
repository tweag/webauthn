{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}

module Main (main) where

import Control.Lens (preview, _Just)
import Control.Monad.Except (ExceptT, MonadError (throwError), MonadIO (liftIO), runExceptT, withExceptT)
--import qualified Crypto.JOSE.Types as JWT
--import qualified Crypto.JWT as JWT

--import qualified Crypto.JOSE.JWS as JWS
--import qualified Crypto.JOSE.Types as JWS

import Crypto.JOSE.JWK.Store (VerificationKeyStore (getVerificationKeys))
import Crypto.JWT (CompactJWS, Error (JWSInvalidSignature), HasX5c (x5c), JWSHeader, JWTError (JWSError), VerificationKeyStore, decodeCompact, defaultValidationSettings, fromX509Certificate, param, verifyJWS, verifyJWS')
import Data.ASN1.Types (asn1CharacterToString)
import qualified Data.Aeson as Aeson
import Data.Aeson.Types
  ( FromJSON (parseJSON),
    Options (constructorTagModifier, fieldLabelModifier),
    Parser,
    Result (Error, Success),
    ToJSON (toJSON),
    Value,
    camelTo2,
    defaultOptions,
    genericParseJSON,
    parse,
  )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Char (toLower, toUpper)
import qualified Data.HashMap.Strict as HM
import Data.List (stripPrefix)
import Data.List.NonEmpty (NonEmpty)
import qualified Data.List.NonEmpty as NE
import Data.Map (Map)
import Data.Maybe (mapMaybe)
import Data.PEM as PEM (PEM (pemContent), pemParseLBS)
import Data.Scientific (Scientific, toBoundedInteger)
import Data.Text (Text)
import Data.Time (Day)
import Data.Word (Word16, Word32, Word64, Word8)
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509
import Debug.Trace (trace)
import GHC.Generics (Generic (Rep))
import Network.HTTP.Client (Request)

data MDSError
  = MDSErrorJWT JWTError
  | MDSErrorClaimDecoding Text Value String
  | MDSErrorClaimMissing Text
  deriving (Show)

data MDSSource = Prefetched Text | Fetched Request

-- Stolen from https://hackage.haskell.org/package/either
maybeToRight :: a -> Maybe b -> Either a b
maybeToRight _ (Just x) = Right x
maybeToRight y Nothing = Left y

getClaim :: Text -> HM.HashMap Text Value -> (Value -> Parser a) -> Either MDSError a
getClaim field claims parser = case HM.lookup field claims of
  Nothing -> Left $ MDSErrorClaimMissing field
  Just value -> case parse parser value of
    Error err -> Left $ MDSErrorClaimDecoding field value err
    Success result -> Right result

parseBoundedIntegralFromScientific :: (Bounded a, Integral a) => Scientific -> Parser a
parseBoundedIntegralFromScientific s =
  maybe
    (fail $ "value is either floating or will cause over or underflow " ++ show s)
    pure
    (toBoundedInteger s)

newtype PublicKeyIdentifier = PublicKeyIdentifier BS.ByteString

-- TODO: Make this contain the root certificate
newtype Chain = Chain X509.SignedCertificate

getNames :: X509.Certificate -> (Maybe String, [String])
getNames cert = (commonName >>= asn1CharacterToString, altNames)
  where
    commonName = X509.getDnElement X509.DnCommonName $ X509.certSubjectDN cert
    altNames = maybe [] toAltName $ X509.extensionGet $ X509.certExtensions cert
    toAltName (X509.ExtSubjectAltName names) = mapMaybe unAltName names
      where
        unAltName (X509.AltNameDNS s) = Just s
        unAltName _ = Nothing

instance VerificationKeyStore (ExceptT JWTError IO) (JWSHeader ()) LBS.ByteString Chain where
  getVerificationKeys header _ (Chain rootCert) = do
    -- TODO Handle pattern mismatch, and the spec says to also check x5u
    let Just (NE.toList -> x) = preview (x5c . _Just . param) header

    let hooks =
          X509.defaultHooks
            { X509.hookValidateName = \host cert -> trace ("Host is " ++ host ++ ", names are " ++ show (getNames cert)) $ X509.hookValidateName X509.defaultHooks host cert
            }
        store = X509.makeCertificateStore [rootCert]
        cache = X509.exceptionValidationCache []
    -- TODO: Does the SHA256 choice matter here?
    result <- liftIO $ X509.validate X509.HashSHA256 hooks X509.defaultChecks store cache ("mds.fidoalliance.org", "") (X509.CertificateChain x)
    case result of
      [] -> do
        --let pem = PEM.PEM "CERTIFICATE" [] (X509.encodeSignedObject $ head x)
        -- TODO: Verify chain
        res <- fromX509Certificate (head x)
        return [res]
      --trace ("Got result: " ++ show result) $ trace (Text.unpack $ Text.decodeUtf8 $ LBS.toStrict $ PEM.pemWriteLBS pem) $
      errors ->
        trace (show errors) $ throwError $ JWSError JWSInvalidSignature

decodeJWTPayload :: LBS.ByteString -> X509.SignedCertificate -> ExceptT JWTError IO LBS.ByteString
decodeJWTPayload bytes rootCert = do
  jws :: CompactJWS JWSHeader <- decodeCompact bytes
  verifyJWS' (Chain rootCert) jws

--let x = jws ^. JWT.jwsHeader ^. JWT.x5c
--key <- JWT.fromX509Certificate cert

-- TODO: Use Either
decodeMDS :: LBS.ByteString -> X509.SignedCertificate -> ExceptT MDSError IO LBS.ByteString
decodeMDS body cert =
  withExceptT MDSErrorJWT $ decodeJWTPayload body cert

--undefined <- JWT.decodeCompact body

--jwt <- maybeToRight MDSErrorJWTDecodingFailed $ JWT.decodeAndVerifySignature undefined body
--let claims = JWT.unregisteredClaims $ JWT.claims jwt
--let claims = undefined
--number <- getClaim "no" claims (withScientific "no" parseBoundedIntegralFromScientific)
--nextUpdate <- getClaim "nextUpdate" claims (withText "nextUpdate" $ iso8601ParseM . Text.unpack)
--legalHeader <- getClaim "legalHeader" claims (withText "legalHeader" pure)
--entries <- getClaim "entries" claims parseJSON
--return
--  MetadataBlobPayload
--    { mdsNumber = number,
--      mdsNextUpdate = nextUpdate,
--      mdsLegalHeader = legalHeader,
--      mdsEntries = entries
--    }

--
-- TODO: Follow this:
-- https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules
--prefetchedTest :: IO (Either MDSError MetadataBlobPayload)
-- FIXME: The jwt library isn't very compliant and doesn't implement everything we need.
-- Use the jose library instead, and specifically Crypto.JOSE.JWK.fromX509Certificate to generate the JWK needed to verify the signature
main :: IO ()
main = do
  putStrLn "Reading contents"
  contents <- LBS.readFile "mds.jwt"
  putStrLn "Reading cert"
  certBytes <- LBS.readFile "root-cert.crt"
  let Right [PEM.pemContent -> pem] = PEM.pemParseLBS certBytes
  let Right cert = X509.decodeSignedCertificate pem
  putStrLn "Cert decoding successful"
  res <- runExceptT $ decodeMDS contents cert
  case res of
    Left err -> print err
    Right payload -> do
      putStrLn "Successfully got payload, writing to output.json"
      LBS.writeFile "output.json" payload

newtype EncodingRules a = EncodingRules a

options :: Aeson.Options
options =
  Aeson.defaultOptions
    { Aeson.fieldLabelModifier = \x ->
        if x == "typ"
          then "type"
          else x,
      Aeson.omitNothingFields = True
    }

instance (Aeson.GToJSON Aeson.Zero (Rep a), Generic a) => ToJSON (EncodingRules a) where
  toJSON (EncodingRules a) = Aeson.genericToJSON options a

instance (Aeson.GFromJSON Aeson.Zero (Rep a), Generic a) => FromJSON (EncodingRules a) where
  parseJSON o = EncodingRules <$> Aeson.genericParseJSON options o

--fetchingTest :: IO ()
--fetchingTest = do
--  manager <- newManager tlsManagerSettings
--
--  request <- parseRequest "https://mds.fidoalliance.org/"
--  putStrLn "Making request"
--  response <- httpLbs request manager
--  putStrLn "Done"
--  putStrLn $ "The status code was: " ++ (show $ statusCode $ responseStatus response)
--
--  let body = decodeUtf8 $ LBS.toStrict $ responseBody response
--  decodeMDS body
