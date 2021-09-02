{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.Fido2.MDS where

import Data.Aeson
import Data.Aeson.Types
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Map as Map
import Data.Scientific
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding
import Data.Time
import Data.Time.Format.ISO8601
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Network.HTTP.Types.Status (statusCode)
import qualified Web.JWT as JWT

data MDSSource = Prefetched Text | Fetched Request

data MDS = MDS
  { mdsNumber :: Int,
    mdsNextUpdate :: Day,
    mdsLegalHeader :: Text,
    mdsEntries :: Value
  }
  deriving (Show)

data MDSError
  = MDSErrorJWTDecodingFailed
  | MDSErrorClaimMissing Text
  | MDSErrorClaimDecoding Text Value String
  deriving (Show)

-- Stolen from https://hackage.haskell.org/package/either
maybeToRight :: a -> Maybe b -> Either a b
maybeToRight _ (Just x) = Right x
maybeToRight y Nothing = Left y

getClaim :: Text -> JWT.ClaimsMap -> (Value -> Parser a) -> Either MDSError a
getClaim field (JWT.ClaimsMap claims) parser = case Map.lookup field claims of
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

data MDSEntry = MDSEntry
  { aaid :: Text,
    aaguid :: Int,
    attestationCertificateKeyIdentifiers :: [Text],
    timeOfLastStatusChange :: Day,
    statusReports :: Int,
    metadataStatement :: Int
  }

-- TODO: Use Either
decodeMDS :: Text -> Either MDSError MDS
decodeMDS body = do
  jwt <- maybeToRight MDSErrorJWTDecodingFailed $ JWT.decode body
  let claims = JWT.unregisteredClaims $ JWT.claims jwt
  number <- getClaim "no" claims (withScientific "no" parseBoundedIntegralFromScientific)
  nextUpdate <- getClaim "nextUpdate" claims (withText "nextUpdate" $ iso8601ParseM . Text.unpack)
  legalHeader <- getClaim "legalHeader" claims (withText "legalHeader" pure)
  entries <- getClaim "entries" claims pure
  return
    MDS
      { mdsNumber = number,
        mdsNextUpdate = nextUpdate,
        mdsLegalHeader = legalHeader,
        mdsEntries = entries
      }

prefetchedTest :: IO (Either MDSError MDS)
prefetchedTest = do
  contents <- BS.readFile "mds.jwt"
  let body = decodeUtf8 contents
  return $ decodeMDS body

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
