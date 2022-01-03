{-# LANGUAGE ScopedTypeVariables #-}

module MetadataFetch
  ( continuousFetch,
    fetchRegistry,
    registryFromJsonFile,
    MetadataFetchError (..),
  )
where

import Control.Concurrent (ThreadId, forkIO, threadDelay)
import Control.Concurrent.STM (TVar, atomically, modifyTVar)
import Control.Exception (Exception, throwIO)
import Control.Monad (forever)
import Crypto.JWT (JWTError)
import Crypto.WebAuthn.Metadata.Service.Decode (decodeMetadataEntry)
import qualified Crypto.WebAuthn.Metadata.Service.IDL as Service
import Crypto.WebAuthn.Metadata.Service.Processing (createMetadataRegistry, fidoAllianceRootCertificate, jsonToPayload, jwtToJson)
import qualified Crypto.WebAuthn.Metadata.Service.Types as Service
import Data.Aeson (eitherDecodeFileStrict)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.List.NonEmpty as NE
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import Network.HTTP.Client (Manager, httpLbs, responseBody)
import Network.HTTP.Client.TLS (newTlsManager)
import System.Hourglass (dateCurrent)

-- | Reads metadata entries from a JSON list. See extra-entries.json for an example
registryFromJsonFile :: FilePath -> IO Service.MetadataServiceRegistry
registryFromJsonFile path = do
  values <-
    eitherDecodeFileStrict path >>= \case
      Left err -> fail $ "Failed to decode JSON file " <> path <> " into a list: " <> err
      Right (values :: [Service.MetadataBLOBPayloadEntry]) -> pure values
  entries <- case sequence (mapMaybe decodeMetadataEntry values) of
    Left err -> fail $ "Failed to decode an metadata entry from file " <> path <> ": " <> Text.unpack err
    Right decodedEntries -> pure $ foldMap NE.toList decodedEntries
  pure $ createMetadataRegistry entries

-- | Continuously fetches the FIDO Metadata and updates a 'TVar' with the decoded results
-- New entries are added to the TVar, entries are not removed if no longer present in the Metadata.
continuousFetch :: TVar Service.MetadataServiceRegistry -> IO ThreadId
continuousFetch var = do
  manager <- newTlsManager
  registry <- fetchRegistry manager
  atomically $ modifyTVar var (<> registry)
  threadId <- forkIO $ forever $ sleepThenUpdate manager var
  pure threadId
  where
    -- 1 hour delay for testing purposes. In reality this only needs to happen perhaps once a month, see also the 'Service.mpNextUpdate' field
    delay :: Int
    delay = 60 * 60 * 1000 * 1000

    sleepThenUpdate :: Manager -> TVar Service.MetadataServiceRegistry -> IO ()
    sleepThenUpdate manager var = do
      putStrLn $ "Sleeping for " <> show (delay `div` (1000 * 1000)) <> " seconds"
      threadDelay delay
      registry <- fetchRegistry manager
      atomically $ modifyTVar var (<> registry)

data MetadataFetchError
  = JWTProcessingFailed JWTError
  | JSONDecodingFailed Text
  deriving (Show, Exception)

fetchBlob :: Manager -> IO BS.ByteString
fetchBlob manager = do
  putStrLn "Fetching Metadata"
  response <- httpLbs "https://mds.fidoalliance.org" manager
  pure $ LBS.toStrict $ responseBody response

fetchRegistry :: Manager -> IO Service.MetadataServiceRegistry
fetchRegistry manager = do
  blobBytes <- fetchBlob manager
  now <- dateCurrent
  case jwtToJson blobBytes fidoAllianceRootCertificate now of
    Left err -> throwIO $ JWTProcessingFailed err
    Right value -> case jsonToPayload value of
      Left err -> throwIO $ JSONDecodingFailed err
      Right result -> return $ createMetadataRegistry $ Service.mpEntries result
