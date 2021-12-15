{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module MetadataSpec (spec) where

import Crypto.WebAuthn.Metadata.Service.IDL (MetadataBLOBPayload)
import Crypto.WebAuthn.Metadata.Service.Processing (RootCertificate (RootCertificate), jsonToPayload, jwtToJson)
import Data.Aeson (Result (Success), ToJSON (toJSON), decodeFileStrict, fromJSON)
import Data.Aeson.Types (Result (Error))
import qualified Data.ByteString as BS
import qualified Data.PEM as PEM
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8)
import qualified Data.X509 as X509
import System.Hourglass (dateCurrent)
import Test.Hspec (SpecWith, describe, it)
import Test.Hspec.Expectations.Json (shouldBeUnorderedJson)

golden :: FilePath -> SpecWith ()
golden subdir = describe subdir $ do
  -- TODO: Property tests: Generate random metadata, encode and sign it, decode and verify it, make sure it's the same result
  it "can verify and extract the blob payload" $ do
    origin <- Text.unpack . Text.strip . decodeUtf8 <$> BS.readFile ("tests/golden-metadata/" <> subdir <> "/origin")

    certBytes <- BS.readFile $ "tests/golden-metadata/" <> subdir <> "/root.crt"
    let Right [PEM.pemContent -> pem] = PEM.pemParseBS certBytes
        Right cert = X509.decodeSignedCertificate pem

    blobBytes <- BS.readFile $ "tests/golden-metadata/" <> subdir <> "/blob.jwt"
    now <- dateCurrent
    let Right result = jwtToJson blobBytes (RootCertificate cert origin) now

    Just expectedPayload <- decodeFileStrict $ "tests/golden-metadata/" <> subdir <> "/payload.json"

    result `shouldBeUnorderedJson` expectedPayload

  it "can decode and reencode the payload to the partially parsed JSON" $ do
    Just payload <- decodeFileStrict $ "tests/golden-metadata/" <> subdir <> "/payload.json"
    case fromJSON payload of
      Error err -> fail err
      Success (value :: MetadataBLOBPayload) ->
        toJSON value `shouldBeUnorderedJson` payload

  it "can decode and reencode the payload to the partially parsed JSON" $ do
    Just value <- decodeFileStrict $ "tests/golden-metadata/" <> subdir <> "/payload.json"
    case jsonToPayload value of
      Left err -> fail $ show err
      Right _result -> pure ()

spec :: SpecWith ()
spec = describe "Golden" $ do
  golden "small"
  golden "big"
