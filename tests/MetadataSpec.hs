{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module MetadataSpec (spec) where

import Control.Monad.Except (runExceptT)
import Crypto.Fido2.Metadata.Service.IDL (MetadataBLOBPayload)
import Crypto.Fido2.Metadata.Service.Processing (RootCertificate (RootCertificate), getPayload)
import Data.Aeson (Result (Success), ToJSON (toJSON), decodeFileStrict, fromJSON)
import Data.Aeson.Types (Result (Error))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.PEM as PEM
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8)
import qualified Data.X509 as X509
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

    blobBytes <- LBS.readFile $ "tests/golden-metadata/" <> subdir <> "/blob.jwt"
    Right result <- runExceptT $ getPayload blobBytes (RootCertificate cert origin)

    Just expectedPayload <- decodeFileStrict $ "tests/golden-metadata/" <> subdir <> "/payload.json"

    result `shouldBeUnorderedJson` expectedPayload

  it "can decode and reencode the payload" $ do
    Just payload <- decodeFileStrict $ "tests/golden-metadata/" <> subdir <> "/payload.json"
    case fromJSON payload of
      Error err -> fail err
      Success (value :: MetadataBLOBPayload) ->
        toJSON value `shouldBeUnorderedJson` payload

spec :: SpecWith ()
spec = describe "Golden" $ do
  golden "small"
  golden "big"
