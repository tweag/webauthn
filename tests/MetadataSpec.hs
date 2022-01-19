{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module MetadataSpec (spec) where

import Crypto.WebAuthn.Metadata.Service.Processing (RootCertificate (RootCertificate), fidoAllianceRootCertificate, jsonToPayload, jwtToJson)
import Crypto.WebAuthn.Metadata.Service.WebIDL (MetadataBLOBPayload)
import Data.Aeson (Result (Success), ToJSON (toJSON), Value (Object), decodeFileStrict, fromJSON)
import Data.Aeson.Types (Result (Error))
import qualified Data.ByteString as BS
import Data.Either (isRight)
import qualified Data.PEM as PEM
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8)
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import System.Hourglass (dateCurrent)
import Test.Hspec (SpecWith, describe, it, shouldSatisfy)
import Test.Hspec.Expectations.Json (shouldBeUnorderedJson)

golden :: FilePath -> SpecWith ()
golden subdir = describe subdir $ do
  it "can verify and extract the blob payload" $ do
    origin <- Text.unpack . Text.strip . decodeUtf8 <$> BS.readFile ("tests/golden-metadata/" <> subdir <> "/origin")

    certBytes <- BS.readFile $ "tests/golden-metadata/" <> subdir <> "/root.crt"
    let Right [PEM.pemContent -> pem] = PEM.pemParseBS certBytes
        Right cert = X509.decodeSignedCertificate pem
        store = X509.makeCertificateStore [cert]

    blobBytes <- BS.readFile $ "tests/golden-metadata/" <> subdir <> "/blob.jwt"
    now <- dateCurrent
    let Right result = jwtToJson blobBytes (RootCertificate store origin) now

    Just expectedPayload <- decodeFileStrict $ "tests/golden-metadata/" <> subdir <> "/payload.json"

    Object result `shouldBeUnorderedJson` expectedPayload

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
spec = do
  describe "Golden" $ do
    golden "small"
    golden "big"
  describe "fidoAllianceRootCertificate" $ do
    it "can validate the payload" $ do
      blobBytes <- BS.readFile "tests/golden-metadata/big/blob.jwt"
      now <- dateCurrent
      jwtToJson blobBytes fidoAllianceRootCertificate now `shouldSatisfy` isRight
