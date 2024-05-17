{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module MetadataSpec (spec) where

import Crypto.WebAuthn.Metadata (metadataBlobToRegistry)
import Crypto.WebAuthn.Metadata.Service.Processing (ProcessingError, RootCertificate (RootCertificate), fidoAllianceRootCertificate, jwtToAdditionalData)
import Crypto.WebAuthn.Metadata.Service.WebIDL (MetadataBLOBPayload)
import Data.Aeson (Result (Success), ToJSON (toJSON), decodeFileStrict, fromJSON)
import Data.Aeson.Types (Result (Error))
import qualified Data.ByteString as BS
import Data.Either (isRight)
import qualified Data.PEM as PEM
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8)
import Data.These (These (These))
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import Spec.Util (predeterminedDateTime)
import Test.Hspec (SpecWith, describe, it, shouldSatisfy)
import Test.Hspec.Expectations.Json (shouldBeUnorderedJson)

golden :: FilePath -> SpecWith ()
golden subdir = describe subdir $ do
  it "can verify and extract the blob payload" $ do
    origin <- Text.unpack . Text.strip . decodeUtf8 <$> BS.readFile ("tests/golden-metadata/" <> subdir <> "/origin.txt")

    certBytes <- BS.readFile $ "tests/golden-metadata/" <> subdir <> "/root.crt"
    let Right [PEM.pemContent -> pem] = PEM.pemParseBS certBytes
        Right cert = X509.decodeSignedCertificate pem
        store = X509.makeCertificateStore [cert]

    blobBytes <- BS.readFile $ "tests/golden-metadata/" <> subdir <> "/blob.jwt"
    let Right result = jwtToAdditionalData blobBytes (RootCertificate store origin) predeterminedDateTime

    Just expectedPayload <- decodeFileStrict $ "tests/golden-metadata/" <> subdir <> "/payload.json"

    toJSON (result :: MetadataBLOBPayload) `shouldBeUnorderedJson` expectedPayload

  it "can decode and reencode the payload to the partially parsed JSON" $ do
    Just payload <- decodeFileStrict $ "tests/golden-metadata/" <> subdir <> "/payload.json"
    case fromJSON payload of
      Error err -> fail err
      Success (value :: MetadataBLOBPayload) ->
        toJSON value `shouldBeUnorderedJson` payload

spec :: SpecWith ()
spec = do
  describe "Golden" $ do
    golden "small"
    golden "big"
  describe "fidoAllianceRootCertificate" $ do
    it "can validate the payload" $ do
      blobBytes <- BS.readFile "tests/golden-metadata/big/blob.jwt"
      let metadata = jwtToAdditionalData blobBytes fidoAllianceRootCertificate predeterminedDateTime :: Either ProcessingError MetadataBLOBPayload
      metadata `shouldSatisfy` isRight
  describe "MDS with errors" $ do
    it "can process an MDS file with errors" $ do
      blobBytes <- BS.readFile "tests/golden-metadata/big/blob-with-errors.jwt"
      case metadataBlobToRegistry blobBytes predeterminedDateTime of
        Right (These _errs _res) -> pure ()
        Right _thisThat -> error "Expected parsing errors as well as registry"
        Left err -> error $ Text.unpack err
