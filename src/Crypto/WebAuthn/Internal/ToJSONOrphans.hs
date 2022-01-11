{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-orphans #-}

-- | This module contain some useful orphan 'ToJSON' instances for pretty-printing values from third-party libraries
module Crypto.WebAuthn.Internal.ToJSONOrphans () where

import Crypto.Hash (Digest)
import qualified Crypto.PubKey.ECC.Types as ECC
import Data.ASN1.Types (ASN1Object)
import qualified Data.ASN1.Types as ASN1
import Data.Aeson (ToJSON, Value (String), object, toJSON, (.=))
import Data.Aeson.Types (Pair)
import Data.ByteArray (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.Hourglass as HG
import Data.List (intercalate)
import Data.Maybe (fromMaybe, mapMaybe)
import Data.String (fromString)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509

instance ToJSON BS.ByteString where
  toJSON = String . Text.decodeUtf8 . Base16.encode

instance ToJSON (Digest h) where
  toJSON = String . Text.decodeUtf8 . Base16.encode . convert

instance (Eq a, Show a, ASN1Object a, ToJSON a) => ToJSON (X509.SignedExact a) where
  toJSON = toJSON . X509.signedObject . X509.getSigned

instance ToJSON X509.Certificate where
  toJSON X509.Certificate {..} =
    object
      [ "certIssuerDN" .= certIssuerDN,
        "certValidity"
          .= object
            [ "notBefore" .= fst certValidity,
              "notAfter" .= snd certValidity
            ],
        "certSubjectDN" .= certSubjectDN,
        "certExtensions" .= certExtensions
      ]

instance ToJSON X509.FailedReason where
  toJSON = String . Text.pack . show

instance ToJSON X509.Extensions where
  toJSON (X509.Extensions raws) = toJSON $ fromMaybe [] raws

instance ToJSON X509.ExtensionRaw where
  toJSON X509.ExtensionRaw {..} =
    object
      [ "extRawOID" .= oidToJSON extRawOID,
        "extRawContent" .= extRawContent
      ]

instance ToJSON ECC.CurveName where
  toJSON = String . Text.pack . show

oidToJSON :: ASN1.OID -> Value
oidToJSON oid = String $ Text.pack $ intercalate "." $ map show oid

instance ToJSON HG.DateTime where
  toJSON = String . Text.pack . HG.timePrint HG.ISO8601_DateAndTime

instance ToJSON HG.Date where
  toJSON = String . Text.pack . HG.timePrint HG.ISO8601_Date

instance ToJSON X509.DistinguishedName where
  toJSON dn = object $ mapMaybe getPair dnElements
    where
      getPair :: X509.DnElement -> Maybe Pair
      getPair el = do
        asnStr <- X509.getDnElement el dn
        str <- ASN1.asn1CharacterToString asnStr
        let key = fromString $ show el
            value = String $ Text.pack str
        pure (key, value)

      dnElements :: [X509.DnElement]
      dnElements =
        [ X509.DnCommonName,
          X509.DnCountry,
          X509.DnOrganization,
          X509.DnOrganizationUnit,
          X509.DnEmailAddress
        ]
