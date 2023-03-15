-- | Stability: experimental
-- A function for decoding a [FIDO Alliance Metadata Service](https://fidoalliance.org/metadata/)
-- BLOB in order to be able to enforce a set of requirements on the authenticator
-- used, e.g. to only allow authenticators that have been
-- [FIDO certified](https://fidoalliance.org/certification/functional-certification/).
module Crypto.WebAuthn.Metadata
  ( metadataBlobToRegistry,
    Service.MetadataServiceRegistry,
  )
where

import qualified Crypto.WebAuthn.Metadata.Service.Processing as Service
import qualified Crypto.WebAuthn.Metadata.Service.Types as Service
import qualified Data.ByteString as BS
import qualified Data.Hourglass as HG
import Data.Text (Text)
import qualified Data.Text as Text
import Data.These (These)
import Data.Bifunctor (first, Bifunctor (second))
import qualified Data.List.NonEmpty as NE

-- | Verifies, decodes and extracts a 'Service.MetadataServiceRegistry' from a
-- [FIDO Alliance Metadata Service](https://fidoalliance.org/metadata/) BLOB.
-- The result can be passed to 'Crypto.WebAuthn.Operation.Registration.verifyRegistrationResponse'.
metadataBlobToRegistry ::
  -- | A Metadata BLOB fetched from <https://mds.fidoalliance.org>
  BS.ByteString ->
  -- | The time at which it was fetched
  HG.DateTime ->
  -- | Either a certifcate error or a list of errors, a registry of metadata entries or both where the MDS has bad entries
  Either Text (These (NE.NonEmpty Text) Service.MetadataServiceRegistry)
metadataBlobToRegistry bytes now = do
  json <- first (Text.pack . show) (Service.jwtToJson bytes Service.fidoAllianceRootCertificate now)
  let payload = Service.jsonToPayload json
  pure $ second (Service.createMetadataRegistry . Service.mpEntries) payload
  