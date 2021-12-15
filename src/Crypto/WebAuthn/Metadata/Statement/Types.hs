{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}

module Crypto.WebAuthn.Metadata.Statement.Types
  ( MetadataStatement (..),
    MetadataEntryIdentifier (..),
    ProtocolVersion (..),
    WebauthnAttestationType (..),
  )
where

import qualified Crypto.WebAuthn.Metadata.Statement.IDL as StatementIDL
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Registry as Registry
import Crypto.WebAuthn.SubjectKeyIdentifier (SubjectKeyIdentifier)
import qualified Data.ByteString as BS
import Data.List.NonEmpty (NonEmpty)
import Data.Text (Text)
import Data.Word (Word32)
import qualified Data.X509 as X509
import GHC.Word (Word16)

-- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys)
data MetadataStatement (p :: StatementIDL.ProtocolFamily) = MetadataStatement
  { -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-legalheader)
    msLegalHeader :: Text,
    -- | Either the AAGUID in case of FIDO 2 or a list of
    -- SubjectKeyIdentifier's in case of FIDO U2F identifying this authenticator
    msIdentifier :: MetadataEntryIdentifier p,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-description)
    msDescription :: Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-alternativedescriptions)
    msAlternativeDescriptions :: Maybe StatementIDL.AlternativeDescriptions,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorversion)
    msAuthenticatorVersion :: Word32,
    -- protocolFamily, encoded as the type-level p
    -- msSchema, this is always schema version 3

    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-upv)
    msUpv :: NonEmpty (ProtocolVersion p),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticationalgorithms)
    msAuthenticationAlgorithms :: NonEmpty Registry.AuthenticationAlgorithm,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-publickeyalgandencodings)
    msPublicKeyAlgAndEncodings :: NonEmpty Registry.PublicKeyRepresentationFormat,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationtypes)
    msAttestationTypes :: NonEmpty WebauthnAttestationType,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-userverificationdetails)
    msUserVerificationDetails :: NonEmpty StatementIDL.VerificationMethodANDCombinations,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-keyprotection)
    msKeyProtection :: NonEmpty Registry.KeyProtectionType,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-iskeyrestricted)
    msIsKeyRestricted :: Maybe Bool,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-isfreshuserverificationrequired)
    msIsFreshUserVerificationRequired :: Maybe Bool,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-matcherprotection)
    msMatcherProtection :: NonEmpty Registry.MatcherProtectionType,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-cryptostrength)
    msCryptoStrength :: Maybe Word16,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attachmenthint)
    msAttachmentHint :: NonEmpty Registry.AuthenticatorAttachmentHint,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplay)
    msTcDisplay :: [Registry.TransactionConfirmationDisplayType],
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplaycontenttype)
    msTcDisplayContentType :: Maybe Text,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-tcdisplaypngcharacteristics)
    msTcDisplayPNGCharacteristics :: Maybe (NonEmpty StatementIDL.DisplayPNGCharacteristicsDescriptor),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationrootcertificates)
    msAttestationRootCertificates :: NonEmpty X509.SignedCertificate,
    -- msEcdaaTrustAnchors, not needed for the subset we implement, FIDO 2 and FIDO U2F

    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-icon)
    msIcon :: Maybe BS.ByteString,
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-supportedextensions)
    msSupportedExtensions :: Maybe (NonEmpty StatementIDL.ExtensionDescriptor),
    -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-authenticatorgetinfo)
    msAuthenticatorGetInfo :: Maybe StatementIDL.AuthenticatorGetInfo
  }

-- | A way to identify an authenticator
data MetadataEntryIdentifier (p :: StatementIDL.ProtocolFamily) where
  -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-aaguid)
  -- FIDO 2 authenticators are identified using an AAGUID
  MetadataEntryIdentifierFido2 ::
    {idAaguid :: M.AAGUID} ->
    MetadataEntryIdentifier 'StatementIDL.ProtocolFamilyFIDO2
  -- | [(spec)](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dom-metadatastatement-attestationcertificatekeyidentifiers)
  -- FIDO U2F authenticators are identified using a subject key identifier
  MetadataEntryIdentifierFidoU2F ::
    {idSubjectKeyIdentifiers :: NonEmpty SubjectKeyIdentifier} ->
    MetadataEntryIdentifier 'StatementIDL.ProtocolFamilyU2F

-- | FIDO protocol versions, parametrized by the protocol family
data ProtocolVersion (p :: StatementIDL.ProtocolFamily) where
  -- | FIDO U2F 1.0
  U2F1_0 :: ProtocolVersion 'StatementIDL.ProtocolFamilyU2F
  -- | FIDO U2F 1.1
  U2F1_1 :: ProtocolVersion 'StatementIDL.ProtocolFamilyU2F
  -- | FIDO U2F 1.2
  U2F1_2 :: ProtocolVersion 'StatementIDL.ProtocolFamilyU2F
  -- | FIDO 2, CTAP 2.0
  CTAP2_0 :: ProtocolVersion 'StatementIDL.ProtocolFamilyFIDO2
  -- | FIDO 2, CTAP 2.1
  CTAP2_1 :: ProtocolVersion 'StatementIDL.ProtocolFamilyFIDO2

-- | Values of 'Registry.AuthenticatorAttestationType' but limited to the ones possible with Webauthn, see https://www.w3.org/TR/webauthn-2/#sctn-attestation-types
data WebauthnAttestationType
  = WebauthnAttestationBasic
  | WebauthnAttestationAttCA
