{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Stability: experimental
-- This module implements attestation of the received authenticator response.
-- See the WebAuthn
-- [specification](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- for the algorithm implemented in this module.
-- Assertion is typically represented as a "register" action
-- in the front-end.
-- [Section 7 of the specification](https://www.w3.org/TR/webauthn-2/#sctn-rp-operations)
-- describes when the relying party must perform attestation. Another relevant
-- section is
-- [Section 1.3.1](https://www.w3.org/TR/webauthn-2/#sctn-sample-registration)
-- which is a high level overview of the registration procedure.
module Crypto.WebAuthn.Operation.Registration
  ( verifyRegistrationResponse,
    RegistrationError (..),
    RegistrationResult (..),
    AuthenticatorModel (..),
    SomeAttestationStatement (..),
  )
where

import Control.Exception (Exception)
import Control.Monad (unless)
import qualified Crypto.Hash as Hash
import qualified Crypto.WebAuthn.Cose.PublicKeyWithSignAlg as Cose
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import Crypto.WebAuthn.Internal.Utils (certificateSubjectKeyIdentifier, failure)
import Crypto.WebAuthn.Metadata.Service.Processing (queryMetadata)
import qualified Crypto.WebAuthn.Metadata.Service.Types as Meta
import qualified Crypto.WebAuthn.Metadata.Statement.Types as Meta
import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.Model.Identifier (AuthenticatorIdentifier (AuthenticatorIdentifierFido2, AuthenticatorIdentifierFidoU2F))
import Crypto.WebAuthn.Operation.CredentialEntry
  ( CredentialEntry
      ( CredentialEntry,
        ceCredentialId,
        cePublicKeyBytes,
        ceSignCounter,
        ceTransports,
        ceUserHandle
      ),
  )
import Data.Aeson (ToJSON, Value (String), object, toJSON, (.=))
import Data.Hourglass (DateTime)
import Data.List.NonEmpty (NonEmpty ((:|)))
import qualified Data.List.NonEmpty as NE
import Data.Validation (Validation (Failure, Success))
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509
import GHC.Generics (Generic)

-- | All the errors that can result from a call to 'verifyRegistrationResponse'
data RegistrationError
  = -- | The received challenge does not match the originally created
    -- challenge
    RegistrationChallengeMismatch
      { -- | The challenge created by the relying party and part of the
        -- `M.CredentialOptions`
        reCreatedChallenge :: M.Challenge,
        -- | The challenge received from the client, part of the response
        reReceivedChallenge :: M.Challenge
      }
  | -- | The returned origin does not match the relying party's origin
    RegistrationOriginMismatch
      { -- | The origin explicitly passed to the `verifyRegistrationResponse`
        -- response, set by the RP
        reExpectedOrigin :: M.Origin,
        -- | The origin received from the client as part of the client data
        reReceivedOrigin :: M.Origin
      }
  | -- | The rpIdHash in the authData is not a valid hash over the RpId
    -- expected by the Relying party
    RegistrationRpIdHashMismatch
      { -- | The RP ID hash explicitly passed to the
        -- `verifyRegistrationResponse` response, set by the RP
        reExpectedRpIdHash :: M.RpIdHash,
        -- | The RP ID hash received from the client as part of the authenticator
        -- data
        reReceivedRpIdHash :: M.RpIdHash
      }
  | -- | The userpresent bit in the authdata was not set
    RegistrationUserNotPresent
  | -- | The userverified bit in the authdata was not set
    RegistrationUserNotVerified
  | -- | The algorithm received from the client was not one of the algorithms
    -- we (the relying party) requested from the client.
    RegistrationPublicKeyAlgorithmDisallowed
      { -- | The signing algorithms requested by the RP
        reAllowedSigningAlgorithms :: [Cose.CoseSignAlg],
        -- | The signing algorithm received from the client
        reReceivedSigningAlgorithm :: Cose.CoseSignAlg
      }
  | -- | There was some exception in the statement format specific section
    forall a. M.AttestationStatementFormat a => RegistrationAttestationFormatError a (NonEmpty (M.AttStmtVerificationError a))

deriving instance Show RegistrationError

deriving instance Exception RegistrationError

-- | Information about the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
-- model that created the [public key credential](https://www.w3.org/TR/webauthn-2/#public-key-credential).
-- Depending on the constructor, this information can be used to base security
-- decisions.
data AuthenticatorModel k where
  -- | An unknown authenticator, meaning that we received no information about
  -- what authenticator model was used to generate the public key credential.
  -- We therefore also cannot assume any security guarantees regarding how the
  -- key is stored and other properties of the authenticator.
  -- This is expected to be the case when the ["none"](https://www.w3.org/TR/webauthn-2/#dom-attestationconveyancepreference-none)
  -- [Attestation Conveyance Preference](https://www.w3.org/TR/webauthn-2/#enum-attestation-convey)
  -- was selected.
  UnknownAuthenticator :: AuthenticatorModel 'M.Unverifiable
  -- | An [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) that
  -- provided a verifiable [attestation type](https://www.w3.org/TR/webauthn-2/#sctn-attestation-types),
  -- see 'M.Verifiable', but the certificate chain in the attestation statement
  -- failed to be verified. This is an indication that the 'uaIdentifier' and
  -- 'uaMetadata' fields cannot be trusted currently. This can happen when the
  -- root certificate of the chain is not trusted or known. Root certificates
  -- are discovered using both the 'M.AttestationStatementFormat's 'M.asfTrustAnchors'
  -- method, and the passed 'Meta.MetadataServiceRegistry'. The relying party
  -- can decide what to do in such a case, for example:
  --
  -- 1. Treating it as if it was an 'UnknownAuthenticator', but logging the
  --   'SomeAttestationStatement' structure, so that the admin can be informed of this
  --   and perhaps add custom entries to the 'Meta.MetadataServiceRegistry' to
  --   allow such authenticators to be verified in the future
  -- 2. Only using the 'uaIdentifier' and 'uaMetadata' for non-security-critical
  --   decisions. For example in order to show the user which authenticator they
  --   used to register.
  UnverifiedAuthenticator ::
    { -- | The failures that occurred when trying to validate the certificate
      -- chain
      uaFailures :: NonEmpty X509.FailedReason,
      -- | The identifier for the authenticator model
      uaIdentifier :: AuthenticatorIdentifier p,
      -- | The metadata looked up in the provided 'Meta.MetadataServiceRegistry'
      -- This field is always equal to 'Meta.queryMetadata registry vaIdentifier',
      -- and is only provided for convenience and because the implementation
      -- already has to look it up
      uaMetadata :: Maybe (Meta.MetadataEntry p)
    } ->
    AuthenticatorModel ('M.Verifiable p)
  -- | An [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator) that
  -- provided a verifiable [attestation type](https://www.w3.org/TR/webauthn-2/#sctn-attestation-types),
  -- see 'M.Verifiable' and whose certificate chain in the attestation statement
  -- could successfully be verified. This is an indication that the 'uaIdentifier'
  -- and 'uaMetadata' fields can be trusted, meaning that we can be sure that
  -- the 'M.CredentialEntry' was created from the authenticator model with
  -- these fields as properties. In this case, the Relying Party can reasonably
  -- do the following:
  --
  -- * Persistently store the 'vaIdentifier' alongside 'CredentialEntry', such
  --   that even after the registration is complete, the 'vaMetadata' entry
  --   from the 'Meta.MetadataServiceRegistry' can be accessed. This also
  --   allows getting more up-to-date metadata (or at all if 'vaMetadata' was
  --   'Nothing') on an authenticator over time.
  -- * The 'vaMetadata' may be used to determine whether this authenticator
  --   model is trustful enough to be allowed for registration. For example,
  --   'Meta.srStatus' in 'Meta.meStatusReports' may be inspected for the
  --   authenticator being 'Meta.FIDO_CERTIFIED', aka that it passed the FIDO
  --   Alliances [Functional Certification](https://fidoalliance.org/certification/functional-certification/)
  -- * It is encouraged to persistently store the certificate chain from the
  --   'M.AttestationType' and check CRLs for revocations of any certificates
  --   in the chain. See [here](https://www.w3.org/TR/webauthn-2/#sctn-ca-compromise)
  --   for more information
  VerifiedAuthenticator ::
    { -- | The identifier for the authenticator model
      vaIdentifier :: AuthenticatorIdentifier p,
      -- | The metadata looked up in the provided 'Meta.MetadataServiceRegistry'
      -- This field is always equal to 'Meta.queryMetadata registry vaIdentifier',
      -- and is only provided for convenience and because the implementation
      -- already has to look it up
      vaMetadata :: Maybe (Meta.MetadataEntry p)
    } ->
    AuthenticatorModel ('M.Verifiable p)

deriving instance Show (AuthenticatorModel k)

deriving instance Eq (AuthenticatorModel k)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON (AuthenticatorModel k) where
  toJSON UnknownAuthenticator =
    object
      [ "tag" .= String "unknown"
      ]
  toJSON UnverifiedAuthenticator {..} =
    object
      [ "tag" .= String "unverified",
        "uaFailures" .= uaFailures,
        "uaIdentifier" .= uaIdentifier,
        "uaMetadata" .= uaMetadata
      ]
  toJSON VerifiedAuthenticator {..} =
    object
      [ "tag" .= String "verified",
        "vaIdentifier" .= vaIdentifier,
        "vaMetadata" .= vaMetadata
      ]

-- | Some attestation statement that represents both the [attestation type](https://www.w3.org/TR/webauthn-2/#sctn-attestation-types)
-- that was returned along with information about the [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
-- model that created it. This result may be inspected to enforce relying party
-- policy, see the individual fields for more information.
data SomeAttestationStatement = forall k.
  SomeAttestationStatement
  { -- | The [attestation type](https://www.w3.org/TR/webauthn-2/#sctn-attestation-types)
    -- of the attestation statement. This could be used to only allow specific
    -- attestation types. E.g. disallowing [Basic](https://www.w3.org/TR/webauthn-2/#basic-attestation)
    -- and [Self](https://www.w3.org/TR/webauthn-2/#self-attestation) attestation,
    -- or marking those specially in the database.
    asType :: M.AttestationType k,
    -- | The [authenticator](https://www.w3.org/TR/webauthn-2/#authenticator)
    -- model that produced the attestation statement. Relying Party policy could
    -- accept this credential based on properties of this field:
    --
    -- * Disallowing unverified authenticators by checking whether
    --   it is an 'UnverifiedAuthenticator'
    --
    -- * Disallowing authenticators that don't meet the required security level by
    --   inspecting the 'vaMetadata' of a 'VerifiedAuthenticator'
    --
    -- * Only allowing a very specific authenticator to be used by looking at
    --   'vaIdentifier' of a 'VerifiedAuthenticator'
    asModel :: AuthenticatorModel k
  }

deriving instance Show SomeAttestationStatement

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
instance ToJSON SomeAttestationStatement where
  toJSON SomeAttestationStatement {..} =
    object
      [ "asType" .= asType,
        "asModel" .= asModel
      ]

-- | The result returned from 'verifyRegistrationResponse'. It indicates that
-- the operation of [registering a new credential](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- didn't fail.
data RegistrationResult = RegistrationResult
  { -- | The entry to insert into the database
    rrEntry :: CredentialEntry,
    -- | Information about the attestation statement
    rrAttestationStatement :: SomeAttestationStatement
  }
  deriving (Show, Generic)

-- | An arbitrary and potentially unstable JSON encoding, only intended for
-- logging purposes. To actually encode and decode structures, use the
-- "Crypto.WebAuthn.Encoding" modules
deriving instance ToJSON RegistrationResult

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential)
-- The resulting 'rrEntry' of this call should be stored in a database by the
-- Relying Party. The 'rrAttestationStatement' contains the result of the
-- attempted attestation, allowing the Relying Party to reject certain
-- authenticators/attempted entry creations based on policy.
verifyRegistrationResponse ::
  -- | The origin of the server
  M.Origin ->
  -- | The relying party id
  M.RpIdHash ->
  -- | The metadata registry, used for verifying the validity of the
  -- attestation by looking up root certificates
  Meta.MetadataServiceRegistry ->
  -- | The current time, used for verifying the validity of the attestation
  -- statement certificate chain
  DateTime ->
  -- | The options passed to the create() method
  M.CredentialOptions 'M.Registration ->
  -- | The response from the authenticator
  M.Credential 'M.Registration 'True ->
  -- | Either a nonempty list of validation errors in case the attestation FailedReason
  -- Or () in case of a result.
  Validation (NonEmpty RegistrationError) RegistrationResult
verifyRegistrationResponse
  rpOrigin
  rpIdHash
  registry
  currentTime
  options@M.CredentialOptionsRegistration {..}
  credential@M.Credential
    { M.cResponse =
        M.AuthenticatorResponseRegistration
          { arrClientData = c,
            arrAttestationObject =
              M.AttestationObject
                { aoAuthData = authData@M.AuthenticatorData {adAttestedCredentialData = M.AttestedCredentialData {..}},
                  ..
                }
          }
    } =
    do
      -- 1. Let options be a new PublicKeyCredentialCreationOptions structure
      -- configured to the Relying Party's needs for the ceremony.
      -- NOTE: Implemented by caller

      -- 2. Call navigator.credentials.create() and pass options as the publicKey
      -- option. Let credential be the result of the successfully resolved
      -- promise. If the promise is rejected, abort the ceremony with a
      -- user-visible error, or otherwise guide the user experience as might be
      -- determinable from the context available in the rejected promise. For
      -- example if the promise is rejected with an error code equivalent to
      -- "InvalidStateError", the user might be instructed to use a different
      -- authenticator. For information on different error contexts and the
      -- circumstances leading to them, see § 6.3.2 The
      -- authenticatorMakeCredential Operation.
      -- NOTE: Implemented by caller

      -- 3. Let response be credential.response. If response is not an instance
      -- of AuthenticatorAttestationResponse, abort the ceremony with a
      -- user-visible error.
      -- NOTE: Already done as part of decoding

      -- 4. Let clientExtensionResults be the result of calling
      -- credential.getClientExtensionResults().
      -- TODO: Extensions are not implemented by this library, see the TODO in the
      -- module documentation of `Crypto.WebAuthn.Model` for more information.

      -- 5. Let JSONtext be the result of running UTF-8 decode on the value of
      -- response.clientDataJSON.
      -- NOTE: Done as part of decoding

      -- 6. Let C, the client data claimed as collected during the credential
      -- creation, be the result of running an implementation-specific JSON
      -- parser on JSONtext.
      -- NOTE: Done as part of decoding

      -- 7. Verify that the value of C.type is webauthn.create.
      -- NOTE: Done as part of decoding

      -- 8. Verify that the value of C.challenge equals the base64url encoding of
      -- options.challenge.
      unless (corChallenge == M.ccdChallenge c) $
        failure $ RegistrationChallengeMismatch corChallenge (M.ccdChallenge c)

      -- 9. Verify that the value of C.origin matches the Relying Party's origin.
      unless (rpOrigin == M.ccdOrigin c) $
        failure $ RegistrationOriginMismatch rpOrigin (M.ccdOrigin c)

      -- 10. Verify that the value of C.tokenBinding.status matches the state of
      -- Token Binding for the TLS connection over which the assertion was
      -- obtained. If Token Binding was used on that TLS connection, also verify
      -- that C.tokenBinding.id matches the base64url encoding of the Token
      -- Binding ID for the connection.
      -- TODO: We do not implement TokenBinding, see the documentation of
      -- `CollectedClientData` for more information.

      -- 11. Let hash be the result of computing a hash over
      -- response.clientDataJSON using SHA-256.
      -- NOTE: Done on raw data from decoding so that we don't need to encode again
      -- here and so that we use the exact some serialization
      let hash = M.ClientDataHash $ Hash.hash $ M.unRaw $ M.ccdRawData c

      -- 12. Perform CBOR decoding on the attestationObject field of the
      -- AuthenticatorAttestationResponse structure to obtain the attestation
      -- statement format fmt, the authenticator data authData, and the attestation
      -- statement attStmt.
      -- NOTE: Already done as part of decoding

      -- 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP
      -- ID expected by the Relying Party.
      unless (rpIdHash == M.adRpIdHash authData) $
        failure $ RegistrationRpIdHashMismatch rpIdHash (M.adRpIdHash authData)

      -- 14. Verify that the User Present bit of the flags in authData is set.
      unless (M.adfUserPresent (M.adFlags authData)) $
        failure RegistrationUserNotPresent

      -- 15. If user verification is required for this registration, verify that
      -- the User Verified bit of the flags in authData is set.
      -- NOTE: The spec is interpreted to mean that the userVerification option
      -- from authenticatorSelection being set to "required" is what is meant by
      -- whether user verification is required
      case ( M.ascUserVerification <$> M.corAuthenticatorSelection options,
             M.adfUserVerified (M.adFlags authData)
           ) of
        (Nothing, _) -> pure ()
        (Just M.UserVerificationRequirementRequired, True) -> pure ()
        (Just M.UserVerificationRequirementRequired, False) -> failure RegistrationUserNotVerified
        (Just M.UserVerificationRequirementPreferred, True) -> pure ()
        (Just M.UserVerificationRequirementPreferred, False) -> pure ()
        (Just M.UserVerificationRequirementDiscouraged, True) -> pure ()
        (Just M.UserVerificationRequirementDiscouraged, False) -> pure ()

      -- 16. Verify that the "alg" parameter in the credential public key in
      -- authData matches the alg attribute of one of the items in
      -- options.pubKeyCredParams.
      let acdAlg = Cose.signAlg acdCredentialPublicKey
          desiredAlgs = map M.cpAlg corPubKeyCredParams
      unless (acdAlg `elem` desiredAlgs) $
        failure $ RegistrationPublicKeyAlgorithmDisallowed desiredAlgs acdAlg

      -- 17. Verify that the values of the client extension outputs in
      -- clientExtensionResults and the authenticator extension outputs in the
      -- extensions in authData are as expected, considering the client extension
      -- input values that were given in options.extensions and any specific
      -- policy of the Relying Party regarding unsolicited extensions, i.e.,
      -- those that were not specified as part of options.extensions. In the
      -- general case, the meaning of "are as expected" is specific to the
      -- Relying Party and which extensions are in use.
      -- TODO: Extensions are not implemented by this library, see the TODO in the
      -- module documentation of `Crypto.WebAuthn.Model` for more information.

      -- 18. Determine the attestation statement format by performing a USASCII
      -- case-sensitive match on fmt against the set of supported WebAuthn
      -- Attestation Statement Format Identifier values. An up-to-date list of
      -- registered WebAuthn Attestation Statement Format Identifier values is
      -- maintained in the IANA "WebAuthn Attestation Statement Format Identifiers"
      -- registry [IANA-WebAuthn-Registries] established by [RFC8809].
      -- NOTE: This check is done during decoding and enforced by the type-system

      -- 19. Verify that attStmt is a correct attestation statement, conveying a
      -- valid attestation signature, by using the attestation statement format
      -- fmt’s verification procedure given attStmt, authData and hash.
      attStmt <- case M.asfVerify aoFmt currentTime aoAttStmt authData hash of
        Failure err -> failure $ RegistrationAttestationFormatError aoFmt err
        Success (M.SomeAttestationType M.AttestationTypeNone) ->
          pure $ SomeAttestationStatement M.AttestationTypeNone UnknownAuthenticator
        Success (M.SomeAttestationType M.AttestationTypeSelf) ->
          pure $ SomeAttestationStatement M.AttestationTypeSelf UnknownAuthenticator
        Success (M.SomeAttestationType attType@M.AttestationTypeVerifiable {}) ->
          pure $ validateAttestationChain credential aoFmt attType registry currentTime
      pure $
        RegistrationResult
          { rrEntry =
              CredentialEntry
                { ceUserHandle = M.cueId $ M.corUser options,
                  ceCredentialId = M.cIdentifier credential,
                  cePublicKeyBytes = M.PublicKeyBytes $ M.unRaw acdCredentialPublicKeyBytes,
                  ceSignCounter = M.adSignCount authData,
                  ceTransports = M.arrTransports $ M.cResponse credential
                },
            rrAttestationStatement = attStmt
          }

-- | Performs step 20 and 21 of attestation for verifieable attestation types.
-- Results in the type of attestation and the model.
validateAttestationChain ::
  forall raw p a.
  M.AttestationStatementFormat a =>
  M.Credential 'M.Registration raw ->
  a ->
  M.AttestationType ('M.Verifiable p) ->
  Meta.MetadataServiceRegistry ->
  DateTime ->
  SomeAttestationStatement
validateAttestationChain
  credential
  fmt
  M.AttestationTypeVerifiable {..}
  registry
  currentTime =
    SomeAttestationStatement attestationType authenticator
    where
      attestationType =
        M.AttestationTypeVerifiable
          { M.atvType = maybe atvType (fixupVerifiableAttestationType atvType) metadataStatement,
            M.atvChain = atvChain
          }
      authenticator = case NE.nonEmpty chainValidationFailures of
        Nothing ->
          VerifiedAuthenticator
            { vaIdentifier = identifier,
              vaMetadata = metadataEntry
            }
        Just failures ->
          UnverifiedAuthenticator
            { uaFailures = failures,
              uaIdentifier = identifier,
              uaMetadata = metadataEntry
            }

      chain :: X509.CertificateChain
      identifier :: AuthenticatorIdentifier p
      (chain, identifier) = case atvChain of
        M.Fido2Chain cs ->
          ( X509.CertificateChain $ NE.toList cs,
            AuthenticatorIdentifierFido2
              . M.acdAaguid
              . M.adAttestedCredentialData
              . M.aoAuthData
              . M.arrAttestationObject
              . M.cResponse
              $ credential
          )
        M.FidoU2FCert c ->
          ( X509.CertificateChain [c],
            AuthenticatorIdentifierFidoU2F
              . certificateSubjectKeyIdentifier
              . X509.getCertificate
              $ c
          )
      metadataEntry = queryMetadata registry identifier
      metadataStatement = metadataEntry >>= Meta.meMetadataStatement

      -- 20. If validation is successful, obtain a list of acceptable trust
      -- anchors (i.e. attestation root certificates) for that attestation type
      -- and attestation statement format fmt, from a trusted source or from
      -- policy. For example, the FIDO Metadata Service [FIDOMetadataService]
      -- provides one way to obtain such information, using the aaguid in the
      -- attestedCredentialData in authData.
      formatRootCerts = M.asfTrustAnchors fmt atvType
      metadataRootCerts = case metadataStatement of
        Nothing -> mempty
        Just statement -> X509.makeCertificateStore $ NE.toList $ Meta.msAttestationRootCertificates statement

      -- 21. Assess the attestation trustworthiness using the outputs of the
      -- verification procedure in step 19, as follows:
      --
      -- -> If no attestation was provided, verify that None attestation is
      --    acceptable under Relying Party policy.
      --    NOTE: Can be decided from the return type
      -- -> If self attestation was used, verify that self attestation is
      --    acceptable under Relying Party policy.
      --    NOTE: Can be decided from the return type
      -- -> Otherwise, use the X.509 certificates returned as the attestation
      --    trust path from the verification procedure to verify that the
      --    attestation public key either correctly chains up to an acceptable
      --    root certificate, or is itself an acceptable certificate (i.e., it
      --    and the root certificate obtained in Step 20 may be the same).
      --    NOTE: We are only returning the errors, which can be used to either
      --    fail or still allow it
      chainValidationFailures =
        X509.validatePure
          currentTime
          X509.defaultHooks
            { X509.hookValidateName = \_fqhn _cert -> []
            }
          X509.defaultChecks
          (formatRootCerts <> metadataRootCerts)
          ("", mempty)
          chain

-- | Metadata statements can convey multiple attestation types.
-- In such a case we choose to result in the Uncertain type.
-- Otherwise, we results in the only one available.
fixupVerifiableAttestationType :: M.VerifiableAttestationType -> Meta.MetadataStatement -> M.VerifiableAttestationType
fixupVerifiableAttestationType M.VerifiableAttestationTypeUncertain statement =
  case Meta.msAttestationTypes statement of
    -- If there are multiple types we can't know which one it is
    (_ :| (_ : _)) -> M.VerifiableAttestationTypeUncertain
    (Meta.WebauthnAttestationBasic :| []) -> M.VerifiableAttestationTypeBasic
    (Meta.WebauthnAttestationAttCA :| []) -> M.VerifiableAttestationTypeAttCA
fixupVerifiableAttestationType certain _ = certain
