{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}

module Emulation.Authenticator
  ( CredentialSource (..),
    AuthenticatorSignatureCounter (..),
    Conformance,
    AuthenticatorNonConformingBehaviour (..),
    Authenticator (..),
    authenticatorMakeCredential,
    authenticatorGetAssertion,
  )
where

import Control.Monad (forM_, when)
import Crypto.Hash (hash)
import Crypto.Random (MonadRandom)
import qualified Crypto.Random as Random
import qualified Crypto.WebAuthn.AttestationStatementFormat.None as None
import qualified Crypto.WebAuthn.Cose.SignAlg as Cose
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Model.WebIDL.Internal.Binary.Encoding as ME
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Data.List (find)
import qualified Data.Map as Map
import Data.Maybe (fromJust, mapMaybe)
import qualified Data.Set as Set
import Data.Text.Encoding (encodeUtf8)
import qualified Spec.Key as Key

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#public-key-credential-source)
-- A stored credential.
data CredentialSource = CredentialSource
  { csId :: M.CredentialId,
    csSignAlg :: Cose.CoseSignAlg,
    csPrivateKey :: Key.PrivateKey,
    csRpId :: M.RpId,
    csUserHandle :: Maybe M.UserHandle
  }
  deriving (Eq, Show)

data AuthenticatorSignatureCounter
  = Unsupported
  | Global M.SignatureCounter
  | PerCredential (Map.Map M.CredentialId M.SignatureCounter)
  deriving (Eq, Show)

-- | Non Conforming behaviour the Authenticator should perform. Some behaviours
-- cannot be performed at the same time. In such cases the superseding or
-- superseded behaviours are marked.
data AuthenticatorNonConformingBehaviour
  = -- | Generates random data to be signed by the signing function
    RandomSignatureData
  | -- | Use a randomly generated private key for signing
    RandomPrivateKey
  | -- | Don't increase the counter during attestation and assertion
    StaticCounter
  deriving (Eq, Ord, Show, Enum, Bounded)

type Conformance = Set.Set AuthenticatorNonConformingBehaviour

-- | The datatype holding all information needed for attestation and assertion
data Authenticator = AuthenticatorNone
  -- https://www.w3.org/TR/webauthn-2/#authenticator-credentials-map
  { aAAGUID :: M.AAGUID,
    aCredentials :: Map.Map (M.RpId, M.UserHandle) CredentialSource,
    aSignatureCounter :: AuthenticatorSignatureCounter,
    aSupportedAlgorithms :: Set.Set Cose.CoseSignAlg,
    aAuthenticatorDataFlags :: M.AuthenticatorDataFlags,
    aConformance :: Conformance
  }
  deriving (Show)

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred)
authenticatorMakeCredential ::
  (MonadRandom m, MonadFail m) =>
  -- | authenticator: The stored authenticator data
  Authenticator ->
  -- | hash: The hash of the serialized client data, provided by the client.
  M.ClientDataHash ->
  -- | rpEntity: The Relying Party's CredentialRpEntity.
  M.CredentialRpEntity ->
  -- | userEntity: The user account’s CredentialUserEntity, containing
  -- the user handle given by the Relying Party.
  M.CredentialUserEntity ->
  -- | requireResidentKey: The effective resident key requirement for
  -- credential creation, a Boolean value determined by the client.
  -- NOTE: We always provide resident keys
  Bool ->
  -- | requireUserPresence: The constant Boolean value true. It is included
  -- here as a pseudo-parameter to simplify applying this abstract
  -- authenticator model to implementations that may wish to make a test of
  -- user presence optional although WebAuthn does not.
  -- NOTE: We currently always have user present
  Bool ->
  -- | requireUserVerification: The effective user verification requirement for
  -- credential creation, a Boolean value determined by the client.
  -- NOTE: We currently always verify the user
  Bool ->
  -- | credTypesAndPubKeyAlgs: A sequence of pairs of CredentialType
  -- and public key algorithms (COSEAlgorithmIdentifier) requested by the
  -- Relying Party. This sequence is ordered from most preferred to least
  -- preferred. The authenticator makes a best-effort to create the most
  -- preferred credential that it can.
  [M.CredentialParameters] ->
  -- | excludeCredentialDescriptorList: An OPTIONAL list of
  -- CredentialDescriptor objects provided by the Relying Party with
  -- the intention that, if any of these are known to the authenticator, it
  -- SHOULD NOT create a new credential. excludeCredentialDescriptorList
  -- contains a list of known credentials.
  [M.CredentialDescriptor] ->
  -- | enterpriseAttestationPossible: A Boolean value that indicates that
  -- individually-identifying attestation MAY be returned by the authenticator.
  Bool ->
  -- | extensions: A CBOR map from extension identifiers to their authenticator
  -- extension inputs, created by the client based on the extensions requested
  -- by the Relying Party, if any.
  Maybe M.AuthenticationExtensionsClientInputs ->
  m (M.AttestationObject 'True, Authenticator)
authenticatorMakeCredential
  authenticator@AuthenticatorNone {..}
  _hash
  rpEntity
  userEntity
  _requireResidentKey
  _requireUserPresence
  _requireUserVerification
  credTypesAndPubKeyAlgs
  excludeCredentialDescriptorList
  _enterpriseAttestationPossible
  _extensions =
    do
      -- 1. Check if all the supplied parameters are syntactically well-formed
      -- and of the correct length. If not, return an error code equivalent to
      -- "UnknownError" and terminate the operation.
      -- NOTE: This step is performed during decoding
      -- NOTE: We assume the client set a rpId if it was initially Nothing.
      let rpId = fromJust $ M.creId rpEntity

      -- 2. Check if at least one of the specified combinations of
      -- CredentialType and cryptographic parameters in
      -- credTypesAndPubKeyAlgs is supported. If not, return an error code
      -- equivalent to "NotSupportedError" and terminate the operation.
      param <- case find ((`Set.member` aSupportedAlgorithms) . M.cpAlg) credTypesAndPubKeyAlgs of
        Just param -> pure param
        Nothing -> fail "NotSupportedError"

      -- 3. For each descriptor of excludeCredentialDescriptorList: If looking up
      -- descriptor.id in this authenticator returns non-null, and the returned
      -- item's RP ID and type match rpEntity.id and
      -- excludeCredentialDescriptorList.type respectively, then collect an
      -- authorization gesture confirming user consent for creating a new
      -- credential. The authorization gesture MUST include a test of user
      -- presence. If the user
      --   confirms consent to create a new credential:
      --       return an error code equivalent to "InvalidStateError" and terminate the operation.
      --   does not consent to create a new credential:
      --       return an error code equivalent to "NotAllowedError" and terminate the operation.
      -- NOTE: We do not perform user tests, instead assuming that the user always consents.
      forM_ excludeCredentialDescriptorList $ \descriptor -> case authenticatorLookupCredential authenticator (M.cdId descriptor) of
        Just item -> do
          when (rpId == csRpId item) (fail "InvalidStateError")
        Nothing -> pure ()

      -- 4. If requireResidentKey is true and the authenticator cannot store a
      -- client-side discoverable public key credential source, return an error
      -- code equivalent to "ConstraintError" and terminate the operation.
      -- NOTE: We do not have to do this because the test authenticator supports
      -- both methods of discoverability

      -- 5. If requireUserVerification is true and the authenticator cannot
      -- perform user verification, return an error code equivalent to
      -- "ConstraintError" and terminate the operation.
      -- NOTE: We do not do this because we fake user verification

      -- 6. Collect an authorization gesture confirming user consent for creating
      -- a new credential. The prompt for the authorization gesture is shown by
      -- the authenticator if it has its own output capability, or by the user
      -- agent otherwise. The prompt SHOULD display rpEntity.id, rpEntity.name,
      -- userEntity.name and userEntity.displayName, if possible.
      --   If requireUserVerification is true, the authorization gesture MUST
      --   include user verification.
      --   If requireUserPresence is true, the authorization gesture MUST include a
      --   test of user presence.
      --   If the user does not consent or if user verification fails, return an
      --   error code equivalent to "NotAllowedError" and terminate the operation.
      -- NOTE: We curently always succeed this step

      -- 7. Once the authorization gesture has been completed and user consent
      -- has been obtained, generate a new credential object:
      -- 7.1. Let (publicKey, privateKey) be a new pair of cryptographic keys
      -- using the combination of CredentialType and cryptographic
      -- parameters represented by the first item in credTypesAndPubKeyAlgs that
      -- is supported by this authenticator.
      let signAlg = M.cpAlg param
      Key.KeyPair {..} <- Key.newKeyPair signAlg

      -- 7.2. Let userHandle be userEntity.id.
      let userHandle = M.cueId userEntity

      -- 7.4 If requireResidentKey is true or the authenticator chooses to
      -- create a client-side discoverable public key credential source:

      -- 7.4.1 Let credentialId be a new credential id.
      -- NOTE: We need to have a CredentialId before we can construct the
      -- credentialSource.
      -- NOTE: We always choose to construct a clientside discoverable
      -- credential, as this is allowed (See 7.4).
      credentialId <- M.generateCredentialId

      -- 7.4.2. Set credentialSource.id to credentialId.
      -- 7.3.  Let credentialSource be a new public key credential source with the fields:
      let credentialSource =
            CredentialSource
              { csId = credentialId,
                csSignAlg = signAlg,
                csPrivateKey = privKey,
                csRpId = rpId,
                csUserHandle = Just userHandle
              }

      -- 7.4.3 Let credentials be this authenticator’s credentials map.
      -- NOTE: we have aCredentials from the patternmatch
      -- 7.4.4 Set credentials[(rpEntity.id, userHandle)] to credentialSource.

      let credentials =
            Map.insert (rpId, userHandle) credentialSource aCredentials

      -- 8. If any error occurred while creating the new credential object,
      -- return an error code equivalent to "UnknownError" and terminate the
      -- operation.
      -- NOTE: See above

      -- 9. Let processedExtensions be the result of authenticator extension
      -- processing for each supported extension identifier → authenticator
      -- extension input in extensions.
      -- NOTE: Extensions are unsupporteded

      -- 10. If the authenticator supports a per credential signature counter,
      -- allocate the counter, associate it with the new credential, and
      -- initialize the counter value as zero.
      -- NOTE: We return the updated signature counter and the supposed signatureCount.
      -- The signatureCount will be 0 if Unsupported
      let (signatureCounter, aSignatureCounter') = initialiseCounter credentialId aSignatureCounter

      -- 11. Let attestedCredentialData be the attested credential data byte
      -- array including the credentialId and publicKey.
      let attestedCredentialData =
            M.AttestedCredentialData
              { M.acdAaguid = aAAGUID,
                M.acdCredentialId = credentialId,
                M.acdCredentialPublicKey = cosePubKey, -- This is selfsigned
                M.acdCredentialPublicKeyBytes = M.NoRaw
              }

      -- 12. Let authenticatorData be the byte array specified in § 6.1
      -- Authenticator Data, including attestedCredentialData as the
      -- attestedCredentialData and processedExtensions, if any, as the
      -- extensions.
      let rpIdHash = hash . encodeUtf8 . M.unRpId $ rpId
      let authenticatorData =
            ME.encodeRawAuthenticatorData
              M.AuthenticatorData
                { M.adRpIdHash = M.RpIdHash rpIdHash,
                  M.adFlags = aAuthenticatorDataFlags,
                  M.adSignCount = signatureCounter,
                  M.adAttestedCredentialData = attestedCredentialData,
                  M.adExtensions = Nothing,
                  M.adRawData = M.NoRaw
                }
      -- On successful completion of this operation, the authenticator returns
      -- the attestation object to the client.
      let attestationObject =
            M.AttestationObject
              { aoAuthData = authenticatorData,
                aoFmt = None.Format,
                aoAttStmt = ()
              }
      pure (attestationObject, authenticator {aCredentials = credentials, aSignatureCounter = aSignatureCounter'})
    where
      initialiseCounter :: M.CredentialId -> AuthenticatorSignatureCounter -> (M.SignatureCounter, AuthenticatorSignatureCounter)
      initialiseCounter _ Unsupported = (M.SignatureCounter 0, Unsupported)
      initialiseCounter _ (Global c) =
        let increment =
              if Set.member StaticCounter aConformance
                then 0
                else 1
            new = increment + c
         in (new, Global new)
      initialiseCounter key (PerCredential m) = do
        let m' = Map.insert key 1 m
        (1, PerCredential m')

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#sctn-op-get-assertion)
authenticatorGetAssertion ::
  (MonadRandom m, MonadFail m) =>
  -- | authenticator: The stored authenticator data
  Authenticator ->
  -- | rpId: The caller’s RP ID, as determined by the user agent and the client.
  M.RpId ->
  -- | hash: The hash of the serialized client data, provided by the client.
  M.ClientDataHash ->
  -- | allowCredentialDescriptorList: An OPTIONAL list of
  -- CredentialDescriptors describing credentials acceptable to the
  -- Relying Party (possibly filtered by the client), if any.
  Maybe [M.CredentialDescriptor] ->
  -- | requireUserPresence: The constant Boolean value true. It is included here as a
  -- pseudo-parameter to simplify applying this abstract authenticator model to
  -- implementations that may wish to make a test of user presence optional
  -- although WebAuthn does not.
  Bool ->
  -- | requireUserVerification: The effective user verification requirement for
  -- assertion, a Boolean value provided by the client.
  Bool ->
  Maybe M.AuthenticationExtensionsClientInputs ->
  m ((M.CredentialId, M.AuthenticatorData 'M.Authentication 'True, BS.ByteString, Maybe M.UserHandle), Authenticator)
authenticatorGetAssertion _ _ _ _ False _ _ = fail "requireUserPresence set to False"
authenticatorGetAssertion
  authenticator@AuthenticatorNone {..}
  rpId
  clientDataHash
  allowCredentialDescriptorList
  True
  _requireUserVerification
  _extensions =
    do
      -- 1. Check if all the supplied parameters are syntactically well-formed
      -- and of the correct length. If not, return an error code equivalent to
      -- "UnknownError" and terminate the operation.
      -- NOTE: Done during decoding

      -- 2. Let credentialOptions be a new empty set of public key credential
      -- sources.
      -- 3. If allowCredentialDescriptorList was supplied, then for each
      -- descriptor of allowCredentialDescriptorList:
      -- 3.1. Let credSource be the result of looking up descriptor.id in this authenticator.
      -- 3.2. If credSource is not null, append it to credentialOptions.
      -- 4. Otherwise (allowCredentialDescriptorList was not supplied), for each
      -- key -> credSource of this authenticator’s credentials map, append
      -- credSource to credentialOptions.
      -- 5. Remove any items from credentialOptions whose rpId is not equal to rpId.
      let credentialOptions = filter
            (\o -> csRpId o == rpId)
            $ case allowCredentialDescriptorList of
              Just descriptors -> mapMaybe (authenticatorLookupCredential authenticator . M.cdId) descriptors
              Nothing -> Map.elems aCredentials

      -- 6. If credentialOptions is now empty, return an error code equivalent
      -- to "NotAllowedError" and terminate the operation.
      when (null credentialOptions) (fail "NotAllowedError: No CredentialOptions (None of the existing credentials were deemed acceptable)")

      -- 7. Prompt the user to select a public key credential source
      -- slectedCredential from credentialOptions. Collect an authorization
      -- gesture confirming user consent for using selectedCredential. The
      -- prompt for the authorization gesture may be shown by the authenticator
      -- if it has its own output capability, or by the user agent otherwise.

      -- If requireUserVerification is true, the authorization gesture MUST
      -- include user verification.

      -- If requireUserPresence is true, the authorization gesture MUST include
      -- a test of user presence.

      -- If the user does not consent, return an error code equivalent to
      -- "NotAllowedError" and terminate the operation.
      -- NOTE: We always assume the user cooperates for now and choses the
      -- first possible source
      let selectedCredential = head credentialOptions

      -- 8. Let processedExtensions be the result of authenticator extension
      -- processing for each supported extension identifier → authenticator
      -- extension input in extensions.
      -- TODO: Extensions are not implemented by this library, see the TODO in the
      -- module documentation of `Crypto.WebAuthn.Model` for more information.

      -- 9. Increment the credential associated signature counter or the global
      -- signature counter value, depending on which approach is implemented by
      -- the authenticator, by some positive value. If the authenticator does
      -- not implement a signature counter, let the signature counter value
      -- remain constant at zero.
      let (signatureCounter, aSignatureCounter') = incrementCounter (csId selectedCredential) aSignatureCounter

      -- 10. Let authenticatorData be the byte array specified in § 6.1
      -- Authenticator Data including processedExtensions, if any, as the
      -- extensions and excluding attestedCredentialData.
      let rpIdHash = hash . encodeUtf8 $ M.unRpId rpId
      let authenticatorData =
            ME.encodeRawAuthenticatorData
              M.AuthenticatorData
                { M.adRpIdHash = M.RpIdHash rpIdHash,
                  M.adFlags = aAuthenticatorDataFlags,
                  M.adSignCount = signatureCounter,
                  M.adAttestedCredentialData = M.NoAttestedCredentialData,
                  M.adExtensions = Nothing,
                  M.adRawData = M.NoRaw
                }

      -- 11. Let signature be the assertion signature of the concatenation
      -- authenticatorData || hash using the privateKey of selectedCredential
      -- as shown in Figure , below. A simple, undelimited concatenation is
      -- safe to use here because the authenticator data describes its own
      -- length. The hash of the serialized client data (which potentially has
      -- a variable length) is always the last element.
      privateKey <-
        if Set.member RandomPrivateKey aConformance
          then -- Generate a new private key with the same algorithm as expected
            Key.privKey <$> Key.newKeyPair (csSignAlg selectedCredential)
          else pure $ csPrivateKey selectedCredential
      msg <-
        if Set.member RandomSignatureData aConformance
          then Random.getRandomBytes 4
          else pure $ M.unRaw (M.adRawData authenticatorData) <> BA.convert (M.unClientDataHash clientDataHash)
      signature <-
        Key.sign
          (csSignAlg selectedCredential)
          privateKey
          msg
      -- 12. If any error occurred while generating the assertion signature,
      -- return an error code equivalent to "UnknownError" and terminate the
      -- operation.
      -- NOTE: We don't produce any error

      -- 13. Return
      pure ((csId selectedCredential, authenticatorData, signature, csUserHandle selectedCredential), authenticator {aSignatureCounter = aSignatureCounter'})
    where
      -- Increments the signature counter and results in the updated version
      incrementCounter :: M.CredentialId -> AuthenticatorSignatureCounter -> (M.SignatureCounter, AuthenticatorSignatureCounter)
      incrementCounter _ Unsupported = (M.SignatureCounter 0, Unsupported)
      incrementCounter _ (Global c) =
        let increment =
              if Set.member StaticCounter aConformance
                then 0
                else 1
            new = increment + c
         in (new, Global new)
      incrementCounter key (PerCredential m) =
        let increment =
              if Set.member StaticCounter aConformance
                then 0
                else 1
            -- updateLookupWithKey results in the updated value
            -- NOTE: Rather sketchy, but should be fine for tests, this map should
            -- have all credentials
            (Just c, m') = Map.updateLookupWithKey (\_ c -> Just $ increment + c) key m
         in (c, PerCredential m')

authenticatorLookupCredential :: Authenticator -> M.CredentialId -> Maybe CredentialSource
authenticatorLookupCredential AuthenticatorNone {..} credentialId = snd <$> Map.lookupMin (Map.filter (\CredentialSource {..} -> csId == credentialId) aCredentials)
