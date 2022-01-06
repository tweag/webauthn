{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RecordWildCards #-}

module Emulation.Authenticator
  ( PublicKeyCredentialSource (..),
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
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA as RSA
import Crypto.Random (MonadRandom)
import qualified Crypto.Random as Random
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Model.Binary.Encoding as ME
import qualified Crypto.WebAuthn.Operations.Attestation.None as None
import qualified Crypto.WebAuthn.PublicKey as PublicKey
import qualified Data.ByteArray as BA
import Data.List (find)
import qualified Data.Map as Map
import Data.Maybe (fromJust, fromMaybe, mapMaybe)
import qualified Data.Set as Set
import Data.Text.Encoding (encodeUtf8)
import qualified Emulation.Client.PrivateKey as PrivateKey

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#public-key-credential-source)
-- A stored credential.
data PublicKeyCredentialSource = PublicKeyCredentialSource
  { pkcsId :: M.CredentialId,
    pkcsPrivateKey :: PrivateKey.PrivateKey,
    pkcsRpId :: M.RpId,
    pkcsUserHandle :: Maybe M.UserHandle
  }
  deriving (Show)

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
    aCredentials :: Map.Map (M.RpId, M.UserHandle) PublicKeyCredentialSource,
    aSignatureCounter :: AuthenticatorSignatureCounter,
    aSupportedAlgorithms :: Set.Set PublicKey.COSEAlgorithmIdentifier,
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
  -- | rpEntity: The Relying Party's PublicKeyCredentialRpEntity.
  M.PublicKeyCredentialRpEntity ->
  -- | userEntity: The user account’s PublicKeyCredentialUserEntity, containing
  -- the user handle given by the Relying Party.
  M.PublicKeyCredentialUserEntity ->
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
  -- | credTypesAndPubKeyAlgs: A sequence of pairs of PublicKeyCredentialType
  -- and public key algorithms (COSEAlgorithmIdentifier) requested by the
  -- Relying Party. This sequence is ordered from most preferred to least
  -- preferred. The authenticator makes a best-effort to create the most
  -- preferred credential that it can.
  [M.PublicKeyCredentialParameters] ->
  -- | excludeCredentialDescriptorList: An OPTIONAL list of
  -- PublicKeyCredentialDescriptor objects provided by the Relying Party with
  -- the intention that, if any of these are known to the authenticator, it
  -- SHOULD NOT create a new credential. excludeCredentialDescriptorList
  -- contains a list of known credentials.
  [M.PublicKeyCredentialDescriptor] ->
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
      let rpId = fromJust $ M.pkcreId rpEntity

      -- 2. Check if at least one of the specified combinations of
      -- PublicKeyCredentialType and cryptographic parameters in
      -- credTypesAndPubKeyAlgs is supported. If not, return an error code
      -- equivalent to "NotSupportedError" and terminate the operation.
      param <- case find ((`Set.member` aSupportedAlgorithms) . M.pkcpAlg) credTypesAndPubKeyAlgs of
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
      forM_ excludeCredentialDescriptorList $ \descriptor -> case authenticatorLookupCredential authenticator (M.pkcdId descriptor) of
        Just item -> do
          when (rpId == pkcsRpId item) (fail "InvalidStateError")
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
      -- using the combination of PublicKeyCredentialType and cryptographic
      -- parameters represented by the first item in credTypesAndPubKeyAlgs that
      -- is supported by this authenticator.
      (publicKey, privateKey) <- newKeyPair $ M.pkcpAlg param

      -- 7.2. Let userHandle be userEntity.id.
      let userHandle = M.pkcueId userEntity

      -- 7.4 If requireResidentKey is true or the authenticator chooses to
      -- create a client-side discoverable public key credential source:

      -- 7.4.1 Let credentialId be a new credential id.
      -- NOTE: We need to have a CredentialId before we can construct the
      -- credentialSource.
      -- NOTE: We always choose to construct a clientside discoverable
      -- credential, as this is allowed (See 7.4).
      -- TODO: Use deterministic random number generator, and ensure that we
      -- use a single random number generator across the entire library.
      credentialId <- M.generateCredentialId

      -- 7.4.2. Set credentialSource.id to credentialId.
      -- 7.3.  Let credentialSource be a new public key credential source with the fields:
      let credentialSource =
            PublicKeyCredentialSource
              { pkcsId = credentialId,
                pkcsPrivateKey = privateKey,
                pkcsRpId = rpId,
                pkcsUserHandle = Just userHandle
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
                M.acdCredentialPublicKey = publicKey, -- This is selfsigned
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
  -- PublicKeyCredentialDescriptors describing credentials acceptable to the
  -- Relying Party (possibly filtered by the client), if any.
  Maybe [M.PublicKeyCredentialDescriptor] ->
  -- | requireUserPresence: The constant Boolean value true. It is included here as a
  -- pseudo-parameter to simplify applying this abstract authenticator model to
  -- implementations that may wish to make a test of user presence optional
  -- although WebAuthn does not.
  Bool ->
  -- | requireUserVerification: The effective user verification requirement for
  -- assertion, a Boolean value provided by the client.
  Bool ->
  Maybe M.AuthenticationExtensionsClientInputs ->
  m ((M.CredentialId, M.AuthenticatorData 'M.Get 'True, PrivateKey.Signature, Maybe M.UserHandle), Authenticator)
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
            (\o -> pkcsRpId o == rpId)
            $ case allowCredentialDescriptorList of
              Just descriptors -> mapMaybe (authenticatorLookupCredential authenticator . M.pkcdId) descriptors
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
      -- TODO: We don't suport extensions

      -- 9. Increment the credential associated signature counter or the global
      -- signature counter value, depending on which approach is implemented by
      -- the authenticator, by some positive value. If the authenticator does
      -- not implement a signature counter, let the signature counter value
      -- remain constant at zero.
      let (signatureCounter, aSignatureCounter') = incrementCounter (pkcsId selectedCredential) aSignatureCounter

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
            snd <$> newKeyPair (PrivateKey.toCOSEAlgorithmIdentifier $ pkcsPrivateKey selectedCredential)
          else pure $ pkcsPrivateKey selectedCredential
      msg <-
        if Set.member RandomSignatureData aConformance
          then Random.getRandomBytes 4
          else pure $ M.unRaw (M.adRawData authenticatorData) <> BA.convert (M.unClientDataHash clientDataHash)
      signature <-
        PrivateKey.sign
          privateKey
          msg
      -- 12. If any error occurred while generating the assertion signature,
      -- return an error code equivalent to "UnknownError" and terminate the
      -- operation.
      -- NOTE: We don't produce any error

      -- 13. Return
      pure ((pkcsId selectedCredential, authenticatorData, signature, pkcsUserHandle selectedCredential), authenticator {aSignatureCounter = aSignatureCounter'})
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

-- TODO: Surely there must be a beter function than lookpMin . filter
authenticatorLookupCredential :: Authenticator -> M.CredentialId -> Maybe PublicKeyCredentialSource
authenticatorLookupCredential AuthenticatorNone {..} credentialId = snd <$> Map.lookupMin (Map.filter (\PublicKeyCredentialSource {..} -> pkcsId == credentialId) aCredentials)

newKeyPair :: MonadRandom m => PublicKey.COSEAlgorithmIdentifier -> m (PublicKey.PublicKey, PrivateKey.PrivateKey)
newKeyPair PublicKey.COSEAlgorithmIdentifierES256 = newECDSAKeyPair PublicKey.COSEAlgorithmIdentifierES256
newKeyPair PublicKey.COSEAlgorithmIdentifierES384 = newECDSAKeyPair PublicKey.COSEAlgorithmIdentifierES384
newKeyPair PublicKey.COSEAlgorithmIdentifierES512 = newECDSAKeyPair PublicKey.COSEAlgorithmIdentifierES512
newKeyPair PublicKey.COSEAlgorithmIdentifierEdDSA = do
  secret <- Ed25519.generateSecretKey
  let public = Ed25519.toPublic secret
  pure (PublicKey.Ed25519PublicKey public, PrivateKey.Ed25519PrivateKey secret)
newKeyPair PublicKey.COSEAlgorithmIdentifierRS1 = newRSAKeyPair PublicKey.COSEAlgorithmIdentifierRS1 160
newKeyPair PublicKey.COSEAlgorithmIdentifierRS256 = newRSAKeyPair PublicKey.COSEAlgorithmIdentifierRS256 256
newKeyPair PublicKey.COSEAlgorithmIdentifierRS384 = newRSAKeyPair PublicKey.COSEAlgorithmIdentifierRS384 384
newKeyPair PublicKey.COSEAlgorithmIdentifierRS512 = newRSAKeyPair PublicKey.COSEAlgorithmIdentifierRS512 512

newECDSAKeyPair :: MonadRandom m => PublicKey.COSEAlgorithmIdentifier -> m (PublicKey.PublicKey, PrivateKey.PrivateKey)
newECDSAKeyPair ident = do
  let curve = ECC.getCurveByName $ PublicKey.toCurveName ident
  (public, private) <- ECC.generate curve
  let privateKey = fromMaybe (error "Not an ECDSAKey") $ PrivateKey.toECDSAKey ident private
      publicKey = fromMaybe (error "Not an ECDSAKey") $ PublicKey.toECDSAKey ident public
  pure (publicKey, privateKey)

newRSAKeyPair :: MonadRandom m => PublicKey.COSEAlgorithmIdentifier -> Int -> m (PublicKey.PublicKey, PrivateKey.PrivateKey)
newRSAKeyPair ident publicSize = do
  -- 65537 is one of the most frequently used exponents for RSA
  (public, private) <- RSA.generate publicSize 65537
  let privateKey = fromMaybe (error "Not an RSAKey") $ PrivateKey.toRSAKey ident private
      publicKey = fromMaybe (error "Not an RSAKey") $ toRSAKey ident public
  pure (publicKey, privateKey)
  where
    toRSAKey PublicKey.COSEAlgorithmIdentifierRS1 pk = pure . PublicKey.RS1PublicKey $ pk
    toRSAKey PublicKey.COSEAlgorithmIdentifierRS256 pk = pure . PublicKey.RS256PublicKey $ pk
    toRSAKey PublicKey.COSEAlgorithmIdentifierRS384 pk = pure . PublicKey.RS384PublicKey $ pk
    toRSAKey PublicKey.COSEAlgorithmIdentifierRS512 pk = pure . PublicKey.RS512PublicKey $ pk
    toRSAKey _ _ = Nothing
