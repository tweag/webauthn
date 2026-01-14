-- | Stability: experimental
-- This module defines default values for fields of webauthn structures that
-- are optional but have a default specified. The identifiers here all have the
-- pattern of @<field>Default@ indicating that this is the default value for
-- field @<field>@ defined in 'Crypto.WebAuthn.Model.Types'
--
-- These default values are used when the respective fields are missing during
-- decoding. They may also be used by relying parties that don't want to set
-- the respective fields to their default. This is needed because defaults for
-- such fields can't be easily mapped to Haskell's records, see
-- "Crypto.WebAuthn.Model.Types#defaultFields"
module Crypto.WebAuthn.Model.Defaults
  ( ascUserVerificationDefault,
    ascResidentKeyDefault,
    corAttestationDefault,
    corExcludeCredentialsDefault,
    corHintsDefault,
    coaUserVerificationDefault,
    coaAllowCredentialsDefault,
    coaHintsDefault,
  )
where

import qualified Crypto.WebAuthn.Model.Types as M

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification)
-- Returns the default of the field 'M.ascUserVerification'
ascUserVerificationDefault :: M.UserVerificationRequirement
ascUserVerificationDefault = M.UserVerificationRequirementPreferred

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
-- Returns the default of the field 'M.ascResidentKey' based on the
-- value of [@requireResidentKey@](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey)
ascResidentKeyDefault :: Maybe Bool -> M.ResidentKeyRequirement
ascResidentKeyDefault (Just True) = M.ResidentKeyRequirementRequired
ascResidentKeyDefault _ = M.ResidentKeyRequirementDiscouraged

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-attestation)
-- Returns the default of the field 'M.corAttestation'
corAttestationDefault :: M.AttestationConveyancePreference
corAttestationDefault = M.AttestationConveyancePreferenceNone

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialcreationoptions-excludecredentials)
-- Returns the default of the field 'M.corExcludeCredentials'
corExcludeCredentialsDefault :: [M.CredentialDescriptor]
corExcludeCredentialsDefault = []

-- | [(spec)](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-hints)
-- Returns the default of the field 'M.corHints'
corHintsDefault :: [M.PublicKeyCredentialHint]
corHintsDefault = []

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-userverification)
-- Returns the default of the field 'M.coaUserVerification'
coaUserVerificationDefault :: M.UserVerificationRequirement
coaUserVerificationDefault = M.UserVerificationRequirementPreferred

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials)
-- Returns the default of the field 'M.coaAllowCredentials'
coaAllowCredentialsDefault :: [M.CredentialDescriptor]
coaAllowCredentialsDefault = []

-- | [(spec)](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-hints)
-- Returns the default of the field 'M.coaHints'
coaHintsDefault :: [M.PublicKeyCredentialHint]
coaHintsDefault = []
