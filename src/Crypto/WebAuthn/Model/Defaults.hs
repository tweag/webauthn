module Crypto.WebAuthn.Model.Defaults
  ( ascUserVerificationDefault,
    ascResidentKeyDefault,
    corAttestationDefault,
    corExcludeCredentialsDefault,
    coaUserVerificationDefault,
    coaAllowCredentialsDefault,
  )
where

import qualified Crypto.WebAuthn.Model.Types as M

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification)
-- Returns the default of the field 'M.ascUserVerification'
ascUserVerificationDefault :: M.UserVerificationRequirement
ascUserVerificationDefault = M.UserVerificationRequirementPreferred

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey)
-- Returns the default of the field 'M.ascResidentKey' based on the
-- value of 'requireResidentKey'
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

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-userverification)
-- Returns the default of the field 'M.coaUserVerification'
coaUserVerificationDefault :: M.UserVerificationRequirement
coaUserVerificationDefault = M.UserVerificationRequirementPreferred

-- | [(spec)](https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials)
-- Returns the default of the field 'M.coaAllowCredentials'
coaAllowCredentialsDefault :: [M.CredentialDescriptor]
coaAllowCredentialsDefault = []
