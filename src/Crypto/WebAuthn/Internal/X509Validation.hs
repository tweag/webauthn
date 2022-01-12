-- |
-- License     : BSD-style
-- Copyright   : (c) 2010-2013 Vincent Hanquez <vincent@snarc.org>
--
-- The 'validatePure' function in this module is part of upstream
-- x509-certificate in master after <https://github.com/vincenthz/hs-certificate/pull/126>,
-- but no new version has yet been released
-- [on hackage](https://hackage.haskell.org/package/x509-validation).
--
-- In order to be able to release this webauthn library onto hackage we're
-- temporarily inlining its implementation here.
module Crypto.WebAuthn.Internal.X509Validation
  ( validatePure,
  )
where

import qualified Data.Hourglass as HG
import Data.List (find, intersect)
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Data.X509.Validation as X509

-- | Validate a certificate chain with explicit pure parameters. This function is copied from [here](https://github.com/vincenthz/hs-certificate/blob/824cca5fba0c7c243c3561727ba16834e33fd32d/x509-validation/Data/X509/Validation.hs#L211-L319).
validatePure ::
  -- | The time for which to check validity for
  HG.DateTime ->
  -- | Hooks to use
  X509.ValidationHooks ->
  -- | Checks to do
  X509.ValidationChecks ->
  -- | The trusted certificate store for CA
  X509.CertificateStore ->
  -- | Identification of the connection
  X509.ServiceID ->
  -- | The certificate chain we want to validate
  X509.CertificateChain ->
  -- | the return failed reasons (empty list is no failure)
  [X509.FailedReason]
validatePure _ _ _ _ _ (X509.CertificateChain []) = [X509.EmptyChain]
validatePure validationTime hooks checks store (fqhn, _) (X509.CertificateChain (top : rchain)) =
  X509.hookFilterReason hooks (doLeafChecks |> doCheckChain 0 top rchain)
  where
    isExhaustive = X509.checkExhaustive checks
    a |> b = exhaustive isExhaustive a b

    doLeafChecks = doNameCheck top ++ doV3Check topCert ++ doKeyUsageCheck topCert
      where
        topCert = X509.getCertificate top

    doCheckChain :: Int -> X509.SignedCertificate -> [X509.SignedCertificate] -> [X509.FailedReason]
    doCheckChain level current chain =
      doCheckCertificate (X509.getCertificate current)
        -- check if we have a trusted certificate in the store belonging to this issuer.
        |> ( case X509.findCertificate (X509.certIssuerDN cert) store of
               Just trustedSignedCert -> checkSignature current trustedSignedCert
               Nothing
                 | isSelfSigned cert -> [X509.SelfSigned] |> checkSignature current current
                 | null chain -> [X509.UnknownCA]
                 | otherwise ->
                   case findIssuer (X509.certIssuerDN cert) chain of
                     Nothing -> [X509.UnknownCA]
                     Just (issuer, remaining) ->
                       checkCA level (X509.getCertificate issuer)
                         |> checkSignature current issuer
                         |> doCheckChain (level + 1) issuer remaining
           )
      where
        cert = X509.getCertificate current
    -- in a strict ordering check the next certificate has to be the issuer.
    -- otherwise we dynamically reorder the chain to have the necessary certificate
    findIssuer issuerDN chain
      | X509.checkStrictOrdering checks =
        case chain of
          [] -> error "not possible"
          (c : cs)
            | matchSubjectIdentifier issuerDN (X509.getCertificate c) -> Just (c, cs)
            | otherwise -> Nothing
      | otherwise =
        (\x -> (x, filter (/= x) chain)) `fmap` find (matchSubjectIdentifier issuerDN . X509.getCertificate) chain
    matchSubjectIdentifier = X509.hookMatchSubjectIssuer hooks

    -- we check here that the certificate is allowed to be a certificate
    -- authority, by checking the BasicConstraint extension. We also check,
    -- if present the key usage extension for ability to cert sign. If this
    -- extension is not present, then according to RFC 5280, it's safe to
    -- assume that only cert sign (and crl sign) are allowed by this certificate.
    checkCA :: Int -> X509.Certificate -> [X509.FailedReason]
    checkCA level cert
      | not (X509.checkCAConstraints checks) = []
      | allowedSign && allowedCA && allowedDepth = []
      | otherwise =
        ([X509.NotAllowedToSign | not allowedSign])
          ++ ([X509.NotAnAuthority | not allowedCA])
          ++ ([X509.AuthorityTooDeep | not allowedDepth])
      where
        extensions = X509.certExtensions cert
        allowedSign = case X509.extensionGet extensions of
          Just (X509.ExtKeyUsage flags) -> X509.KeyUsage_keyCertSign `elem` flags
          Nothing -> True
        (allowedCA, pathLen) = case X509.extensionGet extensions of
          Just (X509.ExtBasicConstraints True pl) -> (True, pl)
          _ -> (False, Nothing)
        allowedDepth = case pathLen of
          Nothing -> True
          Just pl
            | fromIntegral pl >= level -> True
            | otherwise -> False

    doNameCheck cert
      | not (X509.checkFQHN checks) = []
      | otherwise = X509.hookValidateName hooks fqhn (X509.getCertificate cert)

    doV3Check cert
      | X509.checkLeafV3 checks = case X509.certVersion cert of
        2 {- confusingly it means X509.V3 -} -> []
        _ -> [X509.LeafNotV3]
      | otherwise = []

    doKeyUsageCheck cert =
      compareListIfExistAndNotNull mflags (X509.checkLeafKeyUsage checks) X509.LeafKeyUsageNotAllowed
        ++ compareListIfExistAndNotNull mpurposes (X509.checkLeafKeyPurpose checks) X509.LeafKeyPurposeNotAllowed
      where
        mflags = case X509.extensionGet $ X509.certExtensions cert of
          Just (X509.ExtKeyUsage keyflags) -> Just keyflags
          Nothing -> Nothing
        mpurposes = case X509.extensionGet $ X509.certExtensions cert of
          Just (X509.ExtExtendedKeyUsage keyPurposes) -> Just keyPurposes
          Nothing -> Nothing
        -- compare a list of things to an expected list. the expected list
        -- need to be a subset of the list (if not Nothing), and is not will
        -- return [err]
        compareListIfExistAndNotNull Nothing _ _ = []
        compareListIfExistAndNotNull (Just list) expected err
          | null expected = []
          | intersect expected list == expected = []
          | otherwise = [err]

    doCheckCertificate cert =
      exhaustiveList
        (X509.checkExhaustive checks)
        [ (X509.checkTimeValidity checks, X509.hookValidateTime hooks validationTime cert)
        ]
    isSelfSigned :: X509.Certificate -> Bool
    isSelfSigned cert = X509.certSubjectDN cert == X509.certIssuerDN cert

    -- check signature of 'signedCert' against the 'signingCert'
    checkSignature signedCert signingCert =
      case X509.verifySignedSignature signedCert (X509.certPubKey $ X509.getCertificate signingCert) of
        X509.SignaturePass -> []
        X509.SignatureFailed r -> [X509.InvalidSignature r]

exhaustive :: Bool -> [X509.FailedReason] -> [X509.FailedReason] -> [X509.FailedReason]
exhaustive isExhaustive l1 l2
  | null l1 = l2
  | isExhaustive = l1 ++ l2
  | otherwise = l1

exhaustiveList :: Bool -> [(Bool, [X509.FailedReason])] -> [X509.FailedReason]
exhaustiveList _ [] = []
exhaustiveList isExhaustive ((performCheck, c) : cs)
  | performCheck = exhaustive isExhaustive c (exhaustiveList isExhaustive cs)
  | otherwise = exhaustiveList isExhaustive cs
