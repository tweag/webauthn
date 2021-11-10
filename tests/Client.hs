{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

module Client (clientAttestation, spec) where

import qualified Client.PrivateKey as PrivateKey
import qualified Codec.CBOR.Write as CBOR
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import Crypto.Fido2.Model.JavaScript.Decoding (decodeCreatedPublicKeyCredential, decodePublicKeyCredentialCreationOptions)
import Crypto.Fido2.Model.JavaScript.Encoding (encodeCreatedPublicKeyCredential, encodePublicKeyCredentialCreationOptions)
import qualified Crypto.Fido2.Model.JavaScript.Types as JS
import Crypto.Fido2.Operations.Attestation (allSupportedFormats)
import qualified Crypto.Fido2.Operations.Attestation as Fido2
import qualified Crypto.Fido2.Operations.Attestation.None as None
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (Digest, SHA256, hash, hashlazy)
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import Crypto.Random (MonadRandom)
import Data.Aeson (encode)
import Data.Binary.Put (runPut)
import qualified Data.Binary.Put as Put
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Data.ByteString.Lazy (toStrict)
import Data.Either (fromRight, isRight)
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Validation (toEither)
import System.Random.Stateful (globalStdGen, uniformM)
import Test.Hspec (SpecWith, describe, it, shouldSatisfy)

data AuthenticatorCredential = AuthenticatorCredential
  { counter :: M.SignatureCounter,
    privateKey :: PrivateKey.PrivateKey,
    publicKey :: PublicKey.PublicKey
  }

-- | The datatype holding all information needed for attestation and assertion
data Authenticator
  = AuthenticatorNone [AuthenticatorCredential]

clientAttestation :: MonadRandom m => JS.PublicKeyCredentialCreationOptions -> Authenticator -> m (JS.CreatedPublicKeyCredential, Authenticator)
clientAttestation options (AuthenticatorNone creds) = do
  let M.PublicKeyCredentialCreationOptions {M.pkcocChallenge, M.pkcocRp} = fromRight (error "Test: could not decode creation options") $ decodePublicKeyCredentialCreationOptions options
      clientDataBS =
        encode
          JS.ClientDataJSON
            { JS.typ = "webauthn.create",
              JS.challenge = decodeUtf8 $ M.unChallenge pkcocChallenge,
              JS.origin = "https://localhost:8080/",
              JS.crossOrigin = Nothing
            }
      rpIdHash = hash . encodeUtf8 . M.unRpId . fromMaybe (M.RpId "localhost") $ M.pkcreId pkcocRp
      credentialId = M.CredentialId "This is the credential"
  cred <- newCredential PublicKey.COSEAlgorithmIdentifierES256
  let response =
        encodeCreatedPublicKeyCredential
          M.PublicKeyCredential
            { M.pkcIdentifier = credentialId,
              M.pkcResponse =
                M.AuthenticatorAttestationResponse
                  { M.arcClientData =
                      M.CollectedClientData
                        { M.ccdChallenge = pkcocChallenge,
                          M.ccdOrigin = M.Origin "https://localhost:8080",
                          M.ccdCrossOrigin = Just True,
                          M.ccdHash = M.ClientDataHash $ hashlazy clientDataBS
                        },
                    M.arcAttestationObject =
                      M.AttestationObject
                        { M.aoAuthData = createAuthenticatorData rpIdHash cred credentialId,
                          M.aoFmt = None.Format,
                          M.aoAttStmt = ()
                        },
                    M.arcTransports = Set.fromList [M.AuthenticatorTransportUSB, M.AuthenticatorTransportBLE, M.AuthenticatorTransportNFC, M.AuthenticatorTransportInternal]
                  },
              M.pkcClientExtensionResults = M.AuthenticationExtensionsClientOutputs {}
            }
  pure (response, AuthenticatorNone (cred : creds))

createAuthenticatorData :: Digest SHA256 -> AuthenticatorCredential -> M.CredentialId -> M.AuthenticatorData 'M.Create
createAuthenticatorData rpIdHash cred credentialId =
  M.AuthenticatorData
    { M.adRpIdHash = M.RpIdHash rpIdHash,
      M.adFlags =
        M.AuthenticatorDataFlags
          { adfUserPresent = True,
            adfUserVerified = True
          },
      M.adSignCount = counter cred,
      M.adAttestedCredentialData = attestedCredentialData,
      M.adExtensions = Nothing,
      M.adRawData =
        -- TODO: Use Put?
        BA.convert rpIdHash
          <> BS.singleton 0b01000101
          <> (toStrict . runPut $ Put.putWord32be . M.unSignatureCounter $ counter cred)
          <> encodeAttestedCredentialData attestedCredentialData
    }
  where
    attestedCredentialData =
      M.AttestedCredentialData
        { M.acdAaguid = M.AAGUID "0000000000000000",
          M.acdCredentialId = credentialId,
          M.acdCredentialPublicKey = publicKey cred, -- This is selfsigned
          M.acdCredentialPublicKeyBytes = M.PublicKeyBytes . CBOR.toStrictByteString . PublicKey.encodePublicKey $ publicKey cred
        }

    -- https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
    encodeAttestedCredentialData :: M.AttestedCredentialData 'M.Create -> BS.ByteString
    encodeAttestedCredentialData M.AttestedCredentialData {..} =
      M.unAAGUID acdAaguid
        <> (toStrict . runPut . Put.putWord16be . fromIntegral . BS.length $ M.unCredentialId acdCredentialId)
        <> M.unCredentialId credentialId
        <> M.unPublicKeyBytes acdCredentialPublicKeyBytes

newCredential :: MonadRandom m => PublicKey.COSEAlgorithmIdentifier -> m AuthenticatorCredential
newCredential PublicKey.COSEAlgorithmIdentifierES256 = newECDSACredential PublicKey.COSEAlgorithmIdentifierES256
newCredential PublicKey.COSEAlgorithmIdentifierES384 = newECDSACredential PublicKey.COSEAlgorithmIdentifierES384
newCredential PublicKey.COSEAlgorithmIdentifierES512 = newECDSACredential PublicKey.COSEAlgorithmIdentifierES512
newCredential PublicKey.COSEAlgorithmIdentifierEdDSA = do
  secret <- Ed25519.generateSecretKey
  let public = Ed25519.toPublic secret
  pure $
    AuthenticatorCredential
      { counter = M.SignatureCounter 0,
        privateKey = PrivateKey.Ed25519PrivateKey secret,
        publicKey = PublicKey.Ed25519PublicKey public
      }

newECDSACredential :: MonadRandom m => PublicKey.COSEAlgorithmIdentifier -> m AuthenticatorCredential
newECDSACredential ident =
  do
    let curve = ECC.getCurveByName $ PublicKey.toCurveName ident
    (public, private) <- ECC.generate curve
    pure $
      AuthenticatorCredential
        { counter = M.SignatureCounter 0,
          privateKey = fromMaybe (error "Not a ECDSAKey") $ PrivateKey.toECDSAKey ident private,
          publicKey = fromMaybe (error "Not a ECDSAKey") $ PublicKey.toECDSAKey ident public
        }

spec :: SpecWith ()
spec = describe "None" $
  it "succeeds" $ do
    challenge <- uniformM globalStdGen
    userId <- uniformM globalStdGen
    let user =
          M.PublicKeyCredentialUserEntity
            { M.pkcueId = userId,
              M.pkcueDisplayName = M.UserAccountDisplayName "John Doe",
              M.pkcueName = M.UserAccountName "john-doe"
            }
    let options = defaultPkcco user challenge
    (jspkCredential, _) <- clientAttestation (encodePublicKeyCredentialCreationOptions options) (AuthenticatorNone [])
    let mpkCredential = decodeCreatedPublicKeyCredential allSupportedFormats jspkCredential
    mpkCredential `shouldSatisfy` isRight
    let registerResult =
          toEither $
            Fido2.verifyAttestationResponse
              (M.Origin "https://localhost:8080")
              (M.RpIdHash $ hash ("localhost" :: BS.ByteString))
              options
              (fromRight (error "should not happend") mpkCredential)
    registerResult `shouldSatisfy` isRight

defaultPkcco :: M.PublicKeyCredentialUserEntity -> M.Challenge -> M.PublicKeyCredentialOptions 'M.Create
defaultPkcco userEntity challenge =
  M.PublicKeyCredentialCreationOptions
    { M.pkcocRp = M.PublicKeyCredentialRpEntity {M.pkcreId = Nothing, M.pkcreName = "ACME"},
      M.pkcocUser = userEntity,
      M.pkcocChallenge = challenge,
      -- Empty credentialparameters are not supported.
      M.pkcocPubKeyCredParams =
        [ M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = PublicKey.COSEAlgorithmIdentifierES256
            }
        ],
      M.pkcocTimeout = Nothing,
      M.pkcocExcludeCredentials = [],
      M.pkcocAuthenticatorSelection =
        Just
          M.AuthenticatorSelectionCriteria
            { M.ascAuthenticatorAttachment = Nothing,
              M.ascResidentKey = M.ResidentKeyRequirementDiscouraged,
              M.ascUserVerification = M.UserVerificationRequirementPreferred
            },
      M.pkcocAttestation = M.AttestationConveyancePreferenceDirect,
      M.pkcocExtensions = Nothing
    }
