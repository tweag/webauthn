{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

module Client () where

import qualified Client.PrivateKey as PrivateKey
import qualified Codec.CBOR.Write as CBOR
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import qualified Crypto.Fido2.Model.JavaScript.Decoding as JS
import qualified Crypto.Fido2.Operations.Attestation.None as None
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (Digest, SHA256, hash, hashlazy)
import Data.Aeson (encode)
import qualified Data.Binary as Binary
import Data.Binary.Put (putWord32be, runPut)
import qualified Data.Binary.Put as Put
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Data.ByteString.Lazy (toStrict)
import Data.Maybe (fromJust)
import qualified Data.Set as Set
import Data.Text.Encoding (decodeUtf8, encodeUtf8)

data AuthenticatorCredential = AuthenticatorCredential
  { counter :: M.SignatureCounter,
    privateKey :: PrivateKey.PrivateKey,
    publicKey :: PublicKey.PublicKey
  }

-- | The datatype holding all information needed for attestation and assertion
data Authenticator
  = AuthenticatorNone [AuthenticatorCredential]

clientAttestation :: Authenticator -> JS.PublicKeyCredentialCreationOptions -> JS.CreatedPublicKeyCredential
clientAttestation (AuthenticatorNone (cred : _)) options =
  let M.PublicKeyCredentialCreationOptions {M.pkcocChallenge, M.pkcocRp} = undefined {- TODO: decode -} options
      clientDataBS =
        encode
          JS.ClientDataJSON
            { JS.typ = "webauthn.create",
              JS.challenge = decodeUtf8 $ M.unChallenge pkcocChallenge,
              JS.origin = "https://localhost:8080/",
              JS.crossOrigin = Nothing
            }
      rpIdHash = hash . encodeUtf8 . M.unRpId . fromJust $ M.pkcreId pkcocRp
      credentialId = M.CredentialId "This is the credential"
   in undefined {- TODO: encode -}
        M.PublicKeyCredential
          { M.pkcIdentifier = credentialId,
            M.pkcResponse =
              M.AuthenticatorAttestationResponse
                { M.arcClientData =
                    M.CollectedClientData
                      { M.ccdChallenge = pkcocChallenge,
                        M.ccdOrigin = M.Origin "https://localhost:8080/",
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
            M.pkcClientExtensionResults = Nothing
          }

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
        <> M.unPublicKeyBytes acdCredentialPublicKeyBytes
