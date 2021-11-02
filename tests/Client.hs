{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

module Client () where

import qualified Codec.CBOR.Write as CBOR
import qualified Crypto.Fido2.Model as M
import qualified Crypto.Fido2.Model.JavaScript as JS
import qualified Crypto.Fido2.Model.JavaScript.Decoding as JS
import qualified Crypto.Fido2.Operations.Attestation.None as None
import qualified Crypto.Fido2.PublicKey as PublicKey
import Crypto.Hash (hash, hashlazy)
import Data.Aeson (encode)
import Data.Maybe (fromJust)
import Data.Set as Set
import Data.Text.Encoding (decodeUtf8, encodeUtf8)

data Authenticator
  = AuthenticatorNone M.SignatureCounter PublicKey.PublicKey

clientAttestation :: Authenticator -> JS.PublicKeyCredentialCreationOptions -> JS.CreatedPublicKeyCredential
clientAttestation (AuthenticatorNone sc pk) options =
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
                      { M.aoAuthData =
                          M.AuthenticatorData
                            { M.adRpIdHash = M.RpIdHash rpIdHash,
                              M.adFlags =
                                M.AuthenticatorDataFlags
                                  { adfUserPresent = True,
                                    adfUserVerified = True
                                  },
                              M.adSignCount = sc,
                              M.adAttestedCredentialData =
                                M.AttestedCredentialData
                                  { M.acdAaguid = M.AAGUID "0000000000000000",
                                    M.acdCredentialId = credentialId,
                                    M.acdCredentialPublicKey = pk, -- This is selfsigned
                                    M.acdCredentialPublicKeyBytes = M.PublicKeyBytes . CBOR.toStrictByteString $ PublicKey.encodePublicKey pk
                                  },
                              M.adExtensions = Nothing,
                              M.adRawData = undefined
                            },
                        M.aoFmt = None.Format,
                        M.aoAttStmt = ()
                      },
                  M.arcTransports = Set.fromList [M.AuthenticatorTransportUSB, M.AuthenticatorTransportBLE, M.AuthenticatorTransportNFC, M.AuthenticatorTransportInternal]
                },
            M.pkcClientExtensionResults = Nothing
          }
