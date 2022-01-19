{-# LANGUAGE DataKinds #-}
{-# LANGUAGE RecordWildCards #-}

-- | This module implements the Apple Attestation Statement signing procedure.
-- We use our own certificate, which will result in a Unverified
-- authenticator. In reality, the Apple device will have the "Apple anonymous
-- attestation CA" generate a X.509 certificate, which is then used instead.
module Emulation.Authenticator.AttestationStatementFormat.Apple (signAuthenticatorData) where

import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.ECC.Types as ECC
import Crypto.Random (MonadRandom)
import qualified Crypto.WebAuthn.AttestationStatementFormat.Apple as Apple
import qualified Crypto.WebAuthn.Cose.Internal.Verify as Verify
import qualified Crypto.WebAuthn.Cose.Key as Cose
import Crypto.WebAuthn.Internal.Utils (AppleNonceExtension (AppleNonceExtension))
import qualified Crypto.WebAuthn.Model as M
import qualified Data.ASN1.Types as ASN1
import qualified Data.ByteArray as BA
import qualified Data.Hourglass as HG
import qualified Data.X509 as X509
import qualified Spec.Key as Key

signAuthenticatorData :: MonadRandom m => M.AuthenticatorData 'M.Registration 'True -> Key.PrivateKey -> M.ClientDataHash -> m (M.AttestationObject 'True)
signAuthenticatorData authData@M.AuthenticatorData {..} privKey clientDataHash = do
  -- 1. Let authenticatorData denote the authenticator data for the attestation, and
  -- let clientDataHash denote the hash of the serialized client data.
  -- NOTE: Done in patternmatch

  -- 2. Concatenate authenticatorData and clientDataHash to form nonceToHash.
  let nonceToHash = M.unRaw adRawData <> BA.convert (M.unClientDataHash clientDataHash)

  -- 3. Perform SHA-256 hash of nonceToHash to produce nonce.
  let nonce = Hash.hash nonceToHash :: Hash.Digest Hash.SHA256

  -- 4. Let Apple anonymous attestation CA generate an X.509 certificate for the
  -- credential public key and include the nonce as a certificate extension with
  -- OID 1.2.840.113635.100.8.2. credCert denotes this certificate. The credCert
  -- thus serves as a proof of the attestation, and the included nonce proves the
  -- attestation is live. In addition to that, the nonce also protects the
  -- integrity of the authenticatorData and client data.
  let appleNonceExtension = AppleNonceExtension nonce
      appleNonceExtensionRaw = X509.extensionEncode False appleNonceExtension
  let credCert =
        X509.Certificate
          { certVersion = 2,
            certSerial = 1630537327137,
            certSignatureAlg = X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC,
            certIssuerDN =
              X509.DistinguishedName [],
            certValidity =
              ( HG.DateTime
                  { dtDate = HG.Date {dateYear = 2021, dateMonth = HG.December, dateDay = 22},
                    dtTime = HG.TimeOfDay {todHour = 0, todMin = 0, todSec = 0, todNSec = 0}
                  },
                HG.DateTime
                  { dtDate = HG.Date {dateYear = 2021, dateMonth = HG.December, dateDay = 25},
                    dtTime = HG.TimeOfDay {todHour = 0, todMin = 0, todSec = 0, todNSec = 0}
                  }
              ),
            certSubjectDN = X509.DistinguishedName [],
            certPubKey =
              X509.PubKeyEC
                ( X509.PubKeyEC_Named
                    { pubkeyEC_name = ECC.SEC_p256r1,
                      pubkeyEC_pub =
                        X509.SerializedPoint
                          "\EOT\209$\176\233\255\129\146r<\158\226i\
                          \\250O\129p\211s\224\&2\134\207\136\n\238\
                          \\199\NUL\138\DC4\205\234drIc\224[\184\196J\
                          \\159\152\r\237\DC2\170\138\&3y\\\248\GS1\
                          \\231A\SYN\206\214\241\244\197\235\f5\143"
                    }
                ),
            certExtensions = X509.Extensions $ Just [appleNonceExtensionRaw]
          }
  let pubKey = M.acdCredentialPublicKey adAttestedCredentialData
  let alg = Cose.keySignAlg pubKey
  signedCredCert <-
    X509.objectToSignedExactF
      ( Key.sign alg privKey
          >=> ( \bs ->
                  pure (bs, X509.SignatureALG X509.HashSHA256 X509.PubKeyALG_EC)
              )
      )
      credCert

  pure $
    M.AttestationObject
      { aoAuthData = authData,
        aoFmt = Apple.Format,
        aoAttStmt =
          Apple.Statement
            { x5c = pure signedCredCert,
              sNonce = nonce,
              pubKey = Verify.fromCose pubKey
            }
      }
