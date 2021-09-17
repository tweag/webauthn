{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module AttestationSpec (spec) where

import qualified Crypto.Fido2.Attestation as Fido2
import qualified Crypto.Fido2.Error as Fido2
import qualified Crypto.Fido2.Protocol as Fido2
import qualified Crypto.Hash as Hash
import Data.ByteString (ByteString)
import Data.Coerce (coerce)
import Data.Text (Text)
import qualified Data.Text.Encoding as Text
import Spec.Types ()
import Test.Hspec (SpecWith, describe, it)
import Test.QuickCheck.Instances.Text ()
import Test.QuickCheck.Property (property, total, (===), (==>))

spec :: SpecWith ()
spec = do
  describe "Attestation" $
    do
      it "fails if type is wrong" $
        property $
          \(resp', clientData) ->
            let resp =
                  (resp' :: Fido2.AuthenticatorAttestationResponse)
                    { Fido2.clientData = clientData {Fido2.typ = Fido2.Get}
                    }
             in case Fido2.verifyAttestationResponse undefined undefined undefined undefined resp of
                  Left x -> x === Fido2.InvalidWebauthnType
      it "fails if challenges do not match" $
        property $
          \( coerce @ByteString -> c1,
             coerce @ByteString -> c2,
             clientData,
             origin,
             rp,
             req,
             resp'
             ) ->
              -- TODO: Do not expose Challenge; but use its MonadRandom instance ... ?
              c1 /= c2
                ==> let resp =
                          (resp' :: Fido2.AuthenticatorAttestationResponse)
                            { Fido2.clientData = clientData {Fido2.typ = Fido2.Create, Fido2.challenge = c1}
                            }
                     in case Fido2.verifyAttestationResponse origin rp c2 req resp of
                          Left x -> x === Fido2.ChallengeMismatch
      it "fails if origins do not match" $
        property $
          \( c1 :: ByteString,
             coerce @Text -> origin1,
             coerce @Text -> origin2,
             resp' :: Fido2.AuthenticatorAttestationResponse,
             clientData :: Fido2.ClientData,
             rp,
             req
             ) ->
              origin1 /= origin2
                ==> let resp =
                          (resp' :: Fido2.AuthenticatorAttestationResponse)
                            { Fido2.clientData =
                                clientData
                                  { Fido2.typ = Fido2.Create,
                                    Fido2.challenge = coerce c1,
                                    Fido2.origin = origin1
                                  }
                            }
                     in case Fido2.verifyAttestationResponse origin2 rp (coerce c1) req resp of
                          Left x -> x === Fido2.RpOriginMismatch
      it "fails if rpIds do not match" $
        property $
          \( coerce @Text -> rp1,
             coerce @Text -> rp2,
             challenge,
             coerce @Text -> origin,
             resp',
             clientData,
             attestationObject,
             authData
             ) ->
              rp1 /= rp2
                ==> let resp =
                          (resp' :: Fido2.AuthenticatorAttestationResponse)
                            { Fido2.clientData =
                                clientData
                                  { Fido2.typ = Fido2.Create,
                                    Fido2.challenge = challenge,
                                    Fido2.origin = origin
                                  },
                              Fido2.attestationObject =
                                attestationObject
                                  { Fido2.authData =
                                      authData
                                        { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp2))
                                        }
                                  }
                            }
                     in case Fido2.verifyAttestationResponse origin rp1 challenge undefined resp of
                          Left x -> x === Fido2.RpIdHashMismatch
      it "fails if user not present" $
        property $
          \( coerce @Text -> rp,
             challenge,
             coerce @Text -> origin,
             resp',
             clientData,
             attestationObject,
             authData
             ) ->
              let resp =
                    (resp' :: Fido2.AuthenticatorAttestationResponse)
                      { Fido2.clientData =
                          clientData
                            { Fido2.typ = Fido2.Create,
                              Fido2.challenge = challenge,
                              Fido2.origin = origin
                            },
                        Fido2.attestationObject =
                          attestationObject
                            { Fido2.authData =
                                authData
                                  { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp)),
                                    Fido2.userPresent = False
                                  }
                            }
                      }
               in case Fido2.verifyAttestationResponse origin rp challenge undefined resp of
                    Left x -> x === Fido2.UserNotPresent
      it "fails if userverification requirement doesnt match" $
        property $
          \( coerce @Text -> rp,
             coerce @ByteString -> challenge,
             coerce @Text -> origin,
             resp',
             clientData,
             attestationObject,
             authData
             ) ->
              let resp =
                    (resp' :: Fido2.AuthenticatorAttestationResponse)
                      { Fido2.clientData =
                          clientData
                            { Fido2.typ = Fido2.Create,
                              Fido2.challenge = challenge,
                              Fido2.origin = origin
                            },
                        Fido2.attestationObject =
                          attestationObject
                            { Fido2.authData =
                                authData
                                  { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp)),
                                    Fido2.userPresent = True,
                                    Fido2.userVerified = False
                                  }
                            }
                      }
               in case Fido2.verifyAttestationResponse origin rp challenge Fido2.UserVerificationRequired resp of
                    Left x -> x === Fido2.UserNotVerified
      it "fails if no attested credential data" $
        property $
          \( coerce @Text -> rp,
             coerce @ByteString -> challenge,
             coerce @Text -> origin,
             resp',
             clientData,
             attestationObject,
             authData
             ) ->
              let resp =
                    (resp' :: Fido2.AuthenticatorAttestationResponse)
                      { Fido2.clientData =
                          clientData
                            { Fido2.typ = Fido2.Create,
                              Fido2.challenge = challenge,
                              Fido2.origin = origin
                            },
                        Fido2.attestationObject =
                          attestationObject
                            { Fido2.authData =
                                authData
                                  { Fido2.rpIdHash = Hash.hash (Text.encodeUtf8 (coerce @_ @Text rp)),
                                    Fido2.userPresent = True,
                                    Fido2.attestedCredentialData = Nothing
                                  }
                            }
                      }
               in case Fido2.verifyAttestationResponse origin rp challenge Fido2.UserVerificationPreferred resp of
                    Left x -> x === Fido2.AttestationError Fido2.AttestationCredentialDataMissing
      -- Kinda lame. We know that show is total as it's derived
      it
        "Can show Error"
        $ property $ \(err :: Fido2.Error) -> total . show $ err
