{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedLists #-}

module Main
  ( main,
  )
where

import Control.Monad.IO.Class (liftIO)
import Crypto.Fido2 as Fido2
import qualified Crypto.Random as Random
import Data.Aeson.QQ (aesonQQ)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text.Encoding as Text
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID
import Network.Wai.Middleware.Static (staticPolicy, addBase)
import Web.Spock (SpockM)
import qualified Web.Spock as Spock
import qualified Web.Spock.Config as Spock
import qualified Network.HTTP.Types.Status as Status
import Data.List.NonEmpty

{-
instance Aeson.FromJSON PublicKeyCredential where
  parseJSON = Aeson.withObject "PublicKeyCredential" $ \obj -> do
    -- Decode the base64 public key credential
    --
-}

-- Good
data Session
  = Unauthenticated
  | Registering UserId Challenge
  | Authenticating Challenge
  | Authenticated UserId

--
--                         +---> Registering ----+
--                         |                     |
--      Unauthenticated ---+                     +---> Authenticated
--                         |                     |
--                         +---> Authenticating -+
--
--
--  Whether we consider Authenticated right after Registering is a design
--  choice I guess. I think it's safe to do

-- What I want is
--
-- deserialize gadt:
--
--  credential <- Spock.jsonBody' @_ @(PublicKeyCredential a)
--  case credential of
--    AttestationResponse resp ->
--    AssertionResponse resp ->
--
app :: SpockM () Session () ()
app = do
  Spock.middleware (staticPolicy (addBase "dist"))
  Spock.get "/register/begin" $ do
    challenge <- liftIO $ newChallenge
    -- Spock.writeSession . Registering . Challenge $ challenge
    identifier <- liftIO $ newUserId
    Spock.json $
      PublicKeyCredentialCreationOptions
        { rp =
            PublicKeyCredentialRpEntity
              { id = Nothing,
                name = "ACME"
              },
          user =
            PublicKeyCredentialUserEntity
              { id = identifier,
                displayName = "Hello",
                name = "Hello"
              },
          challenge = challenge,
          pubKeyCredParams = [PublicKeyCredentialParameters {
            typ = PublicKey,
            alg = ES256
          }], -- EDIT: NO Is empty supported?
          timeout = Nothing,
          excludeCredentials = Nothing,
          authenticatorSelection = Just AuthenticatorSelectionCriteria {
            authenticatorAttachment = Nothing,
            residentKey = Just ResidentKeyDiscouraged,
            userVerification = Just UserVerificationRequired
          },
          attestation = Nothing
        }
  Spock.post "/register/complete" $ do
    session <- Spock.readSession
    credential <- Spock.jsonBody' @_ @(PublicKeyCredential AuthenticatorAttestationResponse)
    liftIO . print $ credential
    {-
    case session of
      Unauthenticated -> do
        Spock.setStatus  Status.status401
        pure ()
      Registering challenge -> do
        let clientData' :: ClientData = Fido2.clientData (response credential)
        let challenge' = Fido2.challenge (clientData' :: ClientData)
        -- step 3
        if Fido2.typ (clientData' :: ClientData) /= Createj
        then do
          Spock.setStatus Status.status401
          Spock.text "typ mismatch"
        -- step 4
        else if challenge /= (Challenge  challenge')
        then do
          Spock.setStatus Status.status401
          Spock.text "challenge mismatch"
        -- step 5
        else if (Fido2.origin clientData') /= "http://localhost:8080"
        then do
          Spock.setStatus Status.status401
          Spock.text "origin mismatch"
        else do
          -- skip step 6 for now
          Spock.writeSession Authenticated
          pure ()
          -- step 7 we get for free
          --
      Authenticating challenge -> do
        -- We should merge /login/complete and /register/complete. Same code here. Dual
        Spock.setStatus  Status.status401
        Spock.text "authenticating"
        pure ()
      Authenticated -> pure ()
      -}
  Spock.get "/login/begin" $ do
    challenge <- liftIO $ newChallenge
    -- Spock.writeSession . Registering . Challenge $ challenge
    identifier <- liftIO $ newUserId
    Spock.json $
      PublicKeyCredentialRequestOptions
        { rpId = Nothing,
          timeout = Nothing,
          challenge = challenge,
          allowCredentials = Nothing,
          userVerification = Nothing
        }
    pure ()
  Spock.post "/login/complete" $ do
    credential <- Spock.jsonBody' @_ @(PublicKeyCredential AuthenticatorAssertionResponse)
    liftIO . print $ credential
    pure ()

main :: IO ()
main = do
  cfg <- Spock.defaultSpockCfg Unauthenticated Spock.PCNoDatabase ()
  putStrLn "http://localhost:8080/index.html"
  Spock.runSpock 8080 (Spock.spock cfg app)

