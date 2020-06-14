{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main
  ( main,
  )
where

import Control.Applicative ((<|>))
import Control.Concurrent.STM (TVar)
import qualified Control.Concurrent.STM as STM
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Maybe (MaybeT (..), runMaybeT)
import Crypto.Fido2.Protocol as Fido2
import Crypto.Fido2.Attestation (Error, verifyAttestationResponse)
import qualified Crypto.Random as Random
import Data.Aeson.QQ (aesonQQ)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Lazy as LBS
import Data.List.NonEmpty
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import Data.Text (Text, pack)
import qualified Data.Text.Encoding as Text
import Data.Text.Lazy (fromStrict)
import qualified Data.Text.Lazy.Encoding as LText
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID
import Network.HTTP.Types as HTTP
import qualified Network.HTTP.Types.Status as Status
import Network.Wai.Middleware.Static (addBase, staticPolicy)
import qualified Web.Cookie as Cookie
import Web.Scotty (ScottyM)
import qualified Web.Scotty as Scotty

-- Generate a new session for the current user and expose it as a @SetCookie@.
newSession :: TVar Sessions -> IO (SessionId, Session, Cookie.SetCookie)
newSession sessions = do
  sessionId <- UUID.nextRandom
  let session = Unauthenticated
  STM.atomically $ do
    contents <- STM.readTVar sessions
    STM.writeTVar sessions $ Map.insert sessionId session contents
  pure $
    ( sessionId,
      session,
      Cookie.defaultSetCookie
        { Cookie.setCookieName = "session",
          Cookie.setCookieValue = UUID.toASCIIBytes sessionId,
          Cookie.setCookieSameSite = Just Cookie.sameSiteStrict,
          Cookie.setCookieHttpOnly = True
          -- Does not work on localhost: the browser doesn't send any cookies
          -- to a non-TLS version of localhost.
          -- TODO: Use mkcert to get a HTTPS setup for localhost.
          -- , Cookie.setCookieSecure = True
        }
    )

newSessionScotty :: TVar Sessions -> Scotty.ActionM (SessionId, Session)
newSessionScotty sessions = do
  (sessionId, session, setCookie) <- liftIO $ newSession sessions
  -- Scotty is great. Internally, it contains [(HeaderName, ByteString)]
  -- for the headers. The API does not expose this, so here we convert from
  -- bytestring to text and then internally in scotty to bytestring again..
  -- This is quite the unfortunate conversion because the Builder type can
  -- only output lazy bytestrings. Fun times.
  Scotty.setHeader
    "Set-Cookie"
    (LText.decodeUtf8 (Builder.toLazyByteString (Cookie.renderSetCookie setCookie)))
  pure (sessionId, session)

getSession :: TVar Sessions -> SessionId -> MaybeT Scotty.ActionM (SessionId, Session)
getSession sessions sessionId = do
  contents <- liftIO $ STM.atomically $ STM.readTVar sessions
  session <- MaybeT . pure $ Map.lookup sessionId contents
  pure $ (sessionId, session)

readSessionId :: MaybeT Scotty.ActionM UUID
readSessionId = do
  cookieHeader <- MaybeT $ Scotty.header "cookie"
  let cookies = Cookie.parseCookies $ LBS.toStrict $ LText.encodeUtf8 cookieHeader
  sessionCookie <- MaybeT . pure $ lookup "session" cookies
  MaybeT . pure $ UUID.fromASCIIBytes sessionCookie

-- Check if the user has a session cookie.
--
-- If the user doens't have a session set, create a new one and register it
-- with our session registry.
--
-- If the user already has a session set, we don't do anything.
getSessionScotty :: TVar Sessions -> Scotty.ActionM (SessionId, Session)
getSessionScotty sessions = do
  result <- runMaybeT $ do
    uuid <- readSessionId
    getSession sessions uuid
  maybe (newSessionScotty sessions) pure result

setSessionToRegistering :: TVar Sessions -> SessionId -> UserId -> Challenge -> IO ()
setSessionToRegistering sessions sessionId userId challenge =
  STM.atomically $ STM.modifyTVar sessions $ Map.adjust update sessionId
  where
    -- Only update hte session to Registering when the session is Unauthenticated.
    -- This prevents race conditions where two concurrent register requests happen
    -- for the same session.
    update :: Session -> Session
    update (Unauthenticated) = Registering userId challenge
    -- Keep the same state if there are racy calls to the /register endpoints.
    update a = a

-- Session data that we store for each user.
--
--                         +---> Registering ----+
--                         |                     |
--      Unauthenticated ---+                     +---> Authenticated
--                         |                     |
--                         +---> Authenticating -+
--
--  Whether we consider Authenticated right after Registering is a design
--  choice. Should be safe to do? But let's double check that the spec
--  actually guarantees that you own the public key after registering.
data Session
  = Unauthenticated
  | Registering UserId Challenge
  | Authenticating Challenge
  | Authenticated UserId
  deriving (Eq, Show)

data User
  = User
      { credentials :: [AttestedCredentialData]
      }

isUnauthenticated :: Session -> Bool
isUnauthenticated session = case session of
  Unauthenticated -> True
  _ -> False

isRegistering :: Session -> Bool
isRegistering session = case session of
  Registering _ _ -> True
  _ -> False

isAuthenticating :: Session -> Bool
isAuthenticating session = case session of
  Authenticating _ -> True
  _ -> False

isAuthenticated :: Session -> Bool
isAuthenticated session = case session of
  Authenticated _ -> True
  _ -> False

type Sessions = Map SessionId Session

type SessionId = UUID

type Users = (Map UserId User, Map CredentialId UserId)

app :: TVar Sessions -> TVar Users -> ScottyM ()
app sessions users = do
  Scotty.middleware (staticPolicy (addBase "dist"))
  Scotty.get "/register/begin" $ do
    (sessionId, session) <- getSessionScotty sessions
    -- NOTE: We currently do not support multiple credentials per user.
    when
      (not . isUnauthenticated $ session)
      (Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin registration")
    challenge <- liftIO $ newChallenge
    userId <- liftIO $ newUserId
    Scotty.json $
      PublicKeyCredentialCreationOptions
        { rp =
            PublicKeyCredentialRpEntity
              { id = Nothing,
                name = "ACME"
              },
          user =
            PublicKeyCredentialUserEntity
              { id = userId,
                displayName = "Hello",
                name = "Hello"
              },
          challenge = challenge,
          pubKeyCredParams =
            [ PublicKeyCredentialParameters
                { typ = PublicKey,
                  alg = ES256
                }
            ], -- EDIT: NO Is empty supported?
          timeout = Nothing,
          excludeCredentials = Nothing,
          authenticatorSelection =
            Just
              AuthenticatorSelectionCriteria
                { authenticatorAttachment = Nothing,
                  residentKey = Just ResidentKeyDiscouraged,
                  userVerification = Just UserVerificationRequired
                },
          attestation = Nothing
        }
    liftIO $ setSessionToRegistering sessions sessionId userId challenge
  Scotty.post "/register/complete" (handleRegistration sessions users)
  {-
  case session of
    Unauthenticated -> do
      Scotty.setStatus  Status.status401
      pure ()
    Registering challenge -> do
      let clientData' :: ClientData = Fido2.clientData (response credential)
      let challenge' = Fido2.challenge (clientData' :: ClientData)
      -- step 3
      if Fido2.typ (clientData' :: ClientData) /= Createj
      then do
        Scotty.setStatus Status.status401
        Scotty.text "typ mismatch"
      -- step 4
      else if challenge /= (Challenge  challenge')
      then do
        Scotty.setStatus Status.status401
        Scotty.text "challenge mismatch"
      -- step 5
      else if (Fido2.origin clientData') /= "http://localhost:8080"
      then do
        Scotty.setStatus Status.status401
        Scotty.text "origin mismatch"
      else do
        -- skip step 6 for now
        Scotty.writeSession Authenticated
        pure ()
        -- step 7 we get for free
        --
    Authenticating challenge -> do
      -- We should merge /login/complete and /register/complete. Same code here. Dual
      Scotty.setStatus  Status.status401
      Scotty.text "authenticating"
      pure ()
    Authenticated -> pure ()
    -}

  Scotty.get "/login/begin" $ do
    (sessionId, session) <- getSessionScotty sessions
    when
      (not . isUnauthenticated $ session)
      (Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin login")
    challenge <- liftIO $ newChallenge
    -- Scotty.writeSession . Registering . Challenge $ challenge
    identifier <- liftIO $ newUserId
    Scotty.json $
      PublicKeyCredentialRequestOptions
        { rpId = Nothing,
          timeout = Nothing,
          challenge = challenge,
          allowCredentials = Nothing,
          userVerification = Nothing
        }
    pure ()
  Scotty.post "/login/complete" $ do
    (sessionId, session) <- getSessionScotty sessions
    when
      (not . isAuthenticating $ session)
      (Scotty.raiseStatus HTTP.status400 "You need to be authenticating to complete login")
    credential <- Scotty.jsonData @(PublicKeyCredential AuthenticatorAssertionResponse)
    liftIO . print $ credential
    pure ()

data RegistrationResult = Success | AlreadyRegistered | AttestationError Error deriving (Eq, Show)

handleRegistration :: TVar Sessions -> TVar Users -> Scotty.ActionM ()
handleRegistration sessions users = do
  (sessionId, session) <- getSessionScotty sessions
  case session of
    Registering userId challenge -> verifyRegistration sessionId userId challenge
    otherwise -> Scotty.raiseStatus HTTP.status400 "You need to be registering to complete registration"
  where
    verifyRegistration sessionId userId challenge = do
      credentials@(PublicKeyCredential {response}) <- Scotty.jsonData @(PublicKeyCredential AuthenticatorAttestationResponse)
      liftIO $ print credentials
      result <- case (verifyAttestationResponse serverOrigin (RpId domain) challenge UserVerificationRequired response) of
        Left e -> pure $ AttestationError e
        Right creds@(AttestedCredentialData {credentialId}) -> liftIO $ processCredentials sessionId userId credentialId creds
      liftIO $ print result
      case result of
        AttestationError e -> Scotty.raiseStatus HTTP.status400 $ fromStrict $ pack $ show e
        AlreadyRegistered -> Scotty.raiseStatus HTTP.status400 $ "Key has already been registered with a different user"
        Success -> pure ()
    processCredentials sessionId userId credentialId creds =
      STM.atomically
        ( do
            (userMap, credentialsIndex) <- STM.readTVar users
            let result = case (Map.lookup credentialId credentialsIndex) of
                  Nothing -> Success
                  Just existingUserId -> if userId == existingUserId then Success else AlreadyRegistered
            when (result == Success) $ do
              STM.writeTVar users $ updateCredentials userMap credentialsIndex userId creds
              STM.modifyTVar sessions $ Map.insert sessionId (Authenticated userId)
            pure result
        )
    updateCredentials users credentialsIndex userId creds@(AttestedCredentialData {credentialId}) =
      ( Map.insert userId updatedUser users,
        Map.insert credentialId userId credentialsIndex
      )
      where
        existingAttestations = credentials <$> Map.lookup userId users
        updatedUser = User $ creds : (fromMaybe [] existingAttestations)

port :: Int
port = 8080

domain :: Text
domain = "localhost"

serverOrigin :: Origin
serverOrigin = Origin $ "http://" <> domain <> ":" <> (pack $ show port)

main :: IO ()
main = do
  sessions <- STM.newTVarIO Map.empty
  users <- STM.newTVarIO (Map.empty, Map.empty)
  putStrLn "You can view the web-app at: http://localhost:8080/index.html"
  Scotty.scotty port (app sessions users)
