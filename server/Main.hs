{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main
  ( main,
  )
where

import Control.Concurrent.STM (TVar)
import qualified Control.Concurrent.STM as STM
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Maybe (MaybeT (MaybeT, runMaybeT))
import Crypto.Fido2.Attestation (Error, verifyAttestationResponse)
import qualified Crypto.Fido2.Protocol as Fido2
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy as LBS
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (fromMaybe)
import Data.Text (Text, pack)
import Data.Text.Lazy (fromStrict)
import qualified Data.Text.Lazy.Encoding as LText
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID
import qualified Network.HTTP.Types as HTTP
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

setSessionToRegistering :: TVar Sessions -> SessionId -> Fido2.UserId -> Fido2.Challenge -> IO ()
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
  | Registering Fido2.UserId Fido2.Challenge
  | Authenticating Fido2.Challenge
  | Authenticated Fido2.UserId
  deriving (Eq, Show)

data User
  = User
      { credentials :: [Fido2.AttestedCredentialData]
      }

isUnauthenticated :: Session -> Bool
isUnauthenticated session = case session of
  Unauthenticated -> True
  _ -> False

_isRegistering :: Session -> Bool
_isRegistering session = case session of
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

type Users = (Map Fido2.UserId User, Map Fido2.CredentialId Fido2.UserId)

app :: TVar Sessions -> TVar Users -> ScottyM ()
app sessions users = do
  Scotty.middleware (staticPolicy (addBase "dist"))
  Scotty.get "/register/begin" $ do
    (sessionId, session) <- getSessionScotty sessions
    -- NOTE: We currently do not support multiple credentials per user.
    when
      (not . isUnauthenticated $ session)
      (Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin registration")
    challenge <- liftIO $ Fido2.newChallenge
    userId <- liftIO $ Fido2.newUserId
    Scotty.json $
      Fido2.PublicKeyCredentialCreationOptions
        { rp =
            Fido2.PublicKeyCredentialRpEntity
              { id = Nothing,
                name = "ACME"
              },
          user =
            Fido2.PublicKeyCredentialUserEntity
              { id = userId,
                displayName = "Hello",
                name = "Hello"
              },
          challenge = challenge,
          pubKeyCredParams =
            [ Fido2.PublicKeyCredentialParameters
                { typ = Fido2.PublicKey,
                  alg = Fido2.ES256
                }
            ], -- EDIT: NO Is empty supported?
          timeout = Nothing,
          excludeCredentials = Nothing,
          authenticatorSelection =
            Just
              Fido2.AuthenticatorSelectionCriteria
                { authenticatorAttachment = Nothing,
                  residentKey = Just Fido2.ResidentKeyDiscouraged,
                  userVerification = Just Fido2.UserVerificationRequired
                },
          attestation = Nothing
        }
    liftIO $ setSessionToRegistering sessions sessionId userId challenge
  Scotty.post "/register/complete" (handleRegistration sessions users)
  Scotty.get "/login/begin" $ do
    (_sessionId, session) <- getSessionScotty sessions
    when
      (not . isUnauthenticated $ session)
      (Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin login")
    challenge <- liftIO $ Fido2.newChallenge
    -- Scotty.writeSession . Registering . Challenge $ challenge
    _identifier <- liftIO $ Fido2.newUserId
    Scotty.json $
      Fido2.PublicKeyCredentialRequestOptions
        { rpId = Nothing,
          timeout = Nothing,
          challenge = challenge,
          allowCredentials = Nothing,
          userVerification = Nothing
        }
    pure ()
  Scotty.post "/login/complete" $ do
    (_sessionId, session) <- getSessionScotty sessions
    when
      (not . isAuthenticating $ session)
      (Scotty.raiseStatus HTTP.status400 "You need to be authenticating to complete login")
    credential <- Scotty.jsonData @(Fido2.PublicKeyCredential Fido2.AuthenticatorAssertionResponse)
    liftIO . print $ credential
    pure ()
  Scotty.get "/requires-auth" $ do
    (_sessionId, session) <- getSessionScotty sessions
    when (not . isAuthenticated $ session) (Scotty.raiseStatus HTTP.status401 "Please authenticate first")
    Scotty.json @Text $ "This should only be visible when authenticated"

data RegistrationResult = Success | AlreadyRegistered | AttestationError Error deriving (Eq, Show)

handleRegistration :: TVar Sessions -> TVar Users -> Scotty.ActionM ()
handleRegistration sessions users = do
  (sessionId, session) <- getSessionScotty sessions
  case session of
    Registering userId challenge -> verifyRegistration sessionId userId challenge
    _ -> Scotty.raiseStatus HTTP.status400 "You need to be registering to complete registration"
  where
    verifyRegistration sessionId userId challenge = do
      credentials@(Fido2.PublicKeyCredential {response}) <- Scotty.jsonData @(Fido2.PublicKeyCredential Fido2.AuthenticatorAttestationResponse)
      liftIO $ print credentials
      result <- case (verifyAttestationResponse serverOrigin (Fido2.RpId domain) challenge Fido2.UserVerificationRequired response) of
        Left e -> pure $ AttestationError e
        Right creds@(Fido2.AttestedCredentialData {credentialId}) -> liftIO $ processCredentials sessionId userId credentialId creds
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
    updateCredentials users credentialsIndex userId creds@(Fido2.AttestedCredentialData {credentialId}) =
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

serverOrigin :: Fido2.Origin
serverOrigin = Fido2.Origin $ "http://" <> domain <> ":" <> (pack $ show port)

main :: IO ()
main = do
  sessions <- STM.newTVarIO Map.empty
  users <- STM.newTVarIO (Map.empty, Map.empty)
  putStrLn "You can view the web-app at: http://localhost:8080/index.html"
  Scotty.scotty port (app sessions users)
