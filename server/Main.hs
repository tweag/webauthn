{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

module Main
  ( main,
  )
where

import Control.Concurrent.STM (TVar)
import qualified Control.Concurrent.STM as STM
import Control.Monad (when)
import Control.Monad.Except (lift, runExceptT, throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Maybe (MaybeT (MaybeT, runMaybeT))
import qualified Crypto.Fido2.Assertion as Assertion
import Crypto.Fido2.Attestation (Error, verifyAttestationResponse)
import qualified Crypto.Fido2.Protocol as Fido2
import Data.Aeson (FromJSON)
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
import GHC.Generics (Generic)
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

-- | @casVersion@ searches for the session with the given @SessionId@ and will compare
-- and swap it, replacing the @old@ session with the @new@ session. Returns @Nothing@
-- if the CAS was unsuccessful.
casSession :: TVar Sessions -> SessionId -> Session -> Session -> STM.STM ()
casSession sessions sessionId old new = do
  contents <- STM.readTVar sessions
  case Map.updateLookupWithKey casSession sessionId contents of
    (Just _, newMap) -> do
      STM.writeTVar sessions newMap
      pure ()
    (Nothing, _map) -> pure ()
  where
    casSession :: SessionId -> Session -> Maybe Session
    casSession _sessionId current
      | current == old = Just new
      | otherwise = Nothing

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

data RegisterBeginReq
  = RegisterBeginReq
      { userName :: Text,
        displayName :: Text
      }
  deriving (FromJSON) via (Fido2.EncodingRules RegisterBeginReq)
  deriving stock (Generic)

app :: TVar Sessions -> TVar Users -> ScottyM ()
app sessions users = do
  Scotty.middleware (staticPolicy (addBase "dist"))
  Scotty.post "/register/begin" $ beginRegistration sessions
  Scotty.post "/register/complete" $ completeRegistration sessions users
  Scotty.post "/login/begin" $ beginLogin sessions users
  Scotty.post "/login/complete" $ completeLogin sessions users
  Scotty.get "/requires-auth" $ do
    (_sessionId, session) <- getSessionScotty sessions
    when (not . isAuthenticated $ session) (Scotty.raiseStatus HTTP.status401 "Please authenticate first")
    Scotty.json @Text $ "This should only be visible when authenticated"

mkCredentialDescriptor :: Fido2.AttestedCredentialData -> Fido2.PublicKeyCredentialDescriptor
mkCredentialDescriptor Fido2.AttestedCredentialData {credentialId} =
  Fido2.PublicKeyCredentialDescriptor {typ = Fido2.PublicKey, id = credentialId, transports = Nothing}

data RegistrationResult
  = Success
  | AlreadyRegistered
  | AttestationError Error
  deriving (Eq, Show)

handleError :: Show e => Either e a -> Scotty.ActionM a
handleError (Left x) = Scotty.raiseStatus HTTP.status400 . fromStrict . pack . show $ x
handleError (Right x) = pure x

beginLogin :: TVar Sessions -> TVar Users -> Scotty.ActionM ()
beginLogin sessions users = do
  (sessionId, session) <- getSessionScotty sessions
  userId <- Scotty.jsonData @Fido2.UserId
  muser <- liftIO $ STM.atomically $ do
    (map, _) <- STM.readTVar users
    pure $ Map.lookup userId map
  User {credentials} <- maybe (Scotty.raiseStatus HTTP.status404 "User not found") pure muser
  when
    (not . isUnauthenticated $ session)
    (Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin login")
  challenge <- liftIO $ Fido2.newChallenge
  liftIO $ STM.atomically $ casSession sessions sessionId session (Authenticating challenge)
  Scotty.json $
    Fido2.PublicKeyCredentialRequestOptions
      { rpId = Nothing,
        timeout = Nothing,
        challenge = challenge,
        allowCredentials = Just (map mkCredentialDescriptor credentials),
        userVerification = Nothing
      }

completeLogin :: TVar Sessions -> TVar Users -> Scotty.ActionM ()
completeLogin sessions _users = do
  (sessionId, session) <- getSessionScotty sessions
  case session of
    Authenticating challenge -> do
      credential <- Scotty.jsonData @(Fido2.PublicKeyCredential Fido2.AuthenticatorAssertionResponse)
      case verifyLogin challenge credential of
        Left _err -> Scotty.raiseStatus HTTP.status400 "You need to be authenticating to complete login"
        Right _unit -> do
          let userId = undefined -- TODO: how do we get this??
          liftIO
            $ STM.atomically
            $ casSession sessions sessionId session (Authenticated userId)
          Scotty.json @Text "Welcome."
    _ -> Scotty.raiseStatus HTTP.status400 "You need to be authenticating to complete login"
  where
    verifyLogin ::
      Fido2.Challenge ->
      Fido2.PublicKeyCredential Fido2.AuthenticatorAssertionResponse ->
      Either Assertion.Error ()
    verifyLogin challenge credential =
      undefined

beginRegistration :: TVar Sessions -> Scotty.ActionM ()
beginRegistration sessions = do
  (sessionId, session) <- getSessionScotty sessions
  -- NOTE: We currently do not support multiple credentials per user.
  case session of
    Unauthenticated -> generateRegistrationChallenge sessionId session
    _ -> Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin registration"
  where
    generateRegistrationChallenge :: SessionId -> Session -> Scotty.ActionM ()
    generateRegistrationChallenge sessionId session = do
      registerBeginReq <- Scotty.jsonData @RegisterBeginReq
      challenge <- liftIO $ Fido2.newChallenge
      userId <- liftIO $ Fido2.newUserId
      Scotty.json $ defaultPkcco registerBeginReq userId challenge
      liftIO $ STM.atomically $ casSession sessions sessionId session (Registering userId challenge)

completeRegistration :: TVar Sessions -> TVar Users -> Scotty.ActionM ()
completeRegistration sessions users = do
  (sessionId, session) <- getSessionScotty sessions
  case session of
    Registering userId challenge ->
      verifyRegistration sessionId userId challenge
    _ ->
      Scotty.raiseStatus
        HTTP.status400
        "You need to be registering to complete registration"
  where
    verifyRegistration :: SessionId -> Fido2.UserId -> Fido2.Challenge -> Scotty.ActionM ()
    verifyRegistration sessionId userId challenge = do
      Fido2.PublicKeyCredential {response} <- Scotty.jsonData
      -- step 1 to 17
      -- We abort if we couldn't attest the credential
      attestedCredential@Fido2.AttestedCredentialData {credentialId} <-
        handleError $
          verifyAttestationResponse
            serverOrigin
            (Fido2.RpId domain)
            challenge
            Fido2.UserVerificationPreferred
            response
      -- if the credential was succesfully attested, we will see if the
      -- credential doesn't exist yet, and if it doesn't, insert it.
      result <- liftIO . STM.atomically . runExceptT $ do
        (userMap, credentialsIndex) <- lift . STM.readTVar $ users
        when (Map.member credentialId credentialsIndex) $
          throwError AlreadyRegistered
        let existingCredentials = credentials <$> Map.lookup userId userMap
        let updatedUser = User $ attestedCredential : (fromMaybe [] existingCredentials)
        lift . STM.writeTVar users $
          ( Map.insert userId updatedUser userMap,
            Map.insert credentialId userId credentialsIndex
          )
        lift $ STM.modifyTVar sessions $ Map.insert sessionId (Authenticated userId)
      handleError result

defaultPkcco :: RegisterBeginReq -> Fido2.UserId -> Fido2.Challenge -> Fido2.PublicKeyCredentialCreationOptions
defaultPkcco RegisterBeginReq {userName, displayName} userId challenge =
  Fido2.PublicKeyCredentialCreationOptions
    { rp = Fido2.PublicKeyCredentialRpEntity {id = Nothing, name = "ACME"},
      user = Fido2.PublicKeyCredentialUserEntity {id = userId, displayName = displayName, name = userName},
      challenge = challenge,
      -- Empty credentialparameters are not supported.
      pubKeyCredParams = [Fido2.PublicKeyCredentialParameters {typ = Fido2.PublicKey, alg = Fido2.ES256}],
      timeout = Nothing,
      excludeCredentials = Nothing,
      authenticatorSelection =
        Just
          Fido2.AuthenticatorSelectionCriteria
            { authenticatorAttachment = Nothing,
              residentKey = Just Fido2.ResidentKeyDiscouraged,
              userVerification = Just Fido2.UserVerificationPreferred
            },
      attestation = Nothing
    }

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
