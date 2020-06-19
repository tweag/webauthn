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
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Lazy as LText
import qualified Data.Text.Lazy.Encoding as LText
import Data.UUID (UUID)
import qualified Data.UUID as UUID
import qualified Data.UUID.V4 as UUID
import qualified Database
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
          Cookie.setCookieHttpOnly = True,
          Cookie.setCookiePath = Just "/"
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
  | Authenticating Fido2.UserId Fido2.Challenge
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
  Authenticating _ _ -> True
  _ -> False

isAuthenticated :: Session -> Bool
isAuthenticated session = case session of
  Authenticated _ -> True
  _ -> False

type Sessions = Map SessionId Session

type SessionId = UUID

data RegisterBeginReq
  = RegisterBeginReq
      { userName :: Text,
        displayName :: Text
      }
  deriving (FromJSON) via (Fido2.EncodingRules RegisterBeginReq)
  deriving stock (Generic)

app :: Database.Connection -> TVar Sessions -> ScottyM ()
app db sessions = do
  Scotty.middleware (staticPolicy (addBase "dist"))
  Scotty.post "/register/begin" $ beginRegistration db sessions
  Scotty.post "/register/complete" $ completeRegistration db sessions
  Scotty.post "/login/begin" $ beginLogin db sessions
  Scotty.post "/login/complete" $ completeLogin db sessions
  Scotty.get "/requires-auth" $ do
    (_sessionId, session) <- getSessionScotty sessions
    when (not . isAuthenticated $ session) (Scotty.raiseStatus HTTP.status401 "Please authenticate first")
    Scotty.json @Text $ "This should only be visible when authenticated"

mkCredentialDescriptor :: Fido2.CredentialId -> Fido2.PublicKeyCredentialDescriptor
mkCredentialDescriptor credentialId =
  Fido2.PublicKeyCredentialDescriptor
    { typ = Fido2.PublicKey,
      id = credentialId,
      transports = Nothing
    }

data RegistrationResult
  = Success
  | AlreadyRegistered
  | AttestationError Error
  deriving (Eq, Show)

handleError :: Show e => Either e a -> Scotty.ActionM a
handleError (Left x) = Scotty.raiseStatus HTTP.status400 . LText.fromStrict . Text.pack . show $ x
handleError (Right x) = pure x

beginLogin :: Database.Connection -> TVar Sessions -> Scotty.ActionM ()
beginLogin db sessions = do
  (sessionId, session) <- getSessionScotty sessions
  userId <- Scotty.jsonData @Fido2.UserId
  credentialIds <- liftIO $ do
    tx <- Database.begin db
    cr <- Database.getCredentialIdsByUserId tx userId
    Database.commit tx
    pure cr
  when (credentialIds == []) $ Scotty.raiseStatus HTTP.status404 "User not found"
  when
    (not . isUnauthenticated $ session)
    (Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin login")
  challenge <- liftIO $ Fido2.newChallenge
  liftIO $ STM.atomically $ casSession sessions sessionId session (Authenticating userId challenge)
  Scotty.json $
    Fido2.PublicKeyCredentialRequestOptions
      { rpId = Nothing,
        timeout = Nothing,
        challenge = challenge,
        allowCredentials = Just (map mkCredentialDescriptor credentialIds),
        userVerification = Nothing
      }

completeLogin :: Database.Connection -> TVar Sessions -> Scotty.ActionM ()
completeLogin db sessions = do
  (sessionId, session) <- getSessionScotty sessions
  case session of
    Authenticating userId challenge -> verifyLogin sessionId session userId challenge
    _ -> Scotty.raiseStatus HTTP.status400 "You need to be authenticating to complete login"
  where
    verifyLogin :: SessionId -> Session -> Fido2.UserId -> Fido2.Challenge -> Scotty.ActionM ()
    verifyLogin sessionId session userId challenge = do
      credential <- Scotty.jsonData @(Fido2.PublicKeyCredential Fido2.AuthenticatorAssertionResponse)
      credentials <- liftIO $ do
        tx <- Database.begin db
        cr <- Database.getCredentialsByUserId tx userId
        Database.commit tx
        pure cr
      handleError $
        Assertion.verifyAssertionResponse
          relyingPartyConfig
          challenge
          credentials
          -- TODO: Read this from a DB or something?
          Fido2.UserVerificationPreferred
          credential
      liftIO
        $ STM.atomically
        $ casSession sessions sessionId session (Authenticated userId)
      Scotty.json @Text "Welcome."

attestedCredentialDataToCredential :: Fido2.AttestedCredentialData -> Assertion.Credential
attestedCredentialDataToCredential Fido2.AttestedCredentialData {credentialId, credentialPublicKey} =
  Assertion.Credential {id = credentialId, publicKey = credentialPublicKey}

beginRegistration :: Database.Connection -> TVar Sessions -> Scotty.ActionM ()
beginRegistration db sessions = do
  (sessionId, session) <- getSessionScotty sessions
  -- NOTE: We currently do not support multiple credentials per user.
  case session of
    Unauthenticated -> generateRegistrationChallenge sessionId session
    _ -> Scotty.raiseStatus HTTP.status400 "You need to be unauthenticated to begin registration"
  where
    generateRegistrationChallenge :: SessionId -> Session -> Scotty.ActionM ()
    generateRegistrationChallenge sessionId session = do
      RegisterBeginReq {userName, displayName} <- Scotty.jsonData @RegisterBeginReq
      challenge <- liftIO $ Fido2.newChallenge
      userId <- liftIO $ Fido2.newUserId
      let user =
            Fido2.PublicKeyCredentialUserEntity
              { id = userId,
                displayName = displayName,
                name = userName
              }
      Scotty.json $ defaultPkcco user challenge
      liftIO $ do
        tx <- Database.begin db
        Database.addUser tx user
        Database.commit tx
        STM.atomically $ casSession sessions sessionId session (Registering userId challenge)

completeRegistration :: Database.Connection -> TVar Sessions -> Scotty.ActionM ()
completeRegistration db sessions = do
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
      attestedCredential@Fido2.AttestedCredentialData
        { credentialId,
          credentialPublicKey
        } <-
        handleError $
          verifyAttestationResponse
            serverOrigin
            (Fido2.RpId domain)
            challenge
            Fido2.UserVerificationPreferred
            response
      -- if the credential was succesfully attested, we will see if the
      -- credential doesn't exist yet, and if it doesn't, insert it.
      tx <- liftIO $ Database.begin db
      -- If a credential with this id existed already, it must belong to the
      -- current user, otherwise it's an error. The spec allows removing the
      -- credential from the old user instead, but we don't do that.
      existingUserId <- liftIO $ Database.getUserByCredentialId tx credentialId
      case existingUserId of
        Nothing -> pure ()
        Just existingUserId | userId == existingUserId -> pure ()
        Just _differentUserId -> handleError $ Left AlreadyRegistered
      liftIO $ do
        Database.addAttestedCredentialData tx userId credentialId credentialPublicKey
        STM.atomically $ STM.modifyTVar sessions $ Map.insert sessionId (Authenticated userId)
        Database.commit tx

defaultPkcco :: Fido2.PublicKeyCredentialUserEntity -> Fido2.Challenge -> Fido2.PublicKeyCredentialCreationOptions
defaultPkcco userEntity challenge =
  Fido2.PublicKeyCredentialCreationOptions
    { rp = rpEntity,
      user = userEntity,
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
serverOrigin = Fido2.Origin $ "http://" <> domain <> ":" <> (Text.pack $ show port)

-- This type is very very close to the PublicKeyCredentialRpEntity. Should those be the
-- same thing? Origin and ID are very similar things.
relyingPartyConfig :: Assertion.RelyingPartyConfig
relyingPartyConfig = Assertion.RelyingPartyConfig {origin = serverOrigin, rpId = Fido2.RpId domain}

rpEntity :: Fido2.PublicKeyCredentialRpEntity
rpEntity = Fido2.PublicKeyCredentialRpEntity {id = Just (Fido2.RpId domain), name = "ACME"}

main :: IO ()
main = do
  db <- Database.connect
  Database.initialize db
  sessions <- STM.newTVarIO Map.empty
  putStrLn "You can view the web-app at: http://localhost:8080/index.html"
  Scotty.scotty port $ app db sessions
