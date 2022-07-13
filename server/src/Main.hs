{-# LANGUAGE DataKinds #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ViewPatterns #-}

module Main
  ( main,
  )
where

import Control.Concurrent.STM (TVar, newTVarIO, readTVarIO)
import Control.Monad (when)
import Control.Monad.Trans (lift)
import Control.Monad.Trans.Maybe (MaybeT (MaybeT, runMaybeT))
import Crypto.Hash (hash)
import qualified Crypto.WebAuthn as WA
import Data.Aeson (FromJSON, ToJSON, Value (String))
import qualified Data.Aeson.Encode.Pretty as AP
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Builder as Builder
import qualified Data.ByteString.Lazy as LBS
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8)
import qualified Data.Text.Encoding as Text
import qualified Data.Text.IO as TIO
import qualified Data.Text.IO as Text
import qualified Data.Text.Lazy as LText
import qualified Data.Text.Lazy.Encoding as LText
import Data.Validation (Validation (Failure, Success))
import qualified Database
import GHC.Generics (Generic)
import MetadataFetch (continuousFetch, registryFromJsonFile)
import qualified Network.HTTP.Types as HTTP
import Network.Wai.Middleware.Static (addBase, staticPolicy)
import PendingCeremonies
  ( PendingCeremonies,
    defaultPendingCeremoniesConfig,
    getPendingAuthentication,
    getPendingRegistration,
    insertPendingAuthentication,
    insertPendingRegistration,
    newPendingCeremonies,
  )
import System.Environment (getArgs)
import System.Hourglass (dateCurrent)
import qualified Web.Cookie as Cookie
import Web.Scotty (ScottyM)
import qualified Web.Scotty as Scotty

data RegisterBeginReq = RegisterBeginReq
  { accountName :: Text,
    accountDisplayName :: Text
  }
  deriving (Show, FromJSON, ToJSON)
  deriving stock (Generic)

-- | Create a fresh authentication token (cookie) for the provided user, and
-- set it on the client to keep them logged in between sessions.
setAuthenticatedAs :: Database.Connection -> WA.UserHandle -> Scotty.ActionM ()
setAuthenticatedAs db userHandle = do
  token <- Scotty.liftAndCatchIO Database.generateAuthToken
  Scotty.liftAndCatchIO $
    Database.withTransaction db $ \tx ->
      Database.insertAuthToken tx token userHandle
  setAuthToken token

-- | Set the AuthToken cookie on the client to keep them logged in between
-- sessions.
setAuthToken :: Database.AuthToken -> Scotty.ActionM ()
setAuthToken token = do
  let setCookie =
        Cookie.defaultSetCookie
          { Cookie.setCookieName = "auth-token",
            Cookie.setCookieValue = Base64.encodeUnpadded (Database.unAuthToken token),
            Cookie.setCookieSameSite = Just Cookie.sameSiteStrict,
            Cookie.setCookieHttpOnly = True,
            Cookie.setCookiePath = Just "/",
            Cookie.setCookieSecure = True,
            -- Keep user logged in for an hour
            Cookie.setCookieMaxAge = Just (60 * 60 * 24)
          }
  Scotty.setHeader
    "Set-Cookie"
    (LText.decodeUtf8 (Builder.toLazyByteString (Cookie.renderSetCookie setCookie)))

-- | Retrieve the AuthToken cookie from the client
getAuthToken :: MaybeT Scotty.ActionM Database.AuthToken
getAuthToken = do
  cookieHeader <- MaybeT $ Scotty.header "cookie"
  let cookies = Cookie.parseCookies $ LBS.toStrict $ LText.encodeUtf8 cookieHeader
  sessionCookie <- MaybeT . pure $ lookup "auth-token" cookies
  MaybeT . pure $ either (const Nothing) (Just . Database.AuthToken) $ Base64.decodeUnpadded sessionCookie

-- | Tries to find the currently connected user in the database and refreshes
-- the timeout on their AuthToken cookie
getAuthenticatedUser :: Database.Connection -> Scotty.ActionM (Maybe WA.UserAccountName)
getAuthenticatedUser db = runMaybeT $ do
  token <- getAuthToken
  user <- MaybeT $
    Scotty.liftAndCatchIO $
      Database.withTransaction db $ \tx ->
        Database.queryUserByAuthToken tx token
  -- Refresh the cookie, resets the 1 hour expiration
  lift $ setAuthToken token
  pure user

-- | Fetch the AuthToken from the client, remove it from the database, and
-- inform the client that it can remove the AuthToken cookie.
logout :: Database.Connection -> Scotty.ActionM ()
logout db = do
  userHandle <-
    runMaybeT getAuthToken >>= \case
      Nothing -> pure Nothing
      Just token -> do
        Scotty.liftAndCatchIO $
          Database.withTransaction db $ \tx -> do
            userHandle <- Database.queryUserByAuthToken tx token
            Database.deleteAuthToken tx token
            return userHandle

  case userHandle of
    Nothing -> pure ()
    Just user -> return ()

  let setCookie =
        Cookie.defaultSetCookie
          { Cookie.setCookieName = "auth-token",
            Cookie.setCookieValue = "",
            Cookie.setCookieSameSite = Just Cookie.sameSiteStrict,
            Cookie.setCookieSecure = True,
            Cookie.setCookieHttpOnly = True,
            Cookie.setCookiePath = Just "/",
            Cookie.setCookieMaxAge = Just 0
          }
  Scotty.setHeader
    "Set-Cookie"
    (LText.decodeUtf8 (Builder.toLazyByteString (Cookie.renderSetCookie setCookie)))

-- | The main app and logic of our example server. The general flow for
-- registration is as follows:
-- 1. The user visits @https://server.net/@
-- 2. The user enters their registration information and clicks on the
-- "Register" button. This sends a message to the "/register/begin" endpoint
-- which begins registration.
-- 3. The RP (server) responds with the credential creation options, which are
-- used by the client to create a credential.
-- 4. The client contacts the "/register/complete" endpoint which verifies the
-- registration, registers the user in the database, and relays the result back
-- to the client.
-- 5. The client is redirected to the `authenticated.html` page.
--
-- For Login the process is nearly the same:
-- 1. The user visits @https://server.net/@
-- 2. The user enters their login information and clicks on the
-- "Login" button. This sends a message to the "/login/begin" endpoint
-- which begins the login procedure.
-- 3. The RP (server) responds with the credential get (authentication)
-- options, which are used by the client to select a credential.
-- 4. The client contacts the "/login/complete" endpoint which verifies the
-- credential and relays the result back to the client.
-- 5. The client is redirected to the `authenticated.html` page.
app ::
  -- | The origin identifies your web application. Most often, this is set to
  -- your URL, e.g. @https://erin.webauthn.dev.tweag.io/@
  WA.Origin ->
  -- | The SHA256 hash of your [RP ID](https://www.w3.org/TR/webauthn-2/#rp-id)
  -- . The RP is used as the scope for the credential. It should be a valid
  -- domain name, for example: @erin.webauthn.dev.tweag.io@. Other options include:
  -- @webauthn.dev.tweag.io@ (for credentials that are also valid for
  -- @infinisil.webauthn.dev.tweag.io@) and @tweag.io@ (for credentials that
  -- are scoped to all Tweag web apps). The safest option is to use the full
  -- domain name of the @Origin@ set above (@erin.webauthn.dev.tweag.io@ in
  -- this case).
  WA.RpIdHash ->
  -- | This example server uses a library that requires the connection to be
  -- passed along to functions that read from/update the library.
  Database.Connection ->
  -- | The PendingCeremonies structure stores the information required for the open
  -- sessions; ceremonies that have not been completed, and are hence pending.
  PendingCeremonies ->
  -- | The example server makes use of threading to update the Metadata, this
  -- TVar argument gives us access to the latest version of the fetched
  -- Metadata.
  TVar WA.MetadataServiceRegistry ->
  ScottyM ()
app origin rpIdHash db pending registryVar = do
  Scotty.middleware (staticPolicy (addBase "dist"))
  Scotty.get "/" $ do
    getAuthenticatedUser db >>= \case
      Nothing -> Scotty.redirect "unauthenticated.html"
      Just _ -> Scotty.redirect "authenticated.html"
  Scotty.post "/register/begin" $ beginRegistration db pending
  Scotty.post "/register/complete" $ completeRegistration origin rpIdHash db pending registryVar
  Scotty.get "/requires-auth" $ do
    getAuthenticatedUser db >>= \case
      Nothing -> Scotty.raiseStatus HTTP.status401 "Please authenticate first"
      Just name -> Scotty.json $ String $ WA.unUserAccountName name
  Scotty.get "/logout" $ logout db

-- | In this function we receive the intent of the client to register and reply
-- with the
-- [creation options](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions)
-- . This function also checks if the specified user hasn't already registered.
-- WebAuthn does allow a single user to register multiple credentials, but this
-- server doesn't implement it.
beginRegistration :: Database.Connection -> PendingCeremonies -> Scotty.ActionM ()
beginRegistration db pending = do
  req@RegisterBeginReq {accountName, accountDisplayName} <- Scotty.jsonData @RegisterBeginReq
  exists <- Scotty.liftAndCatchIO $
    Database.withTransaction db $ \tx -> do
      Database.userExists tx (WA.UserAccountName accountName)
  when exists $ Scotty.raiseStatus HTTP.status409 "Account name already taken"
  userId <- Scotty.liftAndCatchIO WA.generateUserHandle
  let user =
        WA.CredentialUserEntity
          { WA.cueId = userId,
            WA.cueDisplayName = WA.UserAccountDisplayName accountDisplayName,
            WA.cueName = WA.UserAccountName accountName
          }
  options <- Scotty.liftAndCatchIO $ insertPendingRegistration pending $ defaultPkcco user
  Scotty.json $ WA.wjEncodeCredentialOptionsRegistration options

-- | Completes the relying party's responsibilities of the registration
-- ceremony. Receives the credential from the client and performs the
-- [registration operation](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential).
-- If the operation succeeds, the user is added to the database, logged in, and
-- redirected to the @authenticated.html@ page.
completeRegistration ::
  WA.Origin ->
  WA.RpIdHash ->
  Database.Connection ->
  PendingCeremonies ->
  TVar WA.MetadataServiceRegistry ->
  Scotty.ActionM ()
completeRegistration origin rpIdHash db pending registryVar = do
  credential <- Scotty.jsonData
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Raw register complete <= " <> jsonText credential
  cred <- case WA.wjDecodeCredentialRegistration credential of
    Left err -> do
      Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete failed to decode raw request: " <> Text.pack (show err)
      fail $ show err
    Right result -> pure result

  options <-
    Scotty.liftAndCatchIO (getPendingRegistration pending cred) >>= \case
      Left err -> do
        Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete problem with challenge: " <> jsonText (String $ Text.pack err)
        Scotty.raiseStatus HTTP.status401 $ "Challenge error: " <> LText.pack err
      Right result -> pure result

  let userHandle = WA.cueId $ WA.corUser options
  -- step 1 to 17
  -- We abort if we couldn't attest the credential
  -- FIXME
  registry <- Scotty.liftAndCatchIO $ readTVarIO registryVar
  now <- Scotty.liftAndCatchIO dateCurrent
  result <- case WA.verifyRegistrationResponse origin rpIdHash registry now options cred of
    Failure errs@(err :| _) -> do
      Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete had errors: " <> Text.pack (show errs)
      fail $ show err
    Success result -> pure result
  -- if the credential was succesfully attested, we will see if the
  -- credential doesn't exist yet, and if it doesn't, insert it.
  Scotty.liftAndCatchIO $
    Database.withTransaction db $ \tx -> do
      -- If a credential with this id existed already, it must belong to the
      -- current user, otherwise it's an error. The spec allows removing the
      -- credential from the old user instead, but we don't do that.
      mexistingEntry <- Database.queryCredentialEntryByCredential tx (WA.ceCredentialId $ WA.rrEntry result)
      case mexistingEntry of
        Nothing -> do
          Database.insertUser tx $ WA.corUser options
          Database.insertCredentialEntry tx $ WA.rrEntry result
          pure ()
        Just existingEntry | userHandle == WA.ceUserHandle existingEntry -> pure ()
        Just differentEntry -> do
          TIO.putStrLn $ "Register complete credential already belongs to the user credential entry: " <> jsonText differentEntry
          fail "This credential is already registered"
  setAuthenticatedAs db userHandle
  let result = String "success"
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete => " <> jsonText result
  Scotty.json result

-- | Utility function for debugging. Creates a human-readable bytestring from
-- any value that can be encoded to JSON. We use this function to provide a log
-- of all messages received and sent.
jsonText :: ToJSON a => a -> Text
jsonText = decodeUtf8 . LBS.toStrict . AP.encodePretty' config
  where
    config :: AP.Config
    config =
      AP.defConfig
        { AP.confIndent = AP.Spaces 2,
          AP.confCompare = AP.compare,
          AP.confNumFormat = AP.Decimal
        }

-- | The default
-- [creation options](https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions).
-- For simplicity's sake this server stores the entirety of the options in the
-- `PendingCeremonies`. However, only a subset of these options are used by the
-- `verify` functions. See the `WA.CredentialOptions` documentation for more
-- information.
defaultPkcco :: WA.CredentialUserEntity -> WA.Challenge -> WA.CredentialOptions 'WA.Registration
defaultPkcco userEntity challenge =
  WA.CredentialOptionsRegistration
    { WA.corRp = WA.CredentialRpEntity {WA.creId = Nothing, WA.creName = "ACME"},
      WA.corUser = userEntity,
      WA.corChallenge = challenge,
      WA.corPubKeyCredParams =
        [ WA.CredentialParameters
            { WA.cpTyp = WA.CredentialTypePublicKey,
              WA.cpAlg = WA.CoseAlgorithmES256
            },
          WA.CredentialParameters
            { WA.cpTyp = WA.CredentialTypePublicKey,
              WA.cpAlg = WA.CoseAlgorithmRS256
            }
        ],
      WA.corTimeout = Nothing,
      WA.corExcludeCredentials = [],
      WA.corAuthenticatorSelection =
        Just
          WA.AuthenticatorSelectionCriteria
            { WA.ascAuthenticatorAttachment = Nothing,
              WA.ascResidentKey = WA.ResidentKeyRequirementDiscouraged,
              WA.ascUserVerification = WA.UserVerificationRequirementPreferred
            },
      WA.corAttestation = WA.AttestationConveyancePreferenceDirect,
      WA.corExtensions = Nothing
    }

main :: IO ()
main = do
  [Text.pack -> origin, Text.pack -> domain, read -> port] <- getArgs
  db <- Database.connect
  Database.initialize db
  pending <- newPendingCeremonies defaultPendingCeremoniesConfig
  -- These solokey entries come from https://github.com/solokeys/solo/tree/master/metadata
  -- We import these here because we have access to physical solokey tokens and whished to use those during tests.
  -- As of 3-Jan-2022, solokeys has not added the metadata of their keys to fido mds version 3.
  registry <- registryFromJsonFile "solokey-entries.json"
  registryVar <- newTVarIO registry
  _ <- continuousFetch registryVar
  Text.putStrLn $ "You can view the web-app at: " <> origin
  let rpIdHash = WA.RpIdHash $ hash $ Text.encodeUtf8 domain
  Scotty.scotty port $ app (WA.Origin origin) rpIdHash db pending registryVar
