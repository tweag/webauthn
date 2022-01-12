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
import qualified Crypto.WebAuthn.Cose.Registry as Cose
import qualified Crypto.WebAuthn.Metadata.Service.Types as Service
import qualified Crypto.WebAuthn.Model as M
import qualified Crypto.WebAuthn.Model.Binary.Decoding as MD
import qualified Crypto.WebAuthn.Model.JavaScript as JS
import Crypto.WebAuthn.Model.JavaScript.Decoding (decodeCreatedPublicKeyCredential, decodeRequestedPublicKeyCredential)
import Crypto.WebAuthn.Model.JavaScript.Encoding (encodePublicKeyCredentialCreationOptions, encodePublicKeyCredentialRequestOptions)
import Crypto.WebAuthn.Operations.Assertion (verifyAssertionResponse)
import qualified Crypto.WebAuthn.Operations.Assertion as M
import Crypto.WebAuthn.Operations.Attestation (AttestationResult (rEntry), allSupportedFormats, verifyAttestationResponse)
import Crypto.WebAuthn.Operations.Common (CredentialEntry (CredentialEntry, ceCredentialId, ceUserHandle))
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
import PendingOps (PendingOps, defaultPendingOpsConfig, getPendingOptions, insertPendingOptions, newPendingOps)
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

setAuthenticatedAs :: Database.Connection -> M.UserHandle -> Scotty.ActionM ()
setAuthenticatedAs db userHandle = do
  token <- Scotty.liftAndCatchIO Database.generateAuthToken
  Scotty.liftAndCatchIO $
    Database.withTransaction db $ \tx ->
      Database.insertAuthToken tx token userHandle
  setAuthToken token

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

getAuthToken :: MaybeT Scotty.ActionM Database.AuthToken
getAuthToken = do
  cookieHeader <- MaybeT $ Scotty.header "cookie"
  let cookies = Cookie.parseCookies $ LBS.toStrict $ LText.encodeUtf8 cookieHeader
  sessionCookie <- MaybeT . pure $ lookup "auth-token" cookies
  MaybeT . pure $ either (const Nothing) (Just . Database.AuthToken) $ Base64.decodeUnpadded sessionCookie

getAuthenticatedUser :: Database.Connection -> Scotty.ActionM (Maybe M.UserAccountName)
getAuthenticatedUser db = runMaybeT $ do
  token <- getAuthToken
  user <- MaybeT $
    Scotty.liftAndCatchIO $
      Database.withTransaction db $ \tx ->
        Database.queryUserByAuthToken tx token
  lift $ setAuthToken token
  pure user

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
    Just user ->
      Scotty.liftAndCatchIO $ TIO.putStrLn $ "Logging out user: " <> Text.pack (show user)

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

app ::
  M.Origin ->
  M.RpIdHash ->
  Database.Connection ->
  PendingOps ->
  TVar Service.MetadataServiceRegistry ->
  ScottyM ()
app origin rpIdHash db pending registryVar = do
  Scotty.middleware (staticPolicy (addBase "dist"))
  Scotty.get "/" $ do
    getAuthenticatedUser db >>= \case
      Nothing -> Scotty.redirect "unauthenticated.html"
      Just _ -> Scotty.redirect "authenticated.html"
  Scotty.post "/register/begin" $ beginRegistration db pending
  Scotty.post "/register/complete" $ completeRegistration origin rpIdHash db pending registryVar
  Scotty.post "/login/begin" $ beginLogin db pending
  Scotty.post "/login/complete" $ completeLogin origin rpIdHash db pending
  Scotty.get "/requires-auth" $ do
    getAuthenticatedUser db >>= \case
      Nothing -> Scotty.raiseStatus HTTP.status401 "Please authenticate first"
      Just name -> Scotty.json $ String $ M.unUserAccountName name
  Scotty.get "/logout" $ logout db

mkCredentialDescriptor :: CredentialEntry -> M.PublicKeyCredentialDescriptor
mkCredentialDescriptor CredentialEntry {ceCredentialId} =
  M.PublicKeyCredentialDescriptor
    { M.pkcdTyp = M.PublicKeyCredentialTypePublicKey,
      M.pkcdId = ceCredentialId,
      M.pkcdTransports = Nothing
    }

beginLogin :: Database.Connection -> PendingOps -> Scotty.ActionM ()
beginLogin db pending = do
  accountName <- M.UserAccountName <$> Scotty.jsonData @Text
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Login begin <= " <> jsonText accountName

  credentials <- Scotty.liftAndCatchIO $
    Database.withTransaction db $ \tx -> do
      Database.queryCredentialEntriesByUser tx accountName
  when (null credentials) $ do
    Scotty.liftAndCatchIO $ TIO.putStrLn "Login begin error: User not found"
    Scotty.raiseStatus HTTP.status404 "User not found"
  options <- Scotty.liftAndCatchIO $
    insertPendingOptions pending $ \challenge -> do
      M.PublicKeyCredentialRequestOptions
        { M.pkcogRpId = Nothing,
          M.pkcogTimeout = Nothing,
          M.pkcogChallenge = challenge,
          M.pkcogAllowCredentials = map mkCredentialDescriptor credentials,
          M.pkcogUserVerification = M.UserVerificationRequirementPreferred,
          M.pkcogExtensions = Nothing
        }

  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Login begin => " <> jsonText options
  Scotty.json $ encodePublicKeyCredentialRequestOptions options

completeLogin :: M.Origin -> M.RpIdHash -> Database.Connection -> PendingOps -> Scotty.ActionM ()
completeLogin origin rpIdHash db pending = do
  credential <- Scotty.jsonData @JS.RequestedPublicKeyCredential

  cred <- case decodeRequestedPublicKeyCredential credential of
    Left err -> do
      Scotty.liftAndCatchIO $ TIO.putStrLn $ "Login complete failed to decode request: " <> jsonText credential <> ": " <> Text.pack (show err)
      fail $ show err
    Right result -> pure result
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Login complete <= " <> jsonText (MD.stripRawPublicKeyCredential cred)

  options <-
    Scotty.liftAndCatchIO (getPendingOptions pending cred) >>= \case
      Left err -> do
        Scotty.liftAndCatchIO $ TIO.putStrLn $ "Login complete problem with challenge: " <> jsonText (String $ Text.pack err)
        Scotty.raiseStatus HTTP.status401 $ "Challenge error: " <> LText.pack err
      Right result -> pure result

  mentry <- Scotty.liftAndCatchIO $
    Database.withTransaction db $ \tx ->
      Database.queryCredentialEntryByCredential tx (M.pkcIdentifier cred)
  entry <- case mentry of
    Nothing -> do
      Scotty.liftAndCatchIO $ TIO.putStrLn "Login complete credential entry doesn't exist"
      fail "Credential not found"
    Just entry -> pure entry

  newSigCount <- case verifyAssertionResponse origin rpIdHash (Just (ceUserHandle entry)) entry options cred of
    Failure errs@(err :| _) -> do
      Scotty.liftAndCatchIO $ TIO.putStrLn $ "Login complete had errors: " <> Text.pack (show errs)
      fail $ show err
    Success result -> pure result

  case newSigCount of
    M.SignatureCounterZero ->
      Scotty.liftAndCatchIO $
        TIO.putStrLn "SignatureCounter is Zero"
    (M.SignatureCounterUpdated counter) ->
      Scotty.liftAndCatchIO $ do
        TIO.putStrLn $ "Updating SignatureCounter to: " <> Text.pack (show counter)
        Database.withTransaction db $
          \tx -> Database.updateSignatureCounter tx (M.pkcIdentifier cred) counter
    M.SignatureCounterPotentiallyCloned -> Scotty.raiseStatus HTTP.status401 "Signature Counter Cloned"

  setAuthenticatedAs db (ceUserHandle entry)
  let result = String "success"
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Login complete => " <> jsonText result
  Scotty.json result

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

beginRegistration :: Database.Connection -> PendingOps -> Scotty.ActionM ()
beginRegistration db pending = do
  req@RegisterBeginReq {accountName, accountDisplayName} <- Scotty.jsonData @RegisterBeginReq
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register begin <= " <> jsonText req
  exists <- Scotty.liftAndCatchIO $
    Database.withTransaction db $ \tx -> do
      Database.userExists tx (M.UserAccountName accountName)
  when exists $ Scotty.raiseStatus HTTP.status409 "Account name already taken"
  userId <- Scotty.liftAndCatchIO M.generateUserHandle
  let user =
        M.PublicKeyCredentialUserEntity
          { M.pkcueId = userId,
            M.pkcueDisplayName = M.UserAccountDisplayName accountDisplayName,
            M.pkcueName = M.UserAccountName accountName
          }
  options <- Scotty.liftAndCatchIO $ insertPendingOptions pending $ defaultPkcco user
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register begin => " <> jsonText options
  Scotty.json $ encodePublicKeyCredentialCreationOptions options

completeRegistration ::
  M.Origin ->
  M.RpIdHash ->
  Database.Connection ->
  PendingOps ->
  TVar Service.MetadataServiceRegistry ->
  Scotty.ActionM ()
completeRegistration origin rpIdHash db pending registryVar = do
  credential <- Scotty.jsonData @JS.CreatedPublicKeyCredential
  cred <- case decodeCreatedPublicKeyCredential allSupportedFormats credential of
    Left err -> do
      Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete failed to decode request: " <> jsonText credential <> ": " <> Text.pack (show err)
      fail $ show err
    Right result -> pure result
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete <= " <> jsonText (MD.stripRawPublicKeyCredential cred)

  options <-
    Scotty.liftAndCatchIO (getPendingOptions pending cred) >>= \case
      Left err -> do
        Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete problem with challenge: " <> jsonText (String $ Text.pack err)
        Scotty.raiseStatus HTTP.status401 $ "Challenge error: " <> LText.pack err
      Right result -> pure result

  let userHandle = M.pkcueId $ M.pkcocUser options
  -- step 1 to 17
  -- We abort if we couldn't attest the credential
  -- FIXME
  registry <- Scotty.liftAndCatchIO $ readTVarIO registryVar
  now <- Scotty.liftAndCatchIO dateCurrent
  result <- case verifyAttestationResponse origin rpIdHash registry options cred now of
    Failure errs@(err :| _) -> do
      Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete had errors: " <> Text.pack (show errs)
      fail $ show err
    Success result -> pure result
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete result: " <> jsonText result
  -- if the credential was succesfully attested, we will see if the
  -- credential doesn't exist yet, and if it doesn't, insert it.
  Scotty.liftAndCatchIO $
    Database.withTransaction db $ \tx -> do
      -- If a credential with this id existed already, it must belong to the
      -- current user, otherwise it's an error. The spec allows removing the
      -- credential from the old user instead, but we don't do that.
      mexistingEntry <- Database.queryCredentialEntryByCredential tx (ceCredentialId $ rEntry result)
      case mexistingEntry of
        Nothing -> do
          Database.insertUser tx $ M.pkcocUser options
          Database.insertCredentialEntry tx $ rEntry result
          pure ()
        Just existingEntry | userHandle == ceUserHandle existingEntry -> pure ()
        Just differentEntry -> do
          TIO.putStrLn $ "Register complete credential already belongs to the user credential entry: " <> jsonText differentEntry
          fail "This credential is already registered"
  setAuthenticatedAs db userHandle
  let result = String "success"
  Scotty.liftAndCatchIO $ TIO.putStrLn $ "Register complete => " <> jsonText result
  Scotty.json result

defaultPkcco :: M.PublicKeyCredentialUserEntity -> M.Challenge -> M.PublicKeyCredentialOptions 'M.Create
defaultPkcco userEntity challenge =
  M.PublicKeyCredentialCreationOptions
    { M.pkcocRp = M.PublicKeyCredentialRpEntity {M.pkcreId = Nothing, M.pkcreName = "ACME"},
      M.pkcocUser = userEntity,
      M.pkcocChallenge = challenge,
      -- Empty credentialparameters are not supported.
      M.pkcocPubKeyCredParams =
        [ M.PublicKeyCredentialParameters
            { M.pkcpTyp = M.PublicKeyCredentialTypePublicKey,
              M.pkcpAlg = Cose.CoseSignAlgECDSA Cose.CoseHashAlgECDSASHA256
            }
        ],
      M.pkcocTimeout = Nothing,
      M.pkcocExcludeCredentials = [],
      M.pkcocAuthenticatorSelection =
        Just
          M.AuthenticatorSelectionCriteria
            { M.ascAuthenticatorAttachment = Nothing,
              M.ascResidentKey = M.ResidentKeyRequirementDiscouraged,
              M.ascUserVerification = M.UserVerificationRequirementPreferred
            },
      M.pkcocAttestation = M.AttestationConveyancePreferenceDirect,
      M.pkcocExtensions = Nothing
    }

main :: IO ()
main = do
  [Text.pack -> origin, Text.pack -> domain, read -> port] <- getArgs
  db <- Database.connect
  Database.initialize db
  pending <- newPendingOps defaultPendingOpsConfig
  -- These solokey entries come from https://github.com/solokeys/solo/tree/master/metadata
  -- We import these here because we have access to physical solokey tokens and whished to use those during tests.
  -- As of 3-Jan-2022, solokeys has not added the metadata of their keys to fido mds version 3.
  registry <- registryFromJsonFile "solokey-entries.json"
  registryVar <- newTVarIO registry
  _ <- continuousFetch registryVar
  Text.putStrLn $ "You can view the web-app at: " <> origin
  let rpIdHash = M.RpIdHash $ hash $ Text.encodeUtf8 domain
  Scotty.scotty port $ app (M.Origin origin) rpIdHash db pending registryVar
