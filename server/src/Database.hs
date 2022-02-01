{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module Database
  ( Connection,
    Transaction (), -- Constructor deliberately not exposed.
    withTransaction,
    connect,
    initialize,

    -- * User
    insertUser,
    userExists,

    -- * Credential Entry
    insertCredentialEntry,
    queryCredentialEntryByCredential,
    queryCredentialEntriesByUser,

    -- * Auth token
    AuthToken (..),
    generateAuthToken,
    insertAuthToken,
    queryUserByAuthToken,
    deleteAuthToken,
    updateSignatureCounter,
  )
where

import Crypto.Random (MonadRandom, getRandomBytes)
import qualified Crypto.WebAuthn as WA
import qualified Data.Bits as Bits
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word32)
import qualified Database.SQLite.Simple as Sqlite

type Connection = Sqlite.Connection

newtype Transaction = Transaction Sqlite.Connection

-- | Opens the @users.sqlite3@ database
connect :: IO Sqlite.Connection
connect = do
  conn <- Sqlite.open "users.sqlite3"
  Sqlite.execute conn "pragma foreign_keys = on;" ()
  pure conn

-- | Creates the tables if they do not exist yet
initialize :: Sqlite.Connection -> IO ()
initialize conn = do
  Sqlite.execute
    conn
    " create table if not exists users                                         \
    \ ( handle               blob primary key                                  \
    \ , account_name         text not null unique                              \
    \ , account_display_name text not null                                     \
    \ , created              text not null                                     \
    \                        default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))   \
    \ );                                                                       "
    ()
  Sqlite.execute
    conn
    " create table if not exists credential_entries                            \
    \ ( credential_id    blob    primary key                                   \
    \ , user_handle      blob    not null                                      \
    \ , public_key       blob    not null                                      \
    \ , sign_counter     integer not null                                      \
    \ , transports       integer not null                                      \
    \ , created          text    not null                                      \
    \                    default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))       \
    \ , foreign key (user_handle) references users (handle)                    \
    \ );                                                                       "
    ()
  Sqlite.execute
    conn
    " create index if not exists                                               \
    \ ix_credential_entries_user_handle                                        \
    \ on credential_entries(user_handle);                                      "
    ()
  Sqlite.execute
    conn
    " create table if not exists auth_tokens                                   \
    \ ( token            blob    primary key                                   \
    \ , user_handle      blob    not null                                      \
    \ , foreign key (user_handle) references users (handle)                    \
    \ );                                                                       "
    ()
  Sqlite.execute
    conn
    " create index if not exists                                               \
    \ ix_auth_tokens_user_handle                                               \
    \ on auth_tokens(user_handle);                                             "
    ()

-- | Run an action using `Sqlite.withTransaction`.
--
-- If exceptions occur within the transaciton, the transaction is aborted
-- with `ROLLBACK TRANSACTION`. Otherwise, the transaction is committed using
-- `COMMIT TRANSACTION`.
--
-- This ensures that we always close our transactions and don't leave them
-- open when exceptions occur.
withTransaction :: Sqlite.Connection -> (Transaction -> IO a) -> IO a
withTransaction conn action = Sqlite.withTransaction conn (action (Transaction conn))

-- | Inserts a new user into the database. Used during registration.
insertUser ::
  Transaction ->
  WA.CredentialUserEntity ->
  IO ()
insertUser (Transaction conn) user =
  let WA.CredentialUserEntity
        { WA.cueId = WA.UserHandle handle,
          WA.cueName = WA.UserAccountName accountName,
          WA.cueDisplayName = WA.UserAccountDisplayName accountDisplayName
        } = user
   in Sqlite.execute
        conn
        "insert into users (handle, account_name, account_display_name) values (?, ?, ?);"
        (handle, accountName, accountDisplayName)

-- | Check if a user exists in the database
userExists :: Transaction -> WA.UserAccountName -> IO Bool
userExists (Transaction conn) (WA.UserAccountName accountName) = do
  results :: [Sqlite.Only Text] <- Sqlite.query conn "select account_name from users where account_name = ?;" (Sqlite.Only accountName)
  pure $ not $ null results

-- | Inserts a new credential entry into the database. The example server's
-- logic doesn't allow multiple credential per user, but a typical RP
-- implementation will likely want to support it.
insertCredentialEntry ::
  Transaction ->
  WA.CredentialEntry ->
  IO ()
insertCredentialEntry
  (Transaction conn)
  WA.CredentialEntry
    { WA.ceUserHandle = WA.UserHandle userHandle,
      WA.ceCredentialId = WA.CredentialId credentialId,
      WA.cePublicKeyBytes = WA.PublicKeyBytes publicKey,
      WA.ceSignCounter = WA.SignatureCounter signCounter,
      WA.ceTransports = transportsToBits -> transportBits
    } =
    do
      Sqlite.execute
        conn
        " insert into credential_entries                                     \
        \ (credential_id, user_handle, public_key, sign_counter, transports) \
        \ values                                                             \
        \ (?, ?, ?, ?, ?);                                                   "
        ( credentialId,
          userHandle,
          publicKey,
          signCounter,
          transportBits
        )

-- | Find a credential entry in the database
queryCredentialEntryByCredential :: Transaction -> WA.CredentialId -> IO (Maybe WA.CredentialEntry)
queryCredentialEntryByCredential (Transaction conn) (WA.CredentialId credentialId) = do
  entries <-
    Sqlite.query
      conn
      " select credential_id, user_handle, public_key, sign_counter, transports \
      \ from credential_entries                                     \
      \ where credential_id = ?;                                    "
      [credentialId]
  case entries of
    [] -> pure Nothing
    [entry] -> pure $ Just $ toCredentialEntry entry
    _ -> fail "Unreachable: credential_entries.credential_id has a unique index."

-- | Retrieve the credential entries belonging to the specified user. In
-- reality, the logic of the server doesn't actually allow a single user to
-- register multiple credentials.
queryCredentialEntriesByUser :: Transaction -> WA.UserAccountName -> IO [WA.CredentialEntry]
queryCredentialEntriesByUser (Transaction conn) (WA.UserAccountName accountName) = do
  entries <-
    Sqlite.query
      conn
      " select credential_id, user_handle, public_key, sign_counter, transports \
      \ from credential_entries                                     \
      \ join users on users.handle = credential_entries.user_handle \
      \ where account_name = ?;                                             "
      [accountName]
  pure $ map toCredentialEntry entries

-- | Set the new signature counter for the specified credential. Used to check
-- if the authenticator wasn't cloned.
updateSignatureCounter :: Transaction -> WA.CredentialId -> WA.SignatureCounter -> IO ()
updateSignatureCounter (Transaction conn) (WA.CredentialId credentialId) (WA.SignatureCounter counter) =
  Sqlite.execute
    conn
    " update credential_entries \
    \ set sign_counter = ?      \
    \ where credential_id = ?;  "
    (counter, credentialId)

transportsToBits :: [WA.AuthenticatorTransport] -> Word32
transportsToBits [] = Bits.zeroBits
transportsToBits (WA.AuthenticatorTransportInternal : xs) = transportsToBits xs `Bits.setBit` 0
transportsToBits (WA.AuthenticatorTransportUSB : xs) = transportsToBits xs `Bits.setBit` 1
transportsToBits (WA.AuthenticatorTransportBLE : xs) = transportsToBits xs `Bits.setBit` 2
transportsToBits (WA.AuthenticatorTransportNFC : xs) = transportsToBits xs `Bits.setBit` 3

transportsFromBits :: Word32 -> [WA.AuthenticatorTransport]
transportsFromBits bits =
  [WA.AuthenticatorTransportInternal | Bits.testBit bits 0]
    ++ [WA.AuthenticatorTransportUSB | Bits.testBit bits 1]
    ++ [WA.AuthenticatorTransportBLE | Bits.testBit bits 2]
    ++ [WA.AuthenticatorTransportNFC | Bits.testBit bits 3]

toCredentialEntry :: (BS.ByteString, BS.ByteString, BS.ByteString, Word32, Word32) -> WA.CredentialEntry
toCredentialEntry (credentialId, userHandle, publicKey, signCounter, transportBits) =
  WA.CredentialEntry
    { WA.ceCredentialId = WA.CredentialId credentialId,
      WA.ceUserHandle = WA.UserHandle userHandle,
      WA.cePublicKeyBytes = WA.PublicKeyBytes publicKey,
      WA.ceSignCounter = WA.SignatureCounter signCounter,
      WA.ceTransports = transportsFromBits transportBits
    }

newtype AuthToken = AuthToken {unAuthToken :: BS.ByteString}

generateAuthToken :: MonadRandom m => m AuthToken
generateAuthToken = AuthToken <$> getRandomBytes 16

-- | Find a user from their `AuthToken` cookie
queryUserByAuthToken :: Transaction -> AuthToken -> IO (Maybe WA.UserAccountName)
queryUserByAuthToken (Transaction conn) (AuthToken token) = do
  result <-
    Sqlite.query
      conn
      " select account_name from auth_tokens                   \
      \ join users on users.handle = auth_tokens.user_handle   \
      \ where token = ?;                                       "
      [token]
  case result of
    [] -> pure Nothing
    [Sqlite.Only accountName] -> pure $ Just $ WA.UserAccountName accountName
    _ -> fail "Unreachable: credential_entries.credential_id has a unique index."

-- | Store `AuthToken` to keep the user logged in
insertAuthToken :: Transaction -> AuthToken -> WA.UserHandle -> IO ()
insertAuthToken (Transaction conn) (AuthToken token) (WA.UserHandle userHandle) = do
  Sqlite.execute
    conn
    "insert into auth_tokens (token, user_handle) values (?, ?);"
    (token, userHandle)

-- | Remove the `AuthToken` from the database, effectively logging out the
-- user
deleteAuthToken :: Transaction -> AuthToken -> IO ()
deleteAuthToken (Transaction conn) (AuthToken token) = do
  Sqlite.execute
    conn
    "delete from auth_tokens where token = ?;"
    [token]
