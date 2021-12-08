{-# LANGUAGE ScopedTypeVariables #-}

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
    insertAuthToken,
    queryUserByAuthToken,
    deleteAuthToken,
  )
where

import qualified Crypto.WebAuthn.Model as M
import Crypto.WebAuthn.Operations.Common (CredentialEntry (CredentialEntry, ceCredentialId, cePublicKeyBytes, ceSignCounter, ceUserHandle))
import qualified Data.ByteString as BS
import Data.Text (Text)
import Data.Word (Word32)
import qualified Database.SQLite.Simple as Sqlite
import System.Random.Stateful (Uniform, uniformByteStringM, uniformM)

type Connection = Sqlite.Connection

newtype Transaction = Transaction Sqlite.Connection

connect :: IO Sqlite.Connection
connect = do
  conn <- Sqlite.open "users.sqlite3"
  Sqlite.execute conn "pragma foreign_keys = on;" ()
  pure conn

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

insertUser ::
  Transaction ->
  M.PublicKeyCredentialUserEntity ->
  IO ()
insertUser (Transaction conn) user =
  let M.PublicKeyCredentialUserEntity
        { M.pkcueId = M.UserHandle handle,
          M.pkcueName = M.UserAccountName accountName,
          M.pkcueDisplayName = M.UserAccountDisplayName accountDisplayName
        } = user
   in Sqlite.execute
        conn
        "insert into users (handle, account_name, account_display_name) values (?, ?, ?);"
        (handle, accountName, accountDisplayName)

userExists :: Transaction -> M.UserAccountName -> IO Bool
userExists (Transaction conn) (M.UserAccountName accountName) = do
  results :: [Sqlite.Only Text] <- Sqlite.query conn "select account_name from users where account_name = ?;" (Sqlite.Only accountName)
  pure $ not $ null results

insertCredentialEntry ::
  Transaction ->
  CredentialEntry ->
  IO ()
insertCredentialEntry
  (Transaction conn)
  CredentialEntry
    { ceUserHandle = M.UserHandle userHandle,
      ceCredentialId = M.CredentialId credentialId,
      cePublicKeyBytes = M.PublicKeyBytes publicKey,
      ceSignCounter = M.SignatureCounter signCounter
    } =
    do
      Sqlite.execute
        conn
        " insert into credential_entries                          \
        \ (credential_id, user_handle, public_key, sign_counter)  \
        \ values                                                  \
        \ (?, ?, ?, ?);                                           "
        ( credentialId,
          userHandle,
          publicKey,
          signCounter
        )

queryCredentialEntryByCredential :: Transaction -> M.CredentialId -> IO (Maybe CredentialEntry)
queryCredentialEntryByCredential (Transaction conn) (M.CredentialId credentialId) = do
  entries <-
    Sqlite.query
      conn
      " select credential_id, user_handle, public_key, sign_counter \
      \ from credential_entries                                     \
      \ where credential_id = ?;                                    "
      [credentialId]
  case entries of
    [] -> pure Nothing
    [entry] -> pure $ Just $ toCredentialEntry entry
    _ -> fail "Unreachable: credential_entries.credential_id has a unique index."

queryCredentialEntriesByUser :: Transaction -> M.UserAccountName -> IO [CredentialEntry]
queryCredentialEntriesByUser (Transaction conn) (M.UserAccountName accountName) = do
  entries <-
    Sqlite.query
      conn
      " select credential_id, user_handle, public_key, sign_counter \
      \ from credential_entries                                     \
      \ join users on users.handle = credential_entries.user_handle \
      \ where account_name = ?;                                             "
      [accountName]
  pure $ map toCredentialEntry entries

toCredentialEntry :: (BS.ByteString, BS.ByteString, BS.ByteString, Word32) -> CredentialEntry
toCredentialEntry (credentialId, userHandle, publicKey, signCounter) =
  CredentialEntry
    { ceCredentialId = M.CredentialId credentialId,
      ceUserHandle = M.UserHandle userHandle,
      cePublicKeyBytes = M.PublicKeyBytes publicKey,
      ceSignCounter = M.SignatureCounter signCounter
    }

newtype AuthToken = AuthToken {unAuthToken :: BS.ByteString}

instance Uniform AuthToken where
  uniformM g = AuthToken <$> uniformByteStringM 16 g

queryUserByAuthToken :: Transaction -> AuthToken -> IO (Maybe M.UserAccountName)
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
    [Sqlite.Only accountName] -> pure $ Just $ M.UserAccountName accountName
    _ -> fail "Unreachable: credential_entries.credential_id has a unique index."

insertAuthToken :: Transaction -> AuthToken -> M.UserHandle -> IO ()
insertAuthToken (Transaction conn) (AuthToken token) (M.UserHandle userHandle) = do
  Sqlite.execute
    conn
    "insert into auth_tokens (token, user_handle) values (?, ?);"
    (token, userHandle)

deleteAuthToken :: Transaction -> AuthToken -> IO ()
deleteAuthToken (Transaction conn) (AuthToken token) = do
  Sqlite.execute
    conn
    "delete from auth_tokens where token = ?;"
    [token]
