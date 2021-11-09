module Database
  ( Connection,
    Transaction (), -- Constructor deliberately not exposed.
    AuthToken (..),
    getAuthTokenUser,
    insertAuthToken,
    addAttestedCredentialData,
    addUser,
    withTransaction,
    connect,
    getUserByCredentialId,
    getCredentialsByUserId,
    initialize,
  )
where

import qualified Crypto.Fido2.Model as M
import Crypto.Fido2.Operations.Common (CredentialEntry (CredentialEntry, ceCredentialId, cePublicKeyBytes, ceSignCounter, ceUserHandle))
import qualified Data.ByteString as BS
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
    \ ( id           blob primary key                                          \
    \ , username     text not null unique                                      \
    \ , display_name text not null                                             \
    \ , created      text not null                                             \
    \                default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))           \
    \ );                                                                       "
    ()
  Sqlite.execute
    conn
    " create table if not exists attested_credential_data                      \
    \ ( id               blob    primary key                                   \
    \ , user_id          blob    not null                                      \
    \ , public_key       blob    not null                                      \
    \ , sign_counter     integer not null                                      \
    \ , created          text    not null                                      \
    \                    default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))       \
    \ , foreign key (user_id) references users (id)                            \
    \ );                                                                       "
    ()
  Sqlite.execute
    conn
    " create index if not exists                                               \
    \ ix_attested_credential_data_user_id                                      \
    \ on attested_credential_data(user_id);                                    "
    ()
  Sqlite.execute
    conn
    " create table if not exists auth_tokens                                   \
    \ ( token            blob    primary key                                   \
    \ , user_id          blob    not null                                      \
    \ , foreign key (user_id) references users (id)                            \
    \ );                                                                       "
    ()
  Sqlite.execute
    conn
    " create index if not exists                                               \
    \ ix_auth_tokens_user_id                                                   \
    \ on auth_tokens(user_id);                                                 "
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

addUser ::
  Transaction ->
  M.PublicKeyCredentialUserEntity ->
  IO ()
addUser (Transaction conn) user =
  let M.PublicKeyCredentialUserEntity
        { M.pkcueId = M.UserHandle userId,
          M.pkcueName = M.UserAccountName username,
          M.pkcueDisplayName = M.UserAccountDisplayName displayName
        } = user
   in Sqlite.execute
        conn
        "insert into users (id, username, display_name) values (?, ?, ?);"
        (userId, username, displayName)

addAttestedCredentialData ::
  Transaction ->
  CredentialEntry ->
  IO ()
addAttestedCredentialData
  (Transaction conn)
  CredentialEntry
    { ceUserHandle = M.UserHandle userId,
      ceCredentialId = M.CredentialId credentialId,
      cePublicKeyBytes = M.PublicKeyBytes pubKeyBytes,
      ceSignCounter = M.SignatureCounter signCounter
    } =
    do
      Sqlite.execute
        conn
        " insert into attested_credential_data                        \
        \ (id, user_id, public_key, sign_counter)                     \
        \ values                                                      \
        \ (?, ?, ?, ?);                                               "
        ( credentialId,
          userId,
          pubKeyBytes,
          signCounter
        )

getUserByCredentialId :: Transaction -> M.CredentialId -> IO (Maybe M.UserHandle)
getUserByCredentialId
  (Transaction conn)
  (M.CredentialId credentialId) = do
    result <-
      Sqlite.query
        conn
        "select user_id from attested_credential_data where id = ?;"
        [credentialId]
    case result of
      [] -> pure Nothing
      [Sqlite.Only userId] -> pure $ Just $ M.UserHandle userId
      _ -> fail "Unreachable: attested_credential_data.id has a unique index."

getCredentialsByUserId :: Transaction -> M.UserHandle -> IO [CredentialEntry]
getCredentialsByUserId (Transaction conn) (M.UserHandle userId) = do
  entries <-
    Sqlite.query
      conn
      "select user_id, id, public_key, sign_counter from attested_credential_data where user_id = ?;"
      [userId]
  pure $ map toCredentialEntry entries
  where
    toCredentialEntry (userHandle, credentialId, publicKey, signCounter) =
      CredentialEntry
        { ceUserHandle = M.UserHandle userHandle,
          ceCredentialId = M.CredentialId credentialId,
          cePublicKeyBytes = M.PublicKeyBytes publicKey,
          ceSignCounter = M.SignatureCounter signCounter
        }

newtype AuthToken = AuthToken {unAuthToken :: BS.ByteString}

instance Uniform AuthToken where
  uniformM g = AuthToken <$> uniformByteStringM 16 g

getAuthTokenUser :: Transaction -> AuthToken -> IO (Maybe M.UserHandle)
getAuthTokenUser (Transaction conn) (AuthToken token) = do
  result <-
    Sqlite.query
      conn
      "select user_id from auth_tokens where token = ?;"
      [token]
  case result of
    [] -> pure Nothing
    [Sqlite.Only userId] -> pure $ Just $ M.UserHandle userId
    _ -> fail "Unreachable: attested_credential_data.id has a unique index."

insertAuthToken :: Transaction -> AuthToken -> M.UserHandle -> IO ()
insertAuthToken (Transaction conn) (AuthToken token) (M.UserHandle user) = do
  Sqlite.execute
    conn
    "insert into auth_tokens (token, user_id) values (?, ?);"
    (token, user)
