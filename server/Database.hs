{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Database
  ( Connection,
    Transaction (), -- Constructor deliberately not exposed.
    addAttestedCredentialData,
    addUser,
    begin,
    commit,
    connect,
    getUserByCredentialId,
    getCredentialIdsByUserId,
    getCredentialsByUserId,
    getPublicKeyByCredentialId,
    initialize,
    rollback,
  )
where

import qualified Crypto.Fido2.Assertion as Assertion
import Crypto.Fido2.Protocol
  ( CredentialId (CredentialId),
    PublicKey,
    URLEncodedBase64 (URLEncodedBase64),
    UserId (UserId),
  )
import qualified Crypto.Fido2.Protocol as Fido2
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Database.SQLite.Simple as Sqlite

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
    \ , public_key_x     blob    not null                                      \
    \ , public_key_y     blob    not null                                      \
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

begin :: Sqlite.Connection -> IO Transaction
begin conn = do
  Sqlite.execute conn "begin;" ()
  pure $ Transaction conn

commit :: Transaction -> IO ()
commit (Transaction conn) = Sqlite.execute conn "commit;" ()

rollback :: Transaction -> IO ()
rollback (Transaction conn) = Sqlite.execute conn "rollback;" ()

addUser ::
  Transaction ->
  Fido2.PublicKeyCredentialUserEntity ->
  IO ()
addUser (Transaction conn) user =
  let Fido2.PublicKeyCredentialUserEntity
        { id = (UserId (URLEncodedBase64 userId)),
          name = username,
          displayName = displayName
        } = user
   in Sqlite.execute
        conn
        "insert into users (id, username, display_name) values (?, ?, ?);"
        (userId, username, displayName)

addAttestedCredentialData ::
  Transaction ->
  Fido2.UserId ->
  Fido2.CredentialId ->
  Fido2.PublicKey ->
  IO ()
addAttestedCredentialData
  (Transaction conn)
  (UserId (URLEncodedBase64 userId))
  (CredentialId (URLEncodedBase64 credentialId))
  publicKey =
    Sqlite.execute
      conn
      " insert into attested_credential_data                        \
      \ (id, user_id, public_key_x, public_key_y)                   \
      \ values                                                      \
      \ (?, ?, ?, ?);                                               "
      ( credentialId,
        userId,
        Fido2.publicKeyX publicKey,
        Fido2.publicKeyY publicKey
      )

getUserByCredentialId :: Transaction -> Fido2.CredentialId -> IO (Maybe Fido2.UserId)
getUserByCredentialId
  (Transaction conn)
  (CredentialId (URLEncodedBase64 credentialId)) = do
    result <-
      Sqlite.query
        conn
        "select user_id from attested_credential_data where id = ?;"
        [credentialId]
    case result of
      [] -> pure Nothing
      [Sqlite.Only userId] -> pure $ Just $ UserId $ URLEncodedBase64 $ userId
      _ -> fail "Unreachable: attested_credential_data.id has a unique index."

getCredentialsByUserId :: Transaction -> Fido2.UserId -> IO [Assertion.Credential]
getCredentialsByUserId (Transaction conn) (UserId (URLEncodedBase64 userId)) = do
  credentialRows <-
    Sqlite.query
      conn
      "select id, public_key_x, public_key_y from attested_credential_data where user_id = ?;"
      [userId]
  pure $ fmap (mkCredential) $ credentialRows
  where
    mkCredential (id, x, y) =
      Assertion.Credential
        { id = CredentialId $ URLEncodedBase64 id,
          publicKey = Fido2.mkPublicKey x y
        }

getCredentialIdsByUserId :: Transaction -> Fido2.UserId -> IO [Fido2.CredentialId]
getCredentialIdsByUserId (Transaction conn) (UserId (URLEncodedBase64 userId)) = do
  credentialIds :: [[ByteString]] <-
    Sqlite.query
      conn
      "select id from attested_credential_data where user_id = ?;"
      [userId]
  pure $ fmap (CredentialId . URLEncodedBase64) $ concat credentialIds

getPublicKeyByCredentialId ::
  Transaction ->
  Fido2.CredentialId ->
  IO (Maybe Fido2.PublicKey)
getPublicKeyByCredentialId
  (Transaction conn)
  (CredentialId (URLEncodedBase64 credentialId)) = do
    result <-
      Sqlite.query
        conn
        " select (public_key_x, public_key_y) \
        \ from attested_credential_data                         \
        \ where id = ?;                                         "
        [credentialId]
    case result of
      [] -> pure Nothing
      [(x, y)] -> pure $ Just $ Fido2.mkPublicKey x y
