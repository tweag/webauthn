module Database
  ( addAttestedCredentialData
  , addUser
  , connect
  , initialize
  )
where

import Data.Text (Text)
import Crypto.Fido2.Protocol
  ( URLEncodedBase64 (URLEncodedBase64)
  , UserId (UserId)
  , CredentialId (CredentialId)
  , PublicKey
  )

import qualified Crypto.Fido2.Protocol as Fido2
import qualified Database.SQLite.Simple as Sqlite

connect :: IO Sqlite.Connection
connect = do
  conn <- Sqlite.open "users.sqlite3"
  Sqlite.execute conn "pragma foreign_keys = on;" ()
  pure conn

initialize :: Sqlite.Connection -> IO ()
initialize conn = do
  Sqlite.execute conn
    " create table if not exists users                                         \
    \ ( id           blob primary key                                          \
    \ , username     text not null unique                                      \
    \ , display_name text not null                                             \
    \ , created      text not null                                             \
    \                default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))           \
    \ );                                                                       "
    ()

  Sqlite.execute conn
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

addUser
  :: Sqlite.Connection
  -> Fido2.UserId
  -> Text
  -> Text
  -> IO ()
addUser
  conn (UserId (URLEncodedBase64 userId)) username displayName = do
    Sqlite.execute conn
      "insert into users (id, username, display_name) values (?, ?, ?);"
      (userId, username, displayName)

addAttestedCredentialData
  :: Sqlite.Connection
  -> Fido2.UserId
  -> Fido2.CredentialId
  -> Fido2.PublicKey
  -> IO ()
addAttestedCredentialData
  conn
  (UserId (URLEncodedBase64 userId))
  (CredentialId (URLEncodedBase64 credentialId))
  publicKey = do
    Sqlite.execute conn
      " insert into attested_credential_data                        \
      \ (id, user_id, public_key_x, public_key_y)                   \
      \ values                                                      \
      \ (?, ?, ?, ?);                                               "
      ( credentialId
      , userId
      , Fido2.publicKeyX publicKey
      , Fido2.publicKeyY publicKey
      )
