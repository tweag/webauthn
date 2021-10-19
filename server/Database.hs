{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}

module Database
  ( Connection,
    Transaction (), -- Constructor deliberately not exposed.
    addAttestedCredentialData,
    addUser,
    withTransaction,
    connect,
    getUserByCredentialId,
    getCredentialIdsByUserId,
    getCredentialsByUserId,
    initialize,
  )
where

import qualified Codec.CBOR.Read as CBOR
import qualified Codec.CBOR.Write as CBOR
import qualified Codec.Serialise as Serialise
import qualified Crypto.Fido2.Assertion as Assertion
import Crypto.Fido2.Protocol
  ( CredentialId (CredentialId),
    URLEncodedBase64 (URLEncodedBase64),
    UserId (UserId),
  )
import qualified Crypto.Fido2.Protocol as Fido2
import qualified Crypto.Fido2.PublicKey as Fido2
import qualified Data.Maybe as Maybe
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
    \ , public_key       blob    not null                                      \
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
  publicKey = do
    Sqlite.execute
      conn
      " insert into attested_credential_data                        \
      \ (id, user_id, public_key)                                   \
      \ values                                                      \
      \ (?, ?, ?);                                                  "
      ( credentialId,
        userId,
        CBOR.toStrictByteString (Serialise.encode publicKey)
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
      "select id, public_key from attested_credential_data where user_id = ?;"
      [userId]
  pure $ Maybe.catMaybes $ fmap (mkCredential) $ credentialRows
  where
    mkCredential (id, publicKey) = do
      -- TODO(#22): Convert to the compressed representation so we don't need
      --  the Maybe.
      case snd <$> CBOR.deserialiseFromBytes Serialise.decode publicKey of
        Left _ -> Nothing
        Right publicKey ->
          pure $
            Assertion.Credential
              { id = CredentialId $ URLEncodedBase64 id,
                publicKey = publicKey
              }

getCredentialIdsByUserId :: Transaction -> Fido2.UserId -> IO [Fido2.CredentialId]
getCredentialIdsByUserId (Transaction conn) (UserId (URLEncodedBase64 userId)) = do
  credentialIds <-
    Sqlite.query
      conn
      "select id from attested_credential_data where user_id = ?;"
      [userId]
  pure $ fmap (CredentialId . URLEncodedBase64 . Sqlite.fromOnly) $ credentialIds
