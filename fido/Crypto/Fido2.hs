-- | This module providers an ergonomic wrapper around the low-level
-- | 'Crypto.Fido2.Protocol' module. It makes some opinionated choices for you
-- and implements a large part of the state machine that makes up Webauthn. If
-- you want more control, check out 'Crypto.Fido2.Protocol' instead
module Crypto.Fido2
  ( module Crypto.Fido2.Protocol,
    Timeout (Timeout),
    PublicKeyCredentialUserEntity (..),
  )
where

import Crypto.Fido2.Protocol
import Crypto.Random (MonadRandom)
import Data.Semigroup (Endo)
import Data.Text (Text)
{-
data RegistrationMode
  = NewUser NewUser

-- | Simplified config for Webauthn
data Config
  = Config
      { -- | The display name of the relying party
        name :: Text,
        -- | e.g. @https://foo.example.com:443@
        origin :: Text,
        -- | e.g. foo.example.com or example.com , if omitted equals the host of the origin
        id :: Maybe Text
      }

newtype ExcludeCredentials = ExcludeCredentials [PublicKeyCredentialDescriptor]


registerNewUser :: man sy
-- | Starts a webauthn registration flow to register a credential to a user
--
-- We have two cases. Either the user was already registered,
beginRegistration ::
  (MonadRandom m) =>
  -- | The config
  Config ->
  -- ExcludeCredentials ->
  m PublicKeyCredentialCreationOptions
beginRegistration Config {relyingPartyName, relyingPartyOrigin, relyingPartyId} = do
  challenge <- newChallenge
  userId <- newUserId
  let rp =
        PublicKeyCredentialRpEntity
          { id = relyingPartyId,
            name = relyingPartName
          }
  let user =
        PublicKeyCredentialUserEntity
          { id = userId,
            displayName = undefined,
            name = undefined
          }
  pure $ PublicKeyCredentialCreationOptions {..}
-}
