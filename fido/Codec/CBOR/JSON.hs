-- TODO use upstream cborg-json
{-# LANGUAGE BangPatterns #-}

module Codec.CBOR.JSON where

import           Data.Monoid
import           Control.Applicative
import           Prelude hiding (decodeFloat)

import           Codec.CBOR.Encoding
import           Codec.CBOR.Decoding
import           Data.Aeson                          ( Value(..), Object )
import qualified Data.Aeson                          as Aeson
import qualified Data.HashMap.Lazy                   as HM
import           Data.Scientific                     as Scientific
import qualified Data.Text                           as T
import qualified Data.Vector                         as V

-- | Decode an arbitrary CBOR value into JSON.
decodeValue :: Bool -> Decoder s Value
decodeValue lenient = do
    tkty <- peekTokenType
    case tkty of
      TypeUInt    -> decodeNumberIntegral
      TypeUInt64  -> decodeNumberIntegral
      TypeNInt    -> decodeNumberIntegral
      TypeNInt64  -> decodeNumberIntegral
      TypeInteger -> decodeNumberIntegral
      TypeFloat16 -> decodeNumberFloat16
      TypeFloat32 -> decodeNumberFloating
      TypeFloat64 -> decodeNumberFloating
      TypeBool    -> Bool   <$> decodeBool
      TypeNull    -> Null   <$  decodeNull
      TypeString  -> String <$> decodeString

      TypeListLen      -> decodeListLen >>= decodeListN lenient
      TypeListLenIndef -> decodeListLenIndef >> decodeListIndef lenient []
      TypeMapLen       -> Object <$> (decodeMapLen >>= flip (decodeMapN lenient) HM.empty)

      _           -> fail $ "unexpected CBOR token type for a JSON value: "
                         ++ show tkty

decodeObject :: Bool -> Decoder s Object
decodeObject lenient = do
  tkty <- peekTokenType
  case tkty of
    TypeMapLen -> decodeMapLen >>= flip (decodeMapN lenient) HM.empty
    _           -> fail $ "unexpected CBOR token type for a JSON value: "
                       ++ show tkty

decodeNumberIntegral :: Decoder s Value
decodeNumberIntegral = Number . fromInteger <$> decodeInteger

decodeNumberFloating :: Decoder s Value
decodeNumberFloating = Number . Scientific.fromFloatDigits <$> decodeDouble

decodeNumberFloat16 :: Decoder s Value
decodeNumberFloat16 = do
    f <- decodeFloat
    if isNaN f || isInfinite f
        then return Null
        else return $ Number (Scientific.fromFloatDigits f)

decodeListN :: Bool -> Int -> Decoder s Value
decodeListN !lenient !n = do
  vec <- V.replicateM n (decodeValue lenient) 
  return $! Array vec

decodeListIndef :: Bool -> [Value] -> Decoder s Value
decodeListIndef !lenient acc = do
    stop <- decodeBreakOr
    if stop then return $! Array (V.fromList (reverse acc))
            else do !tm <- decodeValue lenient
                    decodeListIndef lenient (tm : acc)

decodeMapN :: Bool -> Int -> Aeson.Object -> Decoder s Aeson.Object
decodeMapN !lenient !n acc =
    case n of
      0 -> return $! acc
      _ -> do
        !tk <- decodeValue lenient >>= \v -> case v of
                 String s           -> return s
                 -- These cases are only allowed when --lenient is passed,
                 -- as printing them as strings may result in key collisions.
                 Number d | lenient -> return $ T.pack (show d)
                 Bool   b | lenient -> return $ T.pack (show b)
                 _        -> fail "Could not decode map key type"
        !tv  <- decodeValue lenient
        decodeMapN lenient (n-1) (HM.insert tk tv acc)
