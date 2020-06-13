module Main (main) where

import qualified Data.ByteString.Lazy.IO as BS
import           Test.Tasty (TestTree)
import qualified Test.Tasty.HUnit as Tasty
import           Test.Tasty.HUnit ()
import qualified Test.Tasty as Tasty


main :: IO ()
main = Tasty.defaultMain tests


tests :: TestTree
tests = Tasty.testGroup "Some tests"
  [ Tasty.testCase "can decode request.json" $ do
      x <- BS.readFile "./fixtures/request.json"
      _
  ]
