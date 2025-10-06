{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA'
-}

module Test.Clash.Crypto.PQC.SLH_DSA (tastyTests) where


import Test.Tasty

import qualified Test.Clash.Crypto.PQC.SLH_DSA.Specification as Spec
import qualified Test.Clash.Crypto.PQC.SLH_DSA.Streaming as Stream


tastyTests ∷ TestTree
tastyTests = testGroup "Clash.Crypto.PQC.SLH_DSA"
  [ Spec.tastyTests
  , Stream.tastyTests] 

