{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Specification
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Specification'
-}


module Test.Clash.Crypto.PQC.SLH_DSA.Specification (tastyTests) where


import Test.Tasty

import qualified Test.Clash.Crypto.PQC.SLH_DSA.Specification.Algorithm as Alg
import qualified Test.Clash.Crypto.PQC.SLH_DSA.Specification.Definitions as Def


tastyTests ∷ TestTree
tastyTests = testGroup "Clash.Crypto.PQC.SLH_DSA.Specification"
  [ Alg.tastyTests
  , Def.tastyTests] 

