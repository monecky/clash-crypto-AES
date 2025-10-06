{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Streaming
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Streaming'
-}


module Test.Clash.Crypto.PQC.SLH_DSA.Streaming (tastyTests) where


import Test.Tasty

import qualified Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Algorithm as Alg


tastyTests ∷ TestTree
tastyTests = testGroup "Clash.Crypto.PQC.SLH_DSA.Streaming"
  [Alg.tastyTests] 

