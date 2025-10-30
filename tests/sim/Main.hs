import Prelude
import Test.Tasty

import qualified Test.Clash.Crypto.Cipher.AES as AES
import qualified Test.Clash.Crypto.Hash.SHA as SHA
import qualified Test.Clash.Crypto.Hash.MGF1 as MGF1
import qualified Test.Clash.Crypto.MAC.HMAC as HMAC
import qualified Test.Clash.Crypto.ECDSA.Karatsuba as Karatsuba
import qualified Test.Clash.Crypto.ECDSA.Modulo as Modulo
import qualified Test.Clash.Crypto.ECDSA.InverseModulo as InverseModulo
import qualified Test.Clash.Crypto.PQC.SLH_DSA as SLH_DSA

main ∷ IO ()
main = defaultMain $ testGroup "clash-crypto simulation tests"
  [
     AES.tastyTests
  , MGF1.tastyTests
  , SHA.tastyTests
  , HMAC.tastyTests
  , InverseModulo.tastyTests
  , Karatsuba.tastyTests
  , Modulo.tastyTests
  , SLH_DSA.tastyTests
  ]
