{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Hash
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Implemenetation of SLH_DSA_hash of types, that are defined 
in section 4 and 11 regards Hash functions of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
module  Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Hash where
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics

-- instance SLH_DSA_hash SLH_DSA_SHA2_128s where 
--   _PRFᵐˢᵍ ∷ (KnownNat ℓ) ⇒ Proxy alg → SKPrfType alg → Opt_randType alg → MType ℓ → PRFᵐˢᵍOutType alg
--   _PRFᵐˢᵍ _ skPrfType opt_rand m  = 
--   _Hᵐˢᵍ   ∷ (KnownNat ℓ) ⇒ Proxy alg → RType alg → PKSeedType alg → PKRootType alg → MType ℓ →  HᵐˢᵍOutType alg
--   _Hᵐˢᵍ _ r pkSeed pkRoot m = 
--   _PRF    ∷ Proxy alg → PKSeedType alg → SKSeedType alg → ADRSType alg → PRFOutType alg
--   _PRF   pkSeed skSeed adrs =   
  
--   _Tˡ     ∷ (KnownNat ℓ) ⇒ Proxy alg → PKSeedType alg → ADRSType alg → MˡType ℓ alg → TˡOutType alg
--   _Tˡ  
--    _H      ∷ Proxy alg → PKSeedType alg → ADRSType alg → M²Type alg → HOutType alg
--   _H _ pkSeed adrs m2 = 
--   _F      ∷ Proxy alg → PKSeedType alg → ADRSType alg → M¹Type alg → FOutType alg
--   _F _ pkSeed adrs m1 = 