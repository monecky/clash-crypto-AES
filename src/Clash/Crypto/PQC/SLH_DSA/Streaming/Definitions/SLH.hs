{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.SLH
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Implemenetation of algorithm in Chapter 19 and 10.
Algorithm 18-23
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}

{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
{-# OPTIONS_GHC -fno-max-relevant-binds #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.SLH where
import Clash.Prelude
import Clash.Sized.Internal.BitVector
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.PQC.SLH_DSA.General.General
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Streaming.Types
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Signal.Channel
import Clash.Signal.Channel.Extra 
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics (base_2ᵇ)
import Data.Proxy (Proxy(..))
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Address 
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus 
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address 
import Clash.Signal.Extra(apWhen)
import Clash.Signal.DataStream

-- Algorithm 18
slh_keygen_internal ∷ ∀ (alg ∷ SLH_DSA)  dom ℓ . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownNat ℓ) 
    ⇒ Channel dom (SKSeedType alg, SKPrfType alg, PKSeedType alg)  
     → Channel dom ((SKSeedType alg, SKPrfType alg, PKSeedType alg, PKRootType alg), (PKSeedType alg, PKRootType alg))
slh_keygen_internal input
     | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
     = (\(sks,skp,pks) pkr → ((sks, skp, pks, pkr),(pks,pkr))) <$> input <*> pkRoot
      where
        -- Code line 1-2
        adrs ∷ ADRSType alg
        adrs 
          | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
          = setLayerAddress getInitADRS (unconcatBitVector# (natToNum @(D alg) - 1))
        -- Code line 3
        pkRoot ∷ Channel dom (PKRootType alg)
        pkRoot 
          | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
          = xmss_node (fmap (\(sks,skp,pks) → (sks,pks, adrs)) input) (fmap (\x → 0x0 ∷ IdxType alg) input) (fmap (\x → (natToNum @(H' alg)) ∷ IdxType alg) input)
-- Algorithm 19
slh_sign_internal ∷ ∀ (alg ∷ SLH_DSA)  dom ℓ . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownNat ℓ) 
    ⇒ Channel dom (PrivateKey alg, Opt_randType alg)  
    → DataStream dom () () (ByteType) 
    -- ^ Message of arbritrary length
     → Channel dom ((SKSeedType alg, SKPrfType alg, PKSeedType alg, PKRootType alg), (PKSeedType alg, PKRootType alg))
slh_sign_internal inputC inputD
   | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
   =  errorX "No random generator implemented"
    where
      -- Code line 1
      adrs ∷ ADRSType alg
      adrs = getInitADRS
      -- Code line 2
      optRand ∷ Channel dom (Opt_randType alg)
      optRand 
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        = if testBit (deterministicSLHDSA alg) 0 then ifthen else elsethen
        where
          elsethen ∷ Channel dom (Opt_randType alg)
          elsethen = errorX "No random generator implemented"
          ifthen ∷ Channel dom (Opt_randType alg)
          ifthen = fmap go (fstC inputC)
            where 
              go ∷ PrivateKey alg → Opt_randType alg
              go PrivateKey {skPublic = PK {pkSeed = seed}} = seed
      r ∷ Channel dom (PRFᵐˢᵍOutType alg)
      r = _PRFᵐˢᵍStream @alg (zipC skprf optRand) inputD
        where
          skprf = fmap go (fstC inputC)
            where
              go ∷ PrivateKey alg → SKPrfType alg
              go PrivateKey {skPrivate = SK {skPrf = x}} = x 
      -- Code line 5 - 10
      digest ∷ (MDType alg, IdxType alg, IdxType alg)
      digest = error "TODO"
        where
          dig ∷ Channel dom (BitVector (M alg * ByteSize))
          dig 
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = fmap (concatBitVector#) (_HᵐˢᵍStream @alg (zip3C r pkSeed pkRoot) inputD)
          pkSeed = fmap go (fstC inputC)
            where
              go ∷ PrivateKey alg → PKSeedType alg
              go PrivateKey {skPublic = PK {pkSeed = x}} = x 
          pkRoot = fmap go (fstC inputC)
            where
              go ∷ PrivateKey alg → PKSeedType alg
              go PrivateKey {skPublic = PK {pkRoot = x}} = x 
-- slh_sign_internalRandom ∷ 
-- Algorithm 20
-- slh_verify_internal
-- Algorithm 21
slh_keygen ∷  Channel dom ((SKSeedType alg, SKPrfType alg, PKSeedType alg, PKRootType alg), (PKSeedType alg, PKRootType alg))
slh_keygen = errorX "This function should generate SK.seed, SK.prf, PK.seed and if succesful then call slh_keygen_internal."
-- Algorithm 22
-- slh_signDeterministic ∷ 
-- slh_signRandom ∷ 
----------------------------------------
-- The following might be too specific.
-- Maybe moved to somewhere else
----------------------------------------
concatMapC ∷ ∀ ℓ a dom . (KnownNat ℓ) ⇒  Vec ℓ (Channel dom a) -> Channel dom (Vec ℓ a)
concatMapC Nil = errorX "Invalid vector"
concatMapC ( x `Cons` Nil) = fmap singleton  x 
concatMapC (x `Cons` xs) = liftA2 (++) (fmap singleton x) (concatMapC xs)



transferAddressC ∷ ∀ alg dom . (KnownSLH_DSAParameters alg) ⇒ Channel dom (ADRSType alg) → ADRSTypeType → Channel dom (ADRSType alg) 
transferAddressC adrs t 
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    = liftA2 (\ad ad¹  → setKeyPairAddress ad¹ (getKeyPairAddress ad)) (setTypeAndClearC adrs t) adrs

record2bv ∷ SIGˣᵐˢˢType alg → Vec ((H' alg + Len alg)* N alg) ByteType
record2bv XMSSType {
  sig_ots,
  auth
  } = concat (sig_ots ‖ auth)