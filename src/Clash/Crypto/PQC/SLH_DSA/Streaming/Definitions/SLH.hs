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
      skSeed = fmap go (fstC inputC)
            where
              go ∷ PrivateKey alg → PKSeedType alg
              go PrivateKey {skPrivate = SK {skSeed = x}} = x 
      pkSeed = fmap go (fstC inputC)
            where
              go ∷ PrivateKey alg → PKSeedType alg
              go PrivateKey {skPublic = PK {pkSeed = x}} = x 
      pkRoot = fmap go (fstC inputC)
            where
              go ∷ PrivateKey alg → PKSeedType alg
              go PrivateKey {skPublic = PK {pkRoot = x}} = x 
      -- Code line 1
      adrs ∷ Channel dom (ADRSType alg)
      adrs = fmap (const getInitADRS) inputC
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
      digest ∷ Channel dom (MDType alg, IdxType alg, IdxType alg)
      digest = fmap go⁰ digv
        where
          digv ∷ Channel dom (Vec (M alg * ByteSize) Bit)
          digv 
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = fmap (bv2v . concatBitVector#) dig
          dig ∷ Channel dom (MBlockType alg)
          dig 
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = (_HᵐˢᵍStream @alg (zip3C r pkSeed pkRoot) inputD)


          go⁰ ∷ Vec (M alg * ByteSize) Bit → (MDType alg, IdxType alg, IdxType alg)
          go⁰ d 
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = (v2bv (select d0 d1 (SNat @(K alg * A alg)) d),getIdxTree,  getIdxLeaf)
              where
                afterMD ∷ (KnownNat n, (CeilXDivY (K alg * A alg) ByteSize) + n ~ (M alg  * ByteSize)) ⇒ Vec (M alg * ByteSize) Bit
                afterMD 
                   | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                   = fst (shiftOutFrom0 (SNat @(CeilXDivY (K alg * A alg) ByteSize)) d)
                afterIdxTree ∷ (KnownNat n, (CeilXDivY (H alg - Div (H alg) (D alg)) ByteSize) + n ~ (M alg  * ByteSize)) ⇒ Vec (M alg * ByteSize) Bit
                afterIdxTree 
                   | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                   = fst (shiftOutFrom0 (SNat @(CeilXDivY (H alg - Div (H alg) (D alg)) ByteSize)) (afterMD @((M alg  * ByteSize) - (CeilXDivY (K alg * A alg) ByteSize))))
                getIdxTree ∷ IdxType alg
                getIdxTree                    
                    | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                   = resize  ( v2bv (select d0 d1  (SNat @(CeilXDivY (H alg - Div (H alg) (D alg)) ByteSize)) (afterMD @((M alg  * ByteSize) - (CeilXDivY (K alg * A alg) ByteSize)))))
                getIdxLeaf ∷  IdxType alg
                getIdxLeaf                    
                    | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                   = resize  ( v2bv (select d0 d1 (SNat @(CeilXDivY (H alg - Div (H alg) ((D alg) * ByteSize)) ByteSize)) (afterIdxTree @(M alg * ByteSize - CeilXDivY (H alg - Div (H alg) (D alg)) ByteSize))))
      -- Code line 11
      adrs⁰ ∷ Channel dom (ADRSType alg)
      adrs⁰ = setTreeAddressC adrs (sndOf3C digest{-idx tree-})
      -- Code line 12
      adrs¹ ∷ Channel dom (ADRSType alg)
      adrs¹ = setTypeAndClearC adrs⁰ FORS_TREE 
      -- Code line 13
      adrs² ∷ Channel dom (ADRSType alg)
      adrs² = setKeyPairAddressC adrs¹ (thdOf3C digest{-idx leaf-})
      sigᶠᵒʳˢ = fors_sign (zip4C (fstOf3C digest{-md-}) skSeed pkSeed adrs²)
      pkᶠᵒʳˢ = fors_pkFromSig (zip4C sigᶠᵒʳˢ (fstOf3C digest{-md-}) skSeed adrs²)
      sigʰᵗ = ht_sign (zip3C pkᶠᵒʳˢ skSeed pkSeed) (sndOf3C digest{-idx tree-}) (thdOf3C digest{-idx leaf-})
-- -- slh_sign_internalRandom ∷ 
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