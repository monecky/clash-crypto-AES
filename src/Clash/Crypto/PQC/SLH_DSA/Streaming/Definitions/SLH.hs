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
import GHC.TypeNats.Proof (Rewrite(..), using)

import GHC.TypeLits.Extra
import Data.Proxy
import Data.Constraint
import Unsafe.Coerce
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple, DivTimes, ModTimes
  )
import Language.Haskell.Unicode (type (≤))

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
          = xmss_node (liftA3 (\(sks,skp,pks) i s → (sks,pks, adrs, i, s)) input (fmap (\x → 0x0 ∷ IdxType alg) input) (fmap (\x → (natToNum @(H' alg)) ∷ IdxType alg) input))
-- Algorithm 19
slh_sign_internal ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (PrivateKey alg, Opt_randType alg)  
    → DataStream dom () () (ByteType) 
    -- ^ Message of arbritrary length
     → Channel dom (SIGType alg)
slh_sign_internal inputC inputD
   | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
   =  liftA3 (\x y z → SIGType {r = x, sigᶠᵒʳˢ = y, sigʰᵗ = z}) r sigᶠᵒʳˢ sigʰᵗ
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
      digest ∷ Channel dom (MDByteType alg, IdxType alg, IdxType alg)
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


          go⁰ ∷ Vec (M alg * ByteSize) Bit → (MDByteType alg, IdxType alg, IdxType alg)
          go⁰ d 
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = (resize (v2bv (select d0 d1 (SNat @(K alg * A alg)) d)),getIdxTree,  getIdxLeaf)
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
      sigᶠᵒʳˢ ∷ Channel dom (SIGᶠᵒʳˢType alg)
      sigᶠᵒʳˢ 
         | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
         = fors_sign (zip4C (fstOf3C digest{-md-}) skSeed pkSeed adrs²)
      pkᶠᵒʳˢ ∷ Channel dom (NBlockType alg)
      pkᶠᵒʳˢ 
         | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
         = fors_pkFromSig (zip4C sigᶠᵒʳˢ (fstOf3C digest{-md-}) pkSeed adrs²)
      sigʰᵗ ∷ Channel dom (SIGᴴᵀType alg)
      sigʰᵗ 
         | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
         = ht_sign (zip3C pkᶠᵒʳˢ skSeed pkSeed) (sndOf3C digest{-idx tree-}) (thdOf3C digest{-idx leaf-})
-- Algorithm 20
-- The required check |SIG| ≠ (1 + k(1 + a) + h + d ⋅ len) ⋅ n, is always checked for
slh_verify_internal ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (SIGType alg, PublicKey alg)  
    → DataStream dom () () (ByteType) 
    -- ^ Message of arbritrary length
     → Channel dom (Bool)
slh_verify_internal inputC inputD = ht_verify (zip6C pkᶠᵒʳˢ sigʰᵗ pkSeed pkRoot  (sndOf3C digest{-idx tree-}) (thdOf3C digest{-idx leaf-}))
  where
      adrs ∷ Channel dom (ADRSType alg)
      adrs = fmap (const getInitADRS) inputC
      pkSeed = fmap go (sndC inputC)
            where
              go ∷ PublicKey alg → PKSeedType alg
              go PublicKey {pkPublic = PK {pkSeed = x}} = x 
      pkRoot = fmap go (sndC inputC)
            where
              go ∷ PublicKey alg → PKSeedType alg
              go PublicKey {pkPublic = PK {pkRoot = x}} = x
      sig ∷ Channel dom (SIGType alg)
      sig 
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        = fstC inputC
      -- Code line 5
      r ∷ Channel dom (PRFᵐˢᵍOutType alg)
      r = fmap go sig
        where
          go ∷ SIGType alg → RType alg
          go SIGType {r = x} = x 
      -- Code line 6
      sigᶠᵒʳˢ ∷ Channel dom (SIGᶠᵒʳˢType alg)
      sigᶠᵒʳˢ = fmap go sig
        where
          go ∷ SIGType alg → SIGᶠᵒʳˢType alg
          go SIGType {sigᶠᵒʳˢ = x} = x 
      -- Code line 7
      sigʰᵗ ∷ Channel dom (SIGᴴᵀType alg)
      sigʰᵗ = fmap go sig
        where
          go ∷ SIGType alg → SIGᴴᵀType alg
          go SIGType {sigʰᵗ = x} = x
       -- Code line 8 - 13
      digest ∷ Channel dom (MDByteType alg, IdxType alg, IdxType alg)
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


          go⁰ ∷ Vec (M alg * ByteSize) Bit → (MDByteType alg, IdxType alg, IdxType alg)
          go⁰ d 
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = (resize $ v2bv (select d0 d1 (SNat @(K alg * A alg)) d),getIdxTree,  getIdxLeaf)
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
      pkᶠᵒʳˢ ∷ Channel dom (NBlockType alg)
      pkᶠᵒʳˢ 
         | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
         = fors_pkFromSig (zip4C sigᶠᵒʳˢ (fstOf3C digest{-md-}) pkSeed adrs²)
      
-- slh_verify_internal
-- Algorithm 21
slh_keygen ∷  Channel dom ((SKSeedType alg, SKPrfType alg, PKSeedType alg, PKRootType alg), (PKSeedType alg, PKRootType alg))
slh_keygen = errorX "TODO: Implement when random number generator is in place.\n This function should generate SK.seed, SK.prf, PK.seed and if succesful then call slh_keygen_internal."
-- -- Algorithm 22
-- slh_sign ∷ DataStream dom  (Index 255) () (ByteType) → Channel dom (SIGType alg)
-- A purposed DataStream interface
-- Index 255 represent the size of ctx send with the start frame
-- The first group(of multiple frames) represent the SIG
-- The second group(of multiple frames) represent PK
-- The thrid group is ctx with a maximum size of 255, 
-- that size is send over with the first frame with the first group
-- The last group is M of arbritrary size.
slh_sign ∷ ∀ (alg ∷ SLH_DSA)  dom . 
  (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
  ⇒  DataStream dom () () (ByteType) 
  → Channel dom (SIGType alg)
slh_sign = error "TODO: Implement \n Alternative format the input the string yourself and use verify.\n"

-- -- Algorithm 23
hash_slh_sign ∷ ∀ (alg ∷ SLH_DSA)  dom . 
  (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
  ⇒  DataStream dom () () (ByteType) 
  → Channel dom (SIGType alg)
hash_slh_sign = error "TODO: Implement \n Alternative format the input the string yourself and use verify.\n"
-- -- Algorithm 24
-- slh_verify ∷ DataStream dom  (Index 255) () (ByteType) → Channel dom (Bool)
-- A purposed DataStream interface:
-- Index 255 represent the size of ctx send with the start frame
-- The first group(of multiple frames) represent the SIG
-- The second group(of multiple frames) represent PK
-- The thrid group is ctx with a maximum size of 255, 
-- that size is send over with the first frame with the first group
-- The last group is M of arbritrary size.
slh_verify ∷  ∀ (alg ∷ SLH_DSA)  dom . 
  (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
  ⇒  DataStream dom () () (ByteType) 
  → Channel dom Bool
slh_verify = error "TODO: Implement \n Alternative format the input the string yourself and use verify.\n"
-- -- Algorithm 25
hash_slh_verify ∷  ∀ (alg ∷ SLH_DSA)  dom . 
  (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
  ⇒  DataStream dom () () (ByteType) 
  → Channel dom Bool
hash_slh_verify = error "TODO: Implement \n Alternative format the input the string yourself and use verify.\n"
--------------------------------------
-- Interfaces
-- sign for algorithm 22 and 23
-- verify for algorithm 24 and 24
--------------------------------------
-- Interface where the user needs to do formating for algorithm 22 and 23
sign ∷  ∀ (alg ∷ SLH_DSA)  dom . 
  (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
  ⇒  DataStream dom () () (ByteType) 
  → Channel dom (SIGType alg)
sign inputD
         | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
         = slh_sign_internal (transferToC @(PrivateKey alg, Opt_randType alg) @ByteSize inputD) (transferToD @(PrivateKey alg, Opt_randType alg) @ByteSize inputD)

          
-- Interface where the user needs to do formatting for algorithm 24 and 25
verify ∷  ∀ (alg ∷ SLH_DSA)  dom . 
  (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
  ⇒  DataStream dom () () (ByteType) 
  → Channel dom Bool
verify inputD
         | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
         = slh_verify_internal (transferToC @(SIGType alg, PublicKey alg) @ByteSize inputD) (transferToD @(SIGType alg, PublicKey alg) @ByteSize inputD)

----------------------------------------
-- The following might be too specific.
-- Maybe moved to somewhere else
----------------------------------------
concatMapC ∷ ∀ ℓ a dom . (KnownNat ℓ) ⇒  Vec ℓ (Channel dom a) -> Channel dom (Vec ℓ a)
concatMapC Nil = errorX "Invalid vector"
concatMapC ( x `Cons` Nil) = fmap singleton  x 
concatMapC (x `Cons` xs) = liftA2 (++) (fmap singleton x) (concatMapC xs)

