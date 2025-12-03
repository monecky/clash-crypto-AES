{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic WOTS definitions covering the fundamentals of FIPS 205.
Algorithm 5- 13 are implemented and exposed for testing purposes.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
{-# OPTIONS_GHC -fno-max-relevant-binds #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.XMSS 
    (
        -- ALgorithm 5
        chain
        -- Algorithm 6
        , wots_pkGen
        -- Algorithm 7
        , wots_sign
        -- Algorithm 8
        , wots_pkFromSig
        -- Algorithm 9
        , xmss_node
        -- Algorithm 10
        , xmss_sign
        -- Algorithm 11
        , xmss_pkFromSig
    )where
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
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address 
import Clash.Signal.Extra(apWhen)
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus 
-- Algorithm 9
xmss_node ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg 
     , IdxType alg -- i 
     , IdxType alg -- z
     )
     → Channel dom (NodeType alg)
xmss_node input =  mux  (fmap (== 0x00) z) ifthen ifelse
                                                        -- $ apWhen input.hasUpdates (const (FLTSquare, maxBound))
    where
        i ∷ Channel dom (IdxType alg)
        i = frtOf5C input
        z ∷ Channel dom (IdxType alg)
        z = fthOf5C input
        ifthen ∷ Channel dom (NodeType alg)
        ifthen = wots_pkGen (liftA2 (\(s,t,v,x,y) w → (s,t, setKeyPairAddress (setTypeAndClear v WOTS_HASH) w)) input i)
        ifelse ∷ Channel dom (NodeType alg)
        ifelse 
          | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
          = _HStream @alg (zip3C pkSeed adrs¹ ( (‖) <$> lnode <*> rnode))
            where
                -- line 6
                lnode ∷ Channel dom (NodeType alg)
                lnode =  xmss_node (liftA3 (\(a,b,c,d,e) x y → (a,b,c,x,y)) input ((2*) <$> i) (fmap (\x → x - 1) z))
                -- line 7 
                rnode ∷ Channel dom (NodeType alg)
                rnode = xmss_node (liftA3 (\(a,b,c,d,e) x y → (a,b,c,x,y)) input (fmap (\x → 2 * x + 1) i) (fmap (\x → x - 1) z))
                skSeed ∷ Channel dom (PKSeedType alg)
                skSeed = fstOf5C input
                pkSeed ∷ Channel dom (PKSeedType alg)
                pkSeed = sndOf5C input
                adrs ∷ Channel dom (ADRSType alg)
                adrs = thdOf5C input
                adrs¹ ∷ Channel dom (ADRSType alg)
                adrs¹ = liftA3 (\s t v → setTreeIndex (setTreeHeight s t) v) (setTypeAndClearC adrs TREE) z i
-- Algorithm 10
xmss_sign ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (NBlockType alg, SKSeedType alg, PKSeedType alg, ADRSType alg,
        IdxType alg) -- idx
     → Channel dom (SIGˣᵐˢˢType alg)
xmss_sign input 
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    = liftA2 object sig_ots auth
    where 
        idx ∷ Channel dom (IdxType alg)
        idx = fthOf5C input
        object ∷  ( KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg)
                ⇒ SIGʷᵒᵗˢPlusType alg → AUTHType alg → SIGˣᵐˢˢType alg
        object x y 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = XMSSType {sig_ots = x, auth = y}
        k ∷ Channel dom (IdxType alg) → Channel dom (IdxType alg) -- k
        k x = fmap (\y → xor# (0 +>>. y)  1) x -- k ← ⌊idx/2j⌋ ⊕ 1
        auth ∷ Channel dom (AUTHType alg)
        auth
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = concatMapC (map (\(x,y) → (xmss_node (liftA3 (\(s,p,a) x⁰ y⁰ → (s,p,a,x⁰,y⁰)) input⁰ x y))) (iterateI @(H' alg) (\(x, y) → (k x, fmap (1+) y)) (idx, fmap (\x → 0x0 ∷ IdxType alg) idx)))
            where
                input⁰ = fmap (\(_,s,p,a,_) → (s,p,a)) input
        sig_ots ∷ Channel dom (SIGʷᵒᵗˢPlusType alg)
        sig_ots = wots_sign input⁰
            where
                input⁰ = fmap (\(m,s,p,a,x) → (m,s,p, setKeyPairAddress (setTypeAndClear a WOTS_HASH) x)) input

-- -- Algorithm 11
xmss_pkFromSig ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (SIGˣᵐˢˢType alg, NBlockType alg, PKSeedType alg, ADRSType alg
     , IdxType alg -- idx
     )
     → Channel dom (NodeType alg)
xmss_pkFromSig input 
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    = node¹
    where
        idx ∷ Channel dom (IdxType alg)
        idx = fthOf5C input
        adrs ∷ Channel dom (ADRSType alg)
        adrs = frtOf5C input
        sigˣᵐˢˢ ∷  Channel dom (SIGˣᵐˢˢType alg)
        sigˣᵐˢˢ = fstOf5C input
        m ∷ Channel dom (NBlockType alg)
        m = sndOf5C input
        pkSeed ∷ Channel dom (NBlockType alg)
        pkSeed = thdOf5C input
        -- line 1-2
        adrs¹² ∷ Channel dom (ADRSType alg)
        adrs¹² = setKeyPairAddressC (setTypeAndClearC adrs WOTS_HASH) idx
        -- line 3
        sig ∷ SIGˣᵐˢˢType alg → SIGʷᵒᵗˢPlusType alg
        sig (XMSSType {sig_ots = x}) = x
        -- line 4
        auth ∷ SIGˣᵐˢˢType alg → AUTHType alg
        auth (XMSSType {auth = y}) = y
        -- line 5
        node⁰ ∷ (SLH_DSA_hashStreamFact alg) ⇒ Channel dom (PKˢⁱᵍType alg)
        node⁰  
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = wots_pkFromSig (zip4C (fmap sig sigˣᵐˢˢ) m pkSeed adrs¹²)
        -- line 6 - 7
        adrs⁶⁷ ∷ Channel dom (ADRSType alg)
        adrs⁶⁷ = setTreeIndexC (setTypeAndClearC adrs¹² TREE) idx
        node¹ ∷ Channel dom (NodeType alg)
        node¹ 
         | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
         = foldl function node⁰ (iterateI @(H' alg) (fmap (+1)) (fmap (const 0x0) idx)) 
            where
                function ∷ Channel dom (NBlockType alg) → Channel dom (IdxType alg) → Channel dom (NBlockType alg)
                function node k 
                     | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                     = _HStream @alg (zip3C pkSeed (adrs¹⁰ k) (swap node k))
                     where 
                        -- addOne ∷ IdxType alg  → IdxType alg
                        -- addOne k 
                        --     | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                        --     = if testBit idx (bitCoerce (resize k)) then 0x1 else 0x0
                        addOne ∷ Channel dom (IdxType alg)  → Channel dom (IdxType alg)
                        addOne k 
                            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                            = mux (liftA2 (\x y →  testBit x (bitCoerce (resize y))) idx k) ifthen ifelse
                            where
                                ifthen ∷ Channel dom (IdxType alg)
                                ifthen = (fmap (const 0x1) idx)
                                ifelse ∷ Channel dom (IdxType alg)
                                ifelse = (fmap (const 0x0) idx)
                        swap ∷ Channel dom (NodeType alg) → Channel dom (IdxType alg) → Channel dom (M²Type alg)
                        swap node k 
                            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                            = mux (liftA2 (\x y →  testBit x (bitCoerce (resize y))) idx k) ifthen ifelse
                            where
                                ifthen ∷ Channel dom (M²Type alg)
                                ifthen 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = liftA2 (‖) node (liftA2 (!!) (fmap auth sigˣᵐˢˢ) k) 
                                ifelse ∷ Channel dom (M²Type alg)
                                ifelse 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = liftA2 (‖) (liftA2 (!!) (fmap auth sigˣᵐˢˢ) k) node
                        adrs¹⁰ k = liftA3 (\x y z → setTreeIndex  (setTreeHeight x (y + 1)) ((getTreeIndex (setTreeHeight x (y + 1))) + z `div` 2)) adrs⁶⁷ k (addOne k)
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