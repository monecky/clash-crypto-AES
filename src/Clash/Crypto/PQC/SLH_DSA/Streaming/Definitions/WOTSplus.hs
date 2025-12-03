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
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus 
    (
        -- ALgorithm 5
        chain²
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
        -- Algorithm 12
        , ht_sign
        -- Algorithm 13
        , ht_verify
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
-- -- Algorithm 5
chain ∷ ∀ i s (alg ∷ SLH_DSA) dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg,
         KnownNat i, KnownNat s, 0 ≤ i, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg) → Channel dom (NBlockType alg)
chain tmp 
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        = fstOf3C (foldl (function) tmp (iterateI @s (+1) (natToNum @i)))
            where
                function ∷ Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg) 
                    → IdxType alg
                    → Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg)
                function x1 j = zip3C (_FStream @alg (fmap (go j) x1)) pkSeed adrs
                    where 
                        pkSeed ∷ Channel dom (PKSeedType alg)
                        pkSeed = sndOf3C x1
                        adrs ∷ Channel dom (ADRSType alg)
                        adrs = thdOf3C x1
                go ∷  IdxType alg 
                    → (NBlockType alg, PKSeedType alg, ADRSType alg)
                    → (PKSeedType alg, ADRSType alg, NBlockType alg)
                go j (x, pkSeed, adrs) = (pkSeed, setHashAddress adrs j, x)
-- -- -- Version of algorithm 5 that can be used for arbritry number of steps with a max bound, but a bigger piece of hardware. 
chain¹ ∷ ∀ i bound ℓ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg,
         KnownNat i, KnownNat bound, 0 ≤ i, KnownNat ℓ, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg) → BitVector ℓ → Channel dom (NBlockType alg)
chain¹ tmp s
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        = fstOf3C (scanl (function) tmp (iterateI @bound (+1) (natToNum @i)) !! s)
            where
                function ∷ Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg) 
                    → IdxType alg
                    → Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg)
                function x1 j = zip3C (_FStream @alg (fmap (go j) x1)) pkSeed adrs
                    where 
                        pkSeed ∷ Channel dom (PKSeedType alg)
                        pkSeed = sndOf3C x1
                        adrs ∷ Channel dom (ADRSType alg)
                        adrs = thdOf3C x1
                go ∷  IdxType alg 
                    → (NBlockType alg, PKSeedType alg, ADRSType alg)
                    → (PKSeedType alg, ADRSType alg, NBlockType alg)
                go j (x, pkSeed, adrs) = (pkSeed, setHashAddress adrs j, x)
chain² ∷ ∀ bound (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, KnownNat bound, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg)
     → Channel dom (IdxType alg) 
     → Channel dom (IdxType alg) 
     → Channel dom (NBlockType alg)
chain² tmp s i 
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        =  fstOf3C (liftA2 (!!) (concatMapC (scanl (function alg) tmp (iterateI @bound (fmap (+1)) i)))  ((-) <$> s <*> i))
            where
                function ∷ ( SLH_DSA_hashStreamFact alg) ⇒ Proxy alg 
                    → Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg) 
                    → Channel dom (IdxType alg)
                    → Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg)
                function alg x1 j = zip3C (_FStream @alg go) pkSeed adrs
                    where 
                        pkSeed ∷ Channel dom (PKSeedType alg)
                        pkSeed = sndOf3C x1
                        adrs ∷ Channel dom (ADRSType alg)
                        adrs = thdOf3C x1
                        x2 ∷ Channel dom (NBlockType alg)
                        x2 = fstOf3C x1
                        setADRS ∷ Channel dom (ADRSType alg)
                        setADRS = setHashAddressC adrs j
                        go = zip3C pkSeed setADRS x2
                         
-- -- Algorithm 6
-- Another option would to make this methode with the enhance and quit when an result is found, but this will allow for a time analysis attack.
wots_pkGen ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg)
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (NBlockType alg)
wots_pkGen input
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        -- postscanl representing the for loop on line code 4-9 
        = _TˡStream @alg  @(Len alg) @dom (zip3C (pkSeed input) wotspkADRS² (tmp))
            where 
                adrs ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (ADRSType alg)
                adrs input  = thdOf3C input 
                pkSeed ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) →  Channel dom (PKSeedType alg)
                pkSeed input = fstOf3C input 
                skSeed ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (SKSeedType alg)
                skSeed input = sndOf3C input 
                -- Code line 1- 3
                skADRS³ ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (ADRSType alg)
                skADRS³ input = transferAddressC (adrs input) WOTS_PRF  
                    where 
                        adrs¹ = adrs input
                --Code line 5 -8 for in the for loop
                function ∷ (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg)  
                    ⇒ IdxType alg → Channel dom (NBlockType alg)
                function i = chain @0  @(W alg - 1) @alg (zip3C (sk i)  (pkSeed input) (adrs input))
                    where
                        sk i⁰ = _PRFStream @alg (liftA2 (\(sk⁰, pk, _) ad → (pk, sk⁰, ad)) input (fmap (`setChainAddress` i⁰) (adrs input)))
                -- Variable define on line 8
                tmp ∷ (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) ⇒ Channel dom (Vec (Len alg * N alg) (ByteType))
                tmp 
                     | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg    
                     = fmap concat (concatMapC @(Len alg)  tmp⁰)
                tmp⁰ ∷ (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) ⇒ Vec (Len alg) (Channel dom (NBlockType alg))
                tmp⁰ 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg    
                      = map (function) (iterateI @(Len alg) (+1) (0x0 ∷ IdxType alg))
                -- Code line 10 - 12
                wotspkADRS² ∷ Channel dom (ADRSType alg)
                wotspkADRS² = transferAddressC (adrs input) WOTS_PK

-- -- Algorithm 7
wots_sign ∷ ∀ alg dom . (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
            ⇒ Channel dom (NBlockType alg, SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (SIGʷᵒᵗˢPlusType alg)
wots_sign input                               
                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg  
                = sig
                    where
                        m ∷ Channel dom (NBlockType alg)
                        m = fstOf4C input
                        skSeed ∷ Channel dom (SKSeedType alg)
                        skSeed = sndOf4C input
                        pkSeed ∷ Channel dom (PKSeedType alg)
                        pkSeed = thdOf4C input
                        adrs ∷ Channel dom (ADRSType alg)
                        adrs = frtOf4C input
                        msg⁰ ∷ (KnownSLH_DSAParameters alg) ⇒ Channel dom (Vec (Len¹ alg) (BitVector (Lgʷ alg)))
                        msg⁰ 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg  
                            = fmap (base_2ᵇ @(Lgʷ alg) @(Len¹ alg) @(N alg) @(((N alg * ByteSize) `Div` (Lgʷ alg)) - Len¹ alg))  m
                        csum ∷ (KnownSLH_DSAParameters alg) ⇒  Channel dom (BitVector((Len² alg) * (Lgʷ alg) + ByteSize))
                        csum 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                            = fmap (foldl go (0x00 ∷ BitVector((Len² alg) * (Lgʷ alg) + ByteSize))) msg⁰
                            where 
                                go ∷ (KnownSLH_DSAParameters alg) ⇒  BitVector((Len² alg) * (Lgʷ alg) + ByteSize) → BitVector (Lgʷ alg) → BitVector ((Len² alg) * (Lgʷ alg) + ByteSize)
                                go csum¹ msg 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = (natToNum @(W alg)) - 1  + csum¹ - (resize msg)
                        msg¹ ∷ (KnownSLH_DSAParameters alg) ⇒ Channel dom (Vec (Len alg) (BitVector (Lgʷ alg)))
                        msg¹ 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                            = (++) <$> msg⁰ <*> (fmap (unconcatBitVector# . resize) csum)
                        skADRS ∷ Channel dom (ADRSType alg)
                        skADRS = transferAddressC adrs WOTS_PRF
                        -- Line 11 - 16
                        sig ∷ (HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg)
                            ⇒  (Channel dom (SIGʷᵒᵗˢPlusType alg))
                        sig 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                            = concatMapC (map go  (iterateI @(Len alg ) (+1) (natToNum @0)))
                            where
                                go ∷ (HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
                                    ⇒ IdxType alg → Channel dom (NBlockType alg)
                                go i 
                                 | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                 = chain² @(2^Lgʷ alg) (zip3C (sk i) pkSeed adrs) (fmap (\x →  0x0 ∷ IdxType alg) msg¹)  (fmap (\ x → resize (x !! i)) msg¹)
                                    where
                                        sk ∷ (HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) ⇒ IdxType alg → Channel dom (PRFOutType alg)
                                        sk i⁰
                                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                            = _PRFStream @alg (zip3C pkSeed skSeed ( fmap (`setChainAddress` i⁰) skADRS)) 

-- Algorithm 8 
wots_pkFromSig ∷ ∀ alg dom . (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
            ⇒ Channel dom (SIGʷᵒᵗˢPlusType alg, NBlockType alg, PKSeedType alg, ADRSType alg) → Channel dom (PKˢⁱᵍType alg)
wots_pkFromSig input                               
                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg  
                = _TˡStream @alg @(Len alg) (zip3C pkSeed wotspkADRS tmp)
                    where
                        m ∷ Channel dom (NBlockType alg)
                        m = sndOf4C input
                        sig ∷ Channel dom (SIGʷᵒᵗˢPlusType alg)
                        sig = fstOf4C input
                        pkSeed ∷ Channel dom (PKSeedType alg)
                        pkSeed = thdOf4C input
                        adrs ∷ Channel dom (ADRSType alg)
                        adrs = frtOf4C input
                        msg⁰ ∷ (KnownSLH_DSAParameters alg) ⇒ Channel dom (Vec (Len¹ alg) (BitVector (Lgʷ alg)))
                        msg⁰ 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg  
                            = fmap (base_2ᵇ @(Lgʷ alg) @(Len¹ alg) @(N alg) @(((N alg * ByteSize) `Div` (Lgʷ alg)) - Len¹ alg))  m
                        csum ∷ (KnownSLH_DSAParameters alg) ⇒  Channel dom (BitVector((Len² alg) * (Lgʷ alg) + ByteSize))
                        csum 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                            = fmap (foldl go (0x00 ∷ BitVector((Len² alg) * (Lgʷ alg) + ByteSize))) msg⁰
                            where 
                                go ∷ (KnownSLH_DSAParameters alg) ⇒  BitVector((Len² alg) * (Lgʷ alg) + ByteSize) → BitVector (Lgʷ alg) → BitVector ((Len² alg) * (Lgʷ alg) + ByteSize)
                                go csum¹ msg 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = (natToNum @(W alg)) - 1  + csum¹ - (resize msg)
                        msg¹ ∷ (KnownSLH_DSAParameters alg) ⇒ Channel dom (Vec (Len alg) (BitVector (Lgʷ alg)))
                        msg¹ 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                            = (++) <$> msg⁰ <*> (fmap (unconcatBitVector# . resize) csum)
                        -- Line 8 - 11
                        tmp ∷ (HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg)
                            ⇒  Channel dom (Vec (Len alg * N alg) (ByteType))
                        tmp 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                            = fmap concat (concatMapC (map go  (iterateI @(Len alg) (+1) (natToNum @0))))
                            where
                                go ∷ (HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
                                    ⇒ IdxType alg → Channel dom (NBlockType alg)
                                go i 
                                 | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                 = chain² @(2^Lgʷ alg) (zip3C (sigⁱ i) pkSeed adrs) (fmap (\ x → resize (x !! i)) msg¹)  (fmap (\x → (natToNum @(W alg - 1)) - (resize (x !! i))) msg¹)  
                                    where
                                        sigⁱ ∷ (HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) ⇒ IdxType alg → Channel dom (NBlockType alg)
                                        sigⁱ i⁰
                                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                            = fmap (\x → x !! i⁰) sig 
                        wotspkADRS ∷ Channel dom (ADRSType alg)
                        wotspkADRS 
                                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                = transferAddressC (fmap (`setChainAddress` (natToNum @(Len alg) - 1)) adrs) WOTS_PK
-- Algorithm 9
xmss_node ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) 
     → Channel dom (IdxType alg) -- i 
     → Channel dom (IdxType alg) -- z
     → Channel dom (NodeType alg)
xmss_node input i z =  mux  (fmap (== 0x00) z) ifthen ifelse
                                                        -- $ apWhen input.hasUpdates (const (FLTSquare, maxBound))
    where
        ifthen ∷ Channel dom (NodeType alg)
        ifthen = wots_pkGen (liftA2 (\(s,t,v) w → (s,t, setKeyPairAddress (setTypeAndClear v WOTS_HASH) w)) input i)
        ifelse ∷ Channel dom (NodeType alg)
        ifelse 
          | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
          = _HStream @alg (zip3C pkSeed adrs¹ ( (‖) <$> lnode <*> rnode))
            where
                -- line 6
                lnode ∷ Channel dom (NodeType alg)
                lnode =  xmss_node input ((2*) <$> i) (fmap (\x → x - 1) z)
                -- line 7 
                rnode ∷ Channel dom (NodeType alg)
                rnode = xmss_node input (fmap (\x → 2 * x + 1) i) (fmap (\x → x - 1) z)
                skSeed ∷ Channel dom (PKSeedType alg)
                skSeed = fstOf3C input
                pkSeed ∷ Channel dom (PKSeedType alg)
                pkSeed = sndOf3C input
                adrs ∷ Channel dom (ADRSType alg)
                adrs = thdOf3C input
                adrs¹ ∷ Channel dom (ADRSType alg)
                adrs¹ = liftA3 (\s t v → setTreeIndex (setTreeHeight s t) v) (setTypeAndClearC adrs TREE) z i
-- Algorithm 10
xmss_sign ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (NBlockType alg, SKSeedType alg, PKSeedType alg, ADRSType alg) 
     → Channel dom (IdxType alg) -- idx
     → Channel dom (SIGˣᵐˢˢType alg)
xmss_sign input idx 
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    = liftA2 object sig_ots auth
    where 
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
            = concatMapC (map (uncurry (xmss_node input⁰)) (iterateI @(H' alg) (\(x, y) → (k x, fmap (1+) y)) (idx, fmap (\x → 0x0 ∷ IdxType alg) idx)))
            where
                input⁰ = fmap (\(_,s,p,a) → (s,p,a)) input
        sig_ots ∷ Channel dom (SIGʷᵒᵗˢPlusType alg)
        sig_ots = wots_sign input⁰
            where
                input⁰ = liftA2 (\(m,s,p,a) x → (m,s,p, setKeyPairAddress (setTypeAndClear a WOTS_HASH) x)) input idx

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
-- Algorithm 12
ht_sign ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (NBlockType alg, SKSeedType alg, PKSeedType alg) 
     → Channel dom (IdxType alg) -- idx_tree
     → Channel dom (IdxType alg) -- idx_leaf
     → Channel dom (SIGᴴᵀType alg)
ht_sign input idxᵗʳᵉᵉ idxˡᵉᵃᶠ
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        = concatMapC (map thdOf3C forloop)
        where 
            adrs ∷ Channel dom (ADRSType alg)
            adrs = fmap (setTreeAddress getInitADRS) idxᵗʳᵉᵉ
            pkSeed ∷ Channel dom (PKSeedType alg)
            pkSeed = thdOf3C input
            skSeed ∷ Channel dom (SKSeedType alg)
            skSeed = sndOf3C input
            sigᵗᵐᵖ = xmss_sign (liftA2 (\(m,s,p) a → (m,s,p,a)) input adrs) idxˡᵉᵃᶠ
            sigʰᵗ = sigᵗᵐᵖ
            root = xmss_pkFromSig ((\sig (m,s,p) a x → (sig,m,p,a,x)) <$> sigʰᵗ <*> input <*> adrs <*> idxˡᵉᵃᶠ)
            -- line 6 - 16
            forloop ∷ Vec (D alg) (Channel dom (NodeType alg, IdxType alg, SIGˣᵐˢˢType alg) )
            forloop 
                | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                = scanl function (zip3C root idxᵗʳᵉᵉ sigʰᵗ) (iterateI @(D alg - 1) (fmap (+1)) (fmap (const 0x001) idxᵗʳᵉᵉ))
            function ∷ Channel dom (NodeType alg, IdxType alg, SIGˣᵐˢˢType alg) 
                    → Channel dom (IdxType alg) 
                    → Channel dom (NodeType alg, IdxType alg, SIGˣᵐˢˢType alg)
            function input⁰ j 
                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                = zip3C root¹ idxTree sigᵗᵐᵖ⁰
                where
                    adrs⁰ ∷ (KnownSLH_DSAParameters alg) ⇒ Channel dom (ADRSType alg)
                    adrs⁰ 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = setLayerAddressC (setLayerAddressC adrs (fmap (unconcatBitVector# . resize) j)) (fmap (unconcatBitVector# . resize) idxTree)
                    sigʰᵗ⁰ = thdOf3C input⁰
                    idxᵗʳᵉᵉ⁰ = sndOf3C input⁰
                    root⁰ = fstOf3C input⁰
                    idxTree ∷ Channel dom (BitVector 32)
                    idxTree 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = fmap (\x → shiftL x (natToNum @(H' alg))) idxᵗʳᵉᵉ⁰
                    idxLeaf ∷ Channel dom (BitVector 32)
                    idxLeaf 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = fmap (\x → shiftL (shiftR x (natToNum @(H' alg))) (natToNum @(H' alg))) idxᵗʳᵉᵉ⁰
                    sigᵗᵐᵖ⁰ = xmss_sign (zip4C root⁰ skSeed pkSeed adrs) idxLeaf
                    -- sigʰᵗ¹ = (‖) <$> sigʰᵗ⁰ <*> sigᵗᵐᵖ⁰
                    root¹ ∷ Channel dom (NBlockType alg)
                    root¹ 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = mux cond ifthen ifelse
                        where
                            cond ∷ Channel dom Bool
                            cond 
                                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                = fmap (\ x → x < (natToNum @(D alg) - 1)) j
                            ifthen ∷ Channel dom (NBlockType alg)
                            ifthen 
                                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                =  xmss_pkFromSig ((\sig (m,s,p) a r x → (sig,r,p,a, x)) <$> sigᵗᵐᵖ⁰ <*> input <*> adrs <*> root⁰ <*> idxLeaf)
                            ifelse ∷ Channel dom (NBlockType alg)
                            ifelse 
                                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                = root⁰

-- Algorithm 13
ht_verify ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (NBlockType alg, SIGᴴᵀType alg, PKSeedType alg, PKRootType alg
     , IdxType alg -- idx_tree
     , IdxType alg -- idx_leaf 
     )
     → Channel dom (Bool)
ht_verify input  
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        = (==) <$> fstC forloop <*> pkRoot -- line 13-17
        where
            idxᵗʳᵉᵉ ∷ Channel dom (IdxType alg)
            idxᵗʳᵉᵉ = fthOf6C input
            idxˡᵉᵃᶠ ∷ Channel dom (IdxType alg)
            idxˡᵉᵃᶠ = sthOf6C input
            adrs ∷ Channel dom (ADRSType alg)
            adrs = fmap (setTreeAddress getInitADRS) idxᵗʳᵉᵉ -- line 1-2
            pkSeed ∷ Channel dom (PKSeedType alg)
            pkSeed = thdOf6C input
            pkRoot ∷ Channel dom (PKRootType alg)
            pkRoot = frtOf6C input
            sig ∷ Channel dom (SIGᴴᵀType alg)
            sig = sndOf6C input
            sig⁰ ∷ Channel dom (SIGˣᵐˢˢType alg)
            sig⁰ 
                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                = fmap head sig
            m ∷ Channel dom (NBlockType alg)
            m = fstOf6C input
            node⁰ ∷ Channel dom (NBlockType alg)
            node⁰ 
                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                = xmss_pkFromSig (zip5C sig⁰ m pkSeed adrs idxˡᵉᵃᶠ)
            forloop ∷ Channel dom (NodeType alg, IdxType alg)
            forloop 
                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                = foldl function (zipC node⁰ idxᵗʳᵉᵉ) (iterateI @(D alg - 1) (fmap (+1)) (fmap (const 0x001) idxᵗʳᵉᵉ))
            function ∷ Channel dom (NodeType alg, IdxType alg) 
                    → Channel dom (IdxType alg) 
                    → Channel dom (NodeType alg, IdxType alg)
            function input⁰ j 
                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                = zipC node² idxTree
                where
                    adrs⁰ ∷ (KnownSLH_DSAParameters alg) ⇒ Channel dom (ADRSType alg)
                    adrs⁰ 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = setLayerAddressC (setLayerAddressC adrs (fmap (unconcatBitVector# . resize) j)) (fmap (unconcatBitVector# . resize) idxTree)
                    idxᵗʳᵉᵉ⁰ = sndC input⁰
                    node¹ = fstC input⁰
                    idxTree ∷ Channel dom (BitVector 32)
                    idxTree 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = fmap (\x → shiftL x (natToNum @(H' alg))) idxᵗʳᵉᵉ⁰
                    idxLeaf ∷ Channel dom (BitVector 32)
                    idxLeaf 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = fmap (\x → shiftL (shiftR x (natToNum @(H' alg))) (natToNum @(H' alg))) idxᵗʳᵉᵉ⁰
                    node² ∷ Channel dom (NBlockType alg)
                    node² 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = xmss_pkFromSig (zip5C ( (!!) <$> sig <*> j) node¹ pkSeed adrs idxLeaf)
                    

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