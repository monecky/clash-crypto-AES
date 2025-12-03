{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic WOTS definitions covering the fundamentals of FIPS 205.
Algorithm 5- 8 are implemented and exposed for testing purposes.
According to section 5 of FIPS205
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
        chain
        -- Algorithm 6
        , wots_pkGen
        -- Algorithm 7
        , wots_sign
        -- Algorithm 8
        , wots_pkFromSig
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

chain ∷ ∀ bound (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, KnownNat bound, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg
     , IdxType alg -- i 
     , IdxType alg -- s
     )
     → Channel dom (NBlockType alg)
chain input
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        =  fstOf3C (liftA2 (!!) (concatMapC (scanl (function alg) tmp (iterateI @bound (fmap (+1)) i)))  ((-) <$> s <*> i))
            where
                i ∷ Channel dom (IdxType alg)
                i = frtOf5C input
                s ∷ Channel dom (IdxType alg)
                s = fthOf5C input
                tmp ∷ Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg)
                tmp = fmap (\(n,p,a,s⁰,i⁰) → (n,p,a)) input
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
                function i = chain @(W alg) @alg (zip5C (sk i)  (pkSeed input) (adrs input) (fmap (const (natToNum @0)) input) (fmap (const (natToNum @(W alg - 1))) input))
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
                                 = chain @(2^Lgʷ alg) (zip5C (sk i) pkSeed adrs (fmap (\x →  0x0 ∷ IdxType alg) msg¹)  (fmap (\ x → resize (x !! i)) msg¹))
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
                                 = chain @(2^Lgʷ alg) (zip5C (sigⁱ i) pkSeed adrs (fmap (\ x → resize (x !! i)) msg¹)  (fmap (\x → (natToNum @(W alg - 1)) - (resize (x !! i))) msg¹))  
                                    where
                                        sigⁱ ∷ (HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) ⇒ IdxType alg → Channel dom (NBlockType alg)
                                        sigⁱ i⁰
                                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                            = fmap (\x → x !! i⁰) sig 
                        wotspkADRS ∷ Channel dom (ADRSType alg)
                        wotspkADRS 
                                | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                = transferAddressC (fmap (`setChainAddress` (natToNum @(Len alg) - 1)) adrs) WOTS_PK
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