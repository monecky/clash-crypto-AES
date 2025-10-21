{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic WOTS definitions covering the fundamentals of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
{-# OPTIONS_GHC -fno-max-relevant-binds #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus where
import Clash.Prelude
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.PQC.SLH_DSA.General.General
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Streaming.Types.Hash
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash

import Clash.Signal.Channel
import Clash.Signal.Channel.Extra 
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics (base_2ᵇ)
import Data.Proxy (Proxy(..))
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Address 
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address 
-- Algorithm 5
chain ∷ ∀ i s (alg ∷ SLH_DSA) dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg,
         KnownNat i, KnownNat s, 0 ≤ i, SLH_DSA_hashStream alg) 
    ⇒ Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg) → Channel dom (NBlockType alg)
chain tmp 
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        = fstOf3C (foldl (function alg) tmp (iterateI @s (+1) (natToNum @i)))
            where
                function ∷ Proxy alg 
                    → Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg) 
                    → BitVector (ChainAddressTreeHeightSize alg * ByteSize)
                    → Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg)
                function alg x1 j = zip3C (_FStream alg (fmap (go j) x1)) pkSeed adrs
                    where 
                        pkSeed ∷ Channel dom (PKSeedType alg)
                        pkSeed = sndOf3C x1
                        adrs ∷ Channel dom (ADRSType alg)
                        adrs = thdOf3C x1
                go ∷  BitVector (ChainAddressTreeHeightSize alg * ByteSize) 
                    → (NBlockType alg, PKSeedType alg, ADRSType alg)
                    → (PKSeedType alg, ADRSType alg, NBlockType alg)
                go j (x, pkSeed, adrs) = (pkSeed, setHashAddress adrs j, x)
-- Algorithm 6
wots_pkGen ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStream alg)
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (NBlockType alg)
wots_pkGen input
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        -- postscanl representing the for loop on line code 4-9 
        = _TˡStream @alg @dom @(Len alg) alg (zip3C (pkSeed input) wotspkADRS² (tmp alg))
            where 
                adrs ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (ADRSType alg)
                adrs input  = thdOf3C input 
                pkSeed ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) →  Channel dom (PKSeedType alg)
                pkSeed input = fstOf3C input 
                skSeed ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (SKSeedType alg)
                skSeed input = sndOf3C input 
                -- Code line 1- 3
                skADRS³ ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (ADRSType alg)
                skADRS³ input = liftA2 (\ad ad²  → setKeyPairAddress ad² (getKeyPairAddress ad)) (setTypeAndClearC adrs¹ WOTS_PRF) adrs¹
                    where 
                        adrs¹ = adrs input
                --Code line 5 -8 for in the for loop
                function ∷ (KnownSLH_DSAParameters alg, SLH_DSA_hashStream alg) 
                    ⇒  Proxy alg → BitVector (ChainAddressTreeHeightSize alg * ByteSize) → Channel dom (NBlockType alg)
                function alg i = chain @0  @(W alg - 1) @alg (zip3C (sk alg i)  (pkSeed input) (adrs input))
                    where
                        sk alg i = _PRFStream alg (liftA2 (\(sk, pk, _) ad → (pk, sk, ad)) input (setChainAddressC (adrs input) i))
                -- Variable define on line 8
                tmp ∷ (KnownSLH_DSAParameters alg, SLH_DSA_hashStream alg) ⇒ Proxy alg → Channel dom (Vec (Len alg * N alg) (ByteType))
                tmp alg 
                     | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg    
                     = fmap concat (concatMapC @(Len alg)  (tmp⁰ alg))
                tmp⁰ ∷ (KnownSLH_DSAParameters alg, SLH_DSA_hashStream alg) ⇒ Proxy alg → Vec (Len alg) (Channel dom (NBlockType alg))
                tmp⁰ alg 
                        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg    
                      = map  (function alg) (iterateI @(Len alg) (+1) (0x0 ∷ BitVector (ChainAddressTreeHeightSize alg * ByteSize)))
                -- Code line 10 - 12
                wotspkADRS² ∷ Channel dom (ADRSType alg)
                wotspkADRS² = liftA2 (\ad ad¹  → setKeyPairAddress ad¹ (getKeyPairAddress ad)) (setTypeAndClearC adrs¹ WOTS_PK) adrs¹
                    where 
                        adrs¹ = adrs input

-- Algorithm 7
wots_sign ∷ ∀ alg dom . (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg) 
            ⇒ Channel dom (NBlockType alg, SKSeedType alg, PKSeedType alg, ADRSType alg) → Channel dom (SIGʷᵒᵗˢPlusType alg)
wots_sign input                               
                | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg  
                = concatMapC (repeat (fstOf4C input))
                    where
                        m ∷ Channel dom (NBlockType alg)
                        m = fstOf4C input
                        msg⁰ ∷ (KnownSLH_DSAParameters alg) ⇒ Channel dom (Vec (Len¹ alg) (BitVector (Lgʷ alg)))
                        msg⁰ 
                            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg  
                            = fmap (base_2ᵇ @(Lgʷ alg) @(Len¹ alg) @(N alg) @(((N alg * ByteSize) `Div` (Lgʷ alg)) - Len¹ alg))  m
                        csum ∷ (KnownSLH_DSAParameters alg) ⇒  Channel dom (BitVector((Len² alg) * (Lgʷ alg) + ByteSize))
                        csum 
                            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                            = fmap (foldl go (0x00 ∷ BitVector((Len² alg) * (Lgʷ alg) + ByteSize))) msg⁰
                            where 
                                go ∷(KnownSLH_DSAParameters alg) ⇒  BitVector((Len² alg) * (Lgʷ alg) + ByteSize) → BitVector (Lgʷ alg) → BitVector ((Len² alg) * (Lgʷ alg) + ByteSize)
                                go csum¹ msg 
                                    | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                                    = (natToNum @(W alg)) - 1  + csum¹ - (resize msg)
                        msg¹ ∷ (KnownSLH_DSAParameters alg) ⇒ Channel dom (Vec (Len alg) (BitVector (Lgʷ alg)))
                        msg¹ 
                            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                            = (++) <$> msg⁰ <*> (fmap (unconcatBitVector# . resize) csum)
                        -- skADRS ∷ Channel dom (AdrsType alg)
                        -- skADRS = 



concatMapC ∷ ∀ ℓ a dom . (KnownNat ℓ) ⇒  Vec ℓ (Channel dom a) -> Channel dom (Vec ℓ a)
concatMapC Nil = errorX "Invalid vector"
concatMapC ( x `Cons` Nil) = fmap singleton  x 
concatMapC (x `Cons` xs) = liftA2 (++) (fmap singleton x) (concatMapC xs)

