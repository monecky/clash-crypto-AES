{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic FORS definitions covering the fundamentals of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
{-# OPTIONS_GHC -fno-max-relevant-binds #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS where

import Clash.Prelude
import Clash.Sized.Internal.BitVector
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.PQC.SLH_DSA.General.General
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Streaming.Types.Hash
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
-- Algorithm 14
fors_skGen ∷  ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) 
     → Channel dom (IdxType alg) -- idx
     → Channel dom (NBlockType alg)
fors_skGen input idx
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        = _PRFStream (liftA2 go input idx)
        where 
            go (s,p,a) i = (s,p, skADRS²)
                where 
                    skADRS  = setTypeAndClear a FORS_PRF
                    skADRS¹ = setKeyPairAddress skADRS (getKeyPairAddress a)
                    skADRS² = setTreeIndex skADRS¹ i
-- Algorithm 15
fors_node ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) 
     → Channel dom (IdxType alg) -- i 
     → Channel dom (IdxType alg) -- z
     → Channel dom (NodeType alg)
fors_node input i z =  mux  (fmap (== 0x00) z) ifthen ifelse
    where
        ifthen ∷ Channel dom (NodeType alg)
        ifthen 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = _FStream (liftA2 (\(s,t,v) w → (t, setTreeIndex (setTreeHeight v (0x0 ∷ BitVector (ChainAddressTreeHeightSize alg * ByteSize))) w, s)) input i)
        ifelse ∷ Channel dom (NodeType alg)
        ifelse
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = node
                where
                    -- line 7
                    lnode ∷ Channel dom (NodeType alg)
                    lnode =  fors_node input ((2*) <$> i) (fmap (\x → x - 1) z)
                    -- line 8
                    rnode ∷ Channel dom (NodeType alg)
                    rnode = fors_node input (fmap (\x → 2 * x + 1) i) (fmap (\x → x - 1) z)
                    adrs¹ ∷ Channel dom (ADRSType alg)
                    adrs¹ 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = liftA2 (\(s,t,v) w → setTreeIndex (setTreeHeight v (0x0 ∷ BitVector (ChainAddressTreeHeightSize alg * ByteSize))) w) input i
                    node ∷ Channel dom (NodeType alg)
                    node 
                        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                        = _HStream ((\(_,p,_) a l r →  (p,a, l ‖ r)) <$> input <*> adrs¹ <*> lnode <*> rnode)

-- Algorithm 16
fors_sign ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (MDType alg, SKSeedType alg, PKSeedType alg, ADRSType alg) 
     → Channel dom (SIGᶠᵒʳˢType alg)
fors_sign input
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    = sigᶠᵒʳˢ
    where 
        indices ∷ Channel dom (Vec (K alg) (BitVector (A alg)))
        indices 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = fmap unconcatBitVector# (fstOf4C input)
        indicesi ∷ Vec (K alg) (Channel dom (IdxType alg), Channel dom (IdxType alg))
        indicesi 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = map (\(x,y,z) → (x,z)) sub
            where
                sub ∷ Vec (K alg) (Channel dom (IdxType alg), Int, Channel dom (IdxType alg))
                sub 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = (generateI @(K alg) (\(x, y, z) → (fmap (\x → resize (x !! (y + 1))) indices, y + 1 , fmap (+1) z)) (fmap (\x → 0x0 ∷ IdxType alg) input, -1 , fmap (\x → 0x0 ∷ IdxType alg) input))
        sigᶠᵒʳˢ ∷ Channel dom (SIGᶠᵒʳˢType alg)
        sigᶠᵒʳˢ 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = concatMapC (map function indicesi)
        function ∷ (Channel dom (IdxType alg), Channel dom (IdxType alg)) → Channel dom (ElemForsType alg)
        function idxi 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = liftA2 object (sig idxi) (auth idxi)
        sig ∷ (Channel dom (IdxType alg), Channel dom (IdxType alg)) → Channel dom (PrivateKeyValueTreeType alg)
        sig (idx, i) 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = fors_skGen (fmap (\(_,s,t,v) → (s,t,v)) input) (liftA2 (\x y→ shiftL y (natToNum @(A alg)) + x) idx i)
        auth ∷ (Channel dom (IdxType alg), Channel dom (IdxType alg)) → Channel dom (AUTHTreeType alg)
        auth (idx, i) 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = concatMapC (zipWith function⁰  (i2ᵃʲs (idx, i))  j)
            where 
                s ∷ Channel dom (IdxType alg) → Vec (A alg) (Channel dom (IdxType alg))
                s idx 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = iterateI @(A alg) (fmap ( \i → xor# ((0 +>>.) i) 1)) (idx)
                i2ᵃʲ ∷ Channel dom (IdxType alg) → Vec (A alg) (Channel dom (IdxType alg))
                i2ᵃʲ i 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = iterateI @(A alg) (\i →  (fmap (.<<+ 0) i)) i 
                i2ᵃʲs   ∷ (Channel dom (IdxType alg), Channel dom (IdxType alg)) →  Vec (A alg) (Channel dom (IdxType alg))
                i2ᵃʲs (idx, i) 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = zipWith (zipWithC (+)) (s idx) (i2ᵃʲ i)
                j ∷ Vec (A alg) (Channel dom (IdxType alg))
                j 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = iterateI @(A alg) (fmap (+1)) (fmap (\x → 0x0∷ IdxType alg) input)
                function⁰ ∷ Channel dom (IdxType alg) → Channel dom (IdxType alg) → Channel dom (NBlockType alg)
                function⁰ i⁰ j⁰ 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = fors_node  (fmap (\(_,s,t,v) → (s,t,v)) input)  i⁰ j⁰



        object ∷  ( KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg)
                ⇒ PrivateKeyValueTreeType alg → AUTHTreeType alg → ElemForsType alg
        object x y 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = ElemForsType {privateKeyValueElem = x, authElem = y}



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