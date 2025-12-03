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
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Ht 
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
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.XMSS 
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
            sigᵗᵐᵖ = xmss_sign (liftA3 (\(m,s,p) a x → (m,s,p,a,x)) input adrs idxˡᵉᵃᶠ)
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
                    sigᵗᵐᵖ⁰ = xmss_sign (zip5C root⁰ skSeed pkSeed adrs idxLeaf)
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