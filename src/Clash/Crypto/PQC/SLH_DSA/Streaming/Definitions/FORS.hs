{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic FORS definitions covering the fundamentals of FIPS 205.
Thus algorithm 14-17 are implemented from section 8 of the FIPS 205 document.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
{-# OPTIONS_GHC -fno-max-relevant-binds #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS (
     -- Algorithm 14
    fors_skGen 
    -- Algorithm 15
    , fors_node
    -- Algorithm 16
    , fors_sign
    -- Algorithm 17
    , fors_pkFromSig

) where

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
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg, IdxType alg)
     → Channel dom (NBlockType alg)
fors_skGen input
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        = _PRFStream (fmap go input)
        where 
            go (s,p,a,i) = (p,s,skADRS²)
                where 
                    skADRS  = setTypeAndClear a FORS_PRF
                    skADRS¹ = setKeyPairAddress skADRS (getKeyPairAddress a)
                    skADRS² = setTreeIndex skADRS¹ i
-- Algorithm 15
fors_node ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg
        , IdxType alg -- i < k ⋅ 2⁽ᵃ⁻ᶻ⁾
        , IdxType alg -- z ≤ a
        )
     → Channel dom (NodeType alg)
fors_node input⁰ =  mux  (fmap (== 0x00) z) ifthen ifelse
    where
        i ∷ Channel dom (IdxType alg)
        i = fmap (\(s,p,a,x,y) → x) input⁰
        z ∷ Channel dom (IdxType alg)
        z = fmap (\(s,p,a,x,y) → y) input⁰
        input ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg)
        input = fmap (\(s,p,a,x,y) → (s,p,a)) input⁰
        ifthen ∷ Channel dom (NodeType alg)
        ifthen 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = _FStream (liftA3 (\(s,t,v) w sk → (t, setTreeIndex (setTreeHeight v (0x0 ∷ BitVector (ChainAddressTreeHeightSize alg * ByteSize))) w, sk)) input i skSeed)
            where 
                skSeed ∷ Channel dom (SKPrfType alg)
                skSeed = fors_skGen (liftA2 (\(s,t,v) w → (s,t,v,w)) input i)
        ifelse ∷ Channel dom (NodeType alg)
        ifelse
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = node
                where
                    -- line 7
                    lnode ∷ Channel dom (NodeType alg)
                    lnode =  fors_node (liftA3 (\(s,p,a) x y → (s,p,a,x,y)) input ((2*) <$> i) (fmap (\x → x - 1) z))
                    -- line 8
                    rnode ∷ Channel dom (NodeType alg)
                    rnode = fors_node (liftA3 (\(s,p,a) x y → (s,p,a,x,y)) input (fmap (\x → 2 * x + 1) i) (fmap (\x → x - 1) z))
                    adrs¹ ∷ Channel dom (ADRSType alg)
                    adrs¹ 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = liftA2 (\(s,t,v) w → setTreeIndex (setTreeHeight v (0x0 ∷ BitVector (ChainAddressTreeHeightSize alg * ByteSize))) w) input i
                    node ∷ Channel dom (NodeType alg)
                    node 
                        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                        = _HStream ((\(_,p,_) a l r →  (p,a, l ‖ r)) <$> input <*> adrs¹ <*> lnode <*> rnode)
type ForsNodeState alg  =
 (Vec (A alg) (NodeType alg),
  Index (K alg * (2 ^(A alg))), -- i current calculation
  Index (A alg), -- z current calculation
  Index (K alg * (2 ^(A alg))), -- i to find
  Index (A alg) -- z to find
 )
type ForsNodeMealState alg = (IdxType alg{-Current i-},
                              IdxType alg{-Current z-},
                              Vec (A alg) (NodeType alg) {-Buffer-},
                              Bool{-Result is ready-},
                              IdxType alg{-To calculate i-},
                              IdxType alg{-To calculate z-}, 
                              Bool{-Computation going on-},
                              NodeType alg{-Previous output-})
type ForsNodeMealInput alg = ((Maybe (IdxType alg{-i-}), Bool),
                              (Maybe (IdxType alg{-z-}), Bool), 
                              (Maybe (NodeType alg{-h-}), Bool), 
                              (Maybe (NodeType alg{-f-}), Bool))
type ForsNodeMealOutput alg = ((IdxType alg{-i-}, IdxType alg{-z-},NodeType alg{-lNode-}, NodeType alg{-rNode-}, NodeType alg{-Result-}, Bool), ProviderAction)

-- Algorithm 15
fors_nodeOpt ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg
        , IdxType alg -- i < k ⋅ 2⁽ᵃ⁻ᶻ⁾ current
        , IdxType alg -- z ≤ a depth
        )
     → Channel dom (NodeType alg)
fors_nodeOpt input⁰ 
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    = go cResult cReady
    where
        i ∷ Channel dom (IdxType alg)
        i = fmap (\(s,p,a,x,y) → x) input⁰
        z ∷ Channel dom (IdxType alg)
        z = fmap (\(s,p,a,x,y) → y) input⁰
        input ∷ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg)
        input = fmap (\(s,p,a,x,y) → (s,p,a)) input⁰
        pkSeed ∷ Channel dom (PKSeedType alg)
        pkSeed = fmap (\(s,p,a,x,y) → p) input⁰
        adrs ∷ Channel dom (ADRSType alg)
        adrs = fmap (\(s,p,a,x,y) → a) input⁰
        controller ∷ Channel dom (IdxType alg{-i-}, IdxType alg{-z-},NodeType alg{-lNode-}, NodeType alg{-rNode-}, NodeType alg{-Result-}, Bool) -- NodeType alg{-H-}, NodeType alg{-F-})
        controller 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = channel (mealy (~~>) 
            (   -- Initial state
                0x0∷ IdxType alg{-Current i-},
                0x0 ∷ IdxType alg{-Current z-},
                unconcatI (unconcatBitVector# 0x0) ∷ Vec (A alg) (NodeType alg) {-Buffer-},
                False ∷ Bool{-Result is ready-},
                0x0 ∷ IdxType alg{-To calculate i-},
                0x0 ∷ IdxType alg{-To calculate z-}, 
                False ∷ Bool{-Computation going on-},
                unconcatBitVector# 0x0 ∷ NodeType alg{-Previous output-}
            )
            ((,,,) <$> channel2Signal i <*> channel2Signal z <*> channel2Signal hInstance <*> channel2Signal fInstance))
            where
                (~~>) ∷ (ForsNodeMealState alg
                    → ForsNodeMealInput alg
                    → (ForsNodeMealState alg, ForsNodeMealOutput alg))
                (~~>) state@(_,_,_,_,_,_,False,x) input@((Just curI, True), (Just depZ, True),_,_)  
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = (state, ((0x0 ∷ IdxType alg{-Current i-},
                        0x0 ∷ IdxType alg{-Current z-},
                        unconcatBitVector# 0x0 ∷ NodeType alg {-lNode-},
                        unconcatBitVector# 0x0 ∷ NodeType alg {-lNode-},
                        x ∷ NodeType alg {-Result-}, False),Keep))
                (~~>) state@(_,_,_,_,_,_,_,x) input@(_, _, _, _)  
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = (state, ((0x0 ∷ IdxType alg{-Current i-},
                        0x0 ∷ IdxType alg{-Current z-},
                        unconcatBitVector# 0x0 ∷ NodeType alg {-lNode-},
                        unconcatBitVector# 0x0 ∷ NodeType alg {-lNode-},
                        x ∷ NodeType alg {-Result-}, False),Keep))
                -- (~~>) state@(_,_,_,_,_,_,_,_) input@(_, _, _, _)  = (state, (Nothing, Clear))
        cI = fstOf6C controller
        cZ = sndOf6C controller
        cLNode= thdOf6C controller
        cRNode = frtOf6C controller
        cResult = fthOf6C controller
        cReady = sthOf6C controller
        channel2Signal ∷ Channel dom s → Signal dom (Maybe s, Bool)
        channel2Signal inputC = (liftA2 (,) (content inputC) (hasUpdates inputC))
        go ∷ Channel dom (NodeType alg{-Result-}) → Channel dom (Bool) → Channel dom (NodeType alg{-When ready-})
        go result¹ ready¹ 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = channel $ mealy (~~>) (unconcatBitVector# 0x0) (channel2Signal inputC)
            where
                inputC = (zipC result¹ ready¹)
                (~~>) ∷ (NodeType alg)
                        → (Maybe ((NodeType alg), Bool), Bool)
                        → ((NodeType alg), (NodeType alg, ProviderAction))
                (~~>) state@(_) input@((Just (x, True)), True) = (x, (x, Release))
                (~~>) state@(x) input@(_, _) = (state, (x, Keep))    
        hInstance ∷ Channel dom (NodeType alg)
        hInstance
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = _HStream ((\p a l r →  (p,a, l ‖ r)) <$> pkSeed <*> adrs¹ <*> cLNode <*> cRNode)
            where
                adrs¹ ∷ Channel dom (ADRSType alg)
                adrs¹ 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = liftA3 (\a v w → setTreeIndex (setTreeHeight a (v ∷ BitVector (ChainAddressTreeHeightSize alg * ByteSize))) w) adrs cI cZ
        fInstance ∷ Channel dom (NodeType alg)
        fInstance
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = _FStream @alg ((\a w sk p → (p, setTreeIndex (setTreeHeight a (0x0 ∷ BitVector (ChainAddressTreeHeightSize alg * ByteSize))) w, sk)) <$> adrs <*> cI <*> skPrf <*> pkSeed)
            where 
                skPrf ∷ Channel dom (SKPrfType alg)
                skPrf = fors_skGen (liftA2 (\(s,t,v) w → (s,t,v,w)) input cI)

-- Algorithm 16
fors_sign ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (MDByteType alg, SKSeedType alg, PKSeedType alg, ADRSType alg) 
     → Channel dom (SIGᶠᵒʳˢType alg)
fors_sign input
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    = sigᶠᵒʳˢ
    where 
        indices ∷ Channel dom (Vec (K alg) (BitVector (A alg)))
        indices 
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = fmap unconcatBitVector# (fmap (v2bv . takeI @(MD alg) @((CeilXDivY (MD alg) ByteSize) * ByteSize - MD alg) . bv2v) (fstOf4C input))
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
            = fors_skGen (liftA2 (\(_,s,t,v) i → (s,t,v,i)) input makeIdx)
                where
                    makeIdx ∷ Channel dom (IdxType alg)
                    makeIdx 
                        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                        = (liftA2 (\x y→ shiftL y (natToNum @(A alg)) + x) idx i)
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
                    = fors_node (liftA3 (\(_,s,t,v) x y → (s,t,v,x,y)) input  i⁰ j⁰)
        object ∷  ( KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg)
                ⇒ PrivateKeyValueTreeType alg → AUTHTreeType alg → ElemForsType alg
        object x y 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = ElemForsType {privateKeyValueElem = x, authElem = y}

-- Algorithm 17
fors_pkFromSig ∷ ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg) 
    ⇒ Channel dom (SIGᶠᵒʳˢType alg, MDByteType alg, PKSeedType alg, ADRSType alg) 
     → Channel dom (NBlockType alg)
fors_pkFromSig input
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    = _TˡStream @alg @(K alg) @dom (zip3C pkSeed forspkADRS root)
    where
        sigᶠᵒʳˢ ∷ Channel dom (SIGᶠᵒʳˢType alg)
        sigᶠᵒʳˢ = fstOf4C input
        adrs ∷ Channel dom (ADRSType alg)
        adrs = frtOf4C input
        pkSeed ∷ Channel dom (PKSeedType alg)
        pkSeed = thdOf4C input
        -- Line 1
        indices ∷ Channel dom (Vec (K alg) (BitVector (A alg)))
        indices 
            | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
            = fmap unconcatBitVector# (fmap (v2bv . takeI @(MD alg) @((CeilXDivY (MD alg) ByteSize) * ByteSize - MD alg). bv2v) (sndOf4C input))
        -- Line 21- 23
        forspkADRS ∷ Channel dom (ADRSType alg)
        forspkADRS = setKeyPairAddressC forspkADRS⁰ (getKeyPairAddressC adrs)
            where
                forspkADRS⁰ ∷ Channel dom (ADRSType alg)
                forspkADRS⁰ = setTypeAndClearC adrs FORS_ROOTS
        root ∷ Channel dom (MˡType (K alg) alg)
        root 
            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = fmap concat (concatMapC (map function iterationi))
            where
                -- code line 2                    i               ,  i
                iterationi ∷ Vec (K alg) (Channel dom (IdxType alg), Int )
                iterationi 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = iterateI @(K alg) function⁰ (fmap (\x → 0x0∷ IdxType alg) input, 0)
                    where
                        function⁰ (x, y) = (fmap (+1) x, y+1) 
                function ∷ (Channel dom (IdxType alg), Int ) → Channel dom (NBlockType alg)
                function (iBV,iInt) 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = node¹
                    where
                        -- Line 3
                        sk ∷ Channel dom (PrivateKeyValueTreeType alg)
                        sk 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                            = fmap go sigᶠᵒʳˢ
                            where 
                                go ∷ SIGᶠᵒʳˢType alg → PrivateKeyValueTreeType alg
                                go x 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = f (x !! iInt)
                                f ∷ ElemForsType alg → PrivateKeyValueTreeType alg
                                f (ElemForsType { privateKeyValueElem = i }) 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = i 
                        -- Line 3
                        auth ∷ Channel dom (AUTHTreeType alg)
                        auth = fmap go sigᶠᵒʳˢ
                            where 
                                go ∷ SIGᶠᵒʳˢType alg → AUTHTreeType alg
                                go x 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = f (x !! iInt)
                                f ∷ ElemForsType alg → AUTHTreeType alg
                                f (ElemForsType { authElem = i }) 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = i 
                        indicesi ∷ Channel dom (IdxType alg)
                        indicesi 
                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                            = fmap (\ x → resize (x !! iInt)) indices
                        -- Line 5
                        adrs⁵ ∷ Channel dom (ADRSType alg)
                        adrs⁵ = setTreeIndexC adrs⁴ i2ᵃindicesi
                            where 
                                -- Line 4
                                adrs⁴ ∷ Channel dom (ADRSType alg)
                                adrs⁴ = setTreeHeightC adrs (fmap (\x → 0x0∷ IdxType alg) input)
                                i2ᵃ ∷ Channel dom (IdxType alg)
                                i2ᵃ 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = fmap (\x → shiftL x (natToNum @(A alg))) iBV

                                i2ᵃindicesi ∷ Channel dom (IdxType alg)
                                i2ᵃindicesi = (+) <$> i2ᵃ <*> indicesi
                        -- Line 6
                        node⁰ ∷ Channel dom (NBlockType alg)
                        node⁰ = _FStream @alg (zip3C pkSeed  adrs⁵ sk) 
                        -- Line 8 - 18
                        node¹ ∷ Channel dom (NBlockType alg)
                        node¹ = foldl function¹ node⁰ iterationj 
                            where
                                iterationj ∷ Vec (A alg) (Channel dom (IdxType alg), Int )
                                iterationj 
                                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                    = iterateI @(A alg) function⁰ (fmap (\x → 0x0∷ IdxType alg) input, 0)
                                    where
                                        function⁰ (x, y) = (fmap (+1) x, y+1) 
                                function¹ ∷ Channel dom (NBlockType alg) 
                                            → (Channel dom (IdxType alg), Int ) 
                                            → Channel dom (NBlockType alg)
                                function¹ node (jBV, jInt) = _HStream @alg (zip3C pkSeed adrsʰ m²)
                                    where
                                        -- Line 9
                                        adrs⁹ ∷ Channel dom (ADRSType alg)
                                        adrs⁹ = setTreeHeightC adrs⁵ (fmap (+1) jBV)
                                        -- Line 10
                                        cond ∷ Channel dom (Bool)
                                        cond = fmap (\x →  testBit (complement x) jInt) indicesi  
                                        authj ∷ Channel dom (NBlockType alg)
                                        authj 
                                            | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                                            = fmap (!! jInt) auth
                                        adrs¹⁰_¹⁴ ∷ Channel dom (BitVector (HashAddressTreeIndexSize alg * ByteSize))
                                        adrs¹⁰_¹⁴ = mux cond (fmap (\x → 0x0∷ IdxType alg) input) (fmap (\x → 0x1∷ IdxType alg) input)
                                        m² ∷ Channel dom (M²Type alg)
                                        m² = mux cond ((‖) <$> node <*> authj) ((‖) <$> authj <*> node)
                                        adrsʰ = setTreeIndexC adrs⁹ (fmap ((+>>.) 0) (liftA2 (-) (getTreeIndexC adrs⁹) adrs¹⁰_¹⁴))


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