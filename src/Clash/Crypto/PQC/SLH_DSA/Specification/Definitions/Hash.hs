{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Hash
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Implemenetation of SLH_DSA_hash of types, that are defined 
in section 4 and 11 regards Hash functions of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
module  Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Hash where
import Clash.Prelude
import Clash.Signal.Channel
import Clash.Signal.DataStream
import Clash.Signal.Delayed.Extra
import Clash.Signal.Extra (apWhen)
import Clash.Prelude.Safe hiding (fold, unzip)

import Data.Foldable (Foldable(..))
import Data.Functor ((<&>), unzip)
import GHC.Records (HasField(..))


import Data.Proxy (Proxy(..))
import Clash.Prelude
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Crypto.PQC.SLH_DSA.Specification.Types.Hash
import Clash.Crypto.Hash.SHA.Specification as Spec
import Clash.Crypto.Hash.MGF1.Specification as MGF1
import Clash.Crypto.Hash.SHA as SHA
import GHC.TypeNats.Proof (Rewrite(..), using)
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero
  )
import Language.Haskell.Unicode (type (≤))
instance SLH_DSA_hash SLH_DSA_SHA2_128s where 
    -- _PRFᵐˢᵍ ∷ (KnownNat ℓ) ⇒ Proxy alg → SKPrfType alg → Opt_randType alg → MType ℓ → PRFᵐˢᵍOutType alg
    -- _PRFᵐˢᵍ _ skPrfType opt_rand m  = 
    _Hᵐˢᵍ   ∷  ∀ (alg :: SLH_DSA) (ℓ ∷ Nat) . ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg, KnownNat ℓ,
        Div ((48 + ℓ) * 8) 8 ~ 48 + ℓ
        ) ⇒ Proxy alg → RType alg → PKSeedType alg → PKRootType alg → MType ℓ →  HᵐˢᵍOutType alg
    _Hᵐˢᵍ _ r pkSeed pkRoot m   
        | SLH_DSAFacts {} ← knownSLH_DSA @alg
        = truncˡ 
            (unconcatBitVector#   (MGF1.mgf1 
                @SHA256 
                @(M alg) -- maskLen
                @((N alg + N alg + Div (MessageDigestSize SHA256) ByteSize) * ByteSize) -- ℓ 
                @(MessageDigestSize SHA256)
                    (toInt @(N alg + N alg + Div (MessageDigestSize SHA256) ByteSize) @ByteSize @0 
                    (r ‖ pkSeed ‖ hashed r pkSeed pkRoot m))))
    --         where

    _PRF    ∷ ∀ (alg :: SLH_DSA).  ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg) ⇒ Proxy alg → PKSeedType alg → SKSeedType alg → ADRSType alg → PRFOutType alg
    _PRF   _ pkSeed skSeed adrs 
        | SLH_DSAFacts {} ← knownSLH_DSA @alg
        = truncˡ (unconcatBitVector# (Spec.hash 
                @SHA256 
                @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (SKSeedType alg)) 
                    (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (SKSeedType alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ skSeed))))
  
    _Tˡ     ∷ ∀ (alg :: SLH_DSA) ℓ.  ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg, KnownNat ℓ,  Div (688 + ((ℓ * 16) * ByteSize)) ByteSize ~ 86 + (ℓ * 16)) ⇒ Proxy alg → PKSeedType alg → ADRSType alg → MˡType ℓ alg → TˡOutType alg
    _Tˡ   _ pkSeed adrs ml
        | SLH_DSAFacts alg ← knownSLH_DSA @alg
        = truncˡ (unconcatBitVector# (Spec.hash 
                @SHA256 
                @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (MˡType ℓ alg)) 
                    (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (MˡType ℓ alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ ml))))

    _H      ∷ ∀ (alg :: SLH_DSA).  ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg) ⇒ Proxy alg → PKSeedType alg → ADRSType alg → M²Type alg → HOutType alg
    _H _ pkSeed adrs m2
        | SLH_DSAFacts {} ← knownSLH_DSA @alg
        = truncˡ (unconcatBitVector# (Spec.hash 
                @SHA256 
                @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M²Type alg)) 
                    (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M²Type alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ m2))))

    _F      ∷ ∀ (alg :: SLH_DSA).  ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg) ⇒ Proxy alg → PKSeedType alg → ADRSType alg → M¹Type alg → FOutType alg
    _F _ pkSeed adrs m1 
        | SLH_DSAFacts {} ← knownSLH_DSA @alg
        = truncˡ (unconcatBitVector# (Spec.hash 
                @SHA256 
                @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M¹Type alg)) 
                    (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M¹Type alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ m1))))

-- instance SLH_DSA_hashStream SLH_DSA_SHA2_128s where 
-- --   _PRFᵐˢᵍStream ∷ (KnownNat ℓ) ⇒ Proxy alg → SKPrfType alg → Opt_randType alg → MType ℓ → PRFᵐˢᵍOutType alg
-- --   _PRFᵐˢᵍStream _ skPrfType opt_rand m  = 
-- --   _HᵐˢᵍStream   ∷ (KnownNat ℓ) ⇒ Proxy alg → RType alg → PKSeedType alg → PKRootType alg → MType ℓ →  HᵐˢᵍOutType alg
-- --   _HᵐˢᵍStream _ r pkSeed pkRoot m = 
--     -- _PRFStream    ∷ ∀ (alg :: SLH_DSA).  ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg) ⇒ Proxy alg → PKSeedType alg → SKSeedType alg → ADRSType alg → PRFOutType alg
--     -- _PRFStream   _ pkSeed skSeed adrs 
--     --     | SLH_DSAFacts {} ← knownSLH_DSA @alg
--     --     = truncˡ (unconcatBitVector# (Spec.hash 
--     --             @SHA256 
--     --             @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (SKSeedType alg)) 
--     --                 (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (SKSeedType alg)) 8) @ByteSize @0 
--     --                 (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ skSeed))))
  
--     -- _TˡStream     ∷ ∀ (alg :: SLH_DSA) ℓ.  ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg, KnownNat ℓ,  Div (688 + ((ℓ * 16) * 8)) 8 ~ 86 + (ℓ * 16)) ⇒ Proxy alg → PKSeedType alg → ADRSType alg → MˡType ℓ alg → TˡOutType alg
--     -- _TˡStream   _ pkSeed adrs ml
--     --     | SLH_DSAFacts alg ← knownSLH_DSA @alg
--     --     = truncˡ (unconcatBitVector# (Spec.hash 
--     --             @SHA256 
--     --             @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (MˡType ℓ alg)) 
--     --                 (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (MˡType ℓ alg)) 8) @ByteSize @0 
--     --                 (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ ml))))

--     -- _HStream      ∷ ∀ (alg :: SLH_DSA).  ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg) ⇒ Proxy alg → PKSeedType alg → ADRSType alg → M²Type alg → HOutType alg
--     -- _HStream _ pkSeed adrs m2
--     --     | SLH_DSAFacts {} ← knownSLH_DSA @alg
--     --     = truncˡ (unconcatBitVector# (Spec.hash 
--     --             @SHA256 
--     --             @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M²Type alg)) 
--     --                 (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M²Type alg)) 8) @ByteSize @0 
--     --                 (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ m2))))

--     _FStream      ∷ ∀ (alg :: SLH_DSA) dom .  (KnownDomain dom, HiddenClockResetEnable dom, alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg) ⇒ Proxy alg → Channel dom (PKSeedType alg, ADRSType alg, M¹Type alg) → Channel dom (FOutType alg)
--     _FStream _ input
--         | SLH_DSAFacts {} ← knownSLH_DSA @alg
--         = fmap makeOutput (SHA.sha @SHA256 (channel2DataStream transfer))
--             where
--             transfer = fmap go input
--             makeOutput output = truncˡ (unconcatBitVector# output)
--             go (pkSeed, adrs, m1) = toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M¹Type alg)) 8) @ByteSize @0 
--                 (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ m1)
--                 -- 16, 64 - 16 , 32, 16 = 64 + 32 + 16 * 8 896



hashed ∷ ∀ (alg :: SLH_DSA) (ℓ ∷ Nat) . ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg, KnownNat ℓ, Div ((48 + ℓ) * 8) 8 ~ (48 + ℓ)) ⇒ RType alg → PKSeedType alg → PKRootType alg → MType ℓ → Vec (Div (MessageDigestSize SHA256) ByteSize) ByteType
hashed r pkSeed pkRoot m
    = unconcatBitVector# (Spec.hash 
    @SHA256 
    @((N alg + N alg + N alg + ℓ) * ByteSize) 
        (toInt @(Div ((N alg + N alg + N alg + ℓ) * ByteSize)  ByteSize) @ByteSize @0 
        (r ‖ pkSeed ‖ pkRoot ‖ m)))