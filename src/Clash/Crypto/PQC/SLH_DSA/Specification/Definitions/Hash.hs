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
module  Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Hash where
import Data.Proxy (Proxy(..))
import Clash.Prelude
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Crypto.Hash.SHA.Specification as Spec
instance SLH_DSA_hash SLH_DSA_SHA2_128s where 
--   _PRFᵐˢᵍ ∷ (KnownNat ℓ) ⇒ Proxy alg → SKPrfType alg → Opt_randType alg → MType ℓ → PRFᵐˢᵍOutType alg
--   _PRFᵐˢᵍ _ skPrfType opt_rand m  = 
--   _Hᵐˢᵍ   ∷ (KnownNat ℓ) ⇒ Proxy alg → RType alg → PKSeedType alg → PKRootType alg → MType ℓ →  HᵐˢᵍOutType alg
--   _Hᵐˢᵍ _ r pkSeed pkRoot m = 
    _PRF    ∷ ∀ (alg :: SLH_DSA).  ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg) ⇒ Proxy alg → PKSeedType alg → SKSeedType alg → ADRSType alg → PRFOutType alg
    _PRF   _ pkSeed skSeed adrs 
        | SLH_DSAFacts {} ← knownSLH_DSA @alg
        = truncˡ (unconcatBitVector# (Spec.hash 
                @SHA256 
                @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (SKSeedType alg)) 
                    (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (SKSeedType alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ skSeed))))
  
    _Tˡ     ∷ ∀ (alg :: SLH_DSA) ℓ.  ( alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSA alg, KnownNat ℓ,  Div (688 + ((ℓ * 16) * 8)) 8 ~ 86 + (ℓ * 16)) ⇒ Proxy alg → PKSeedType alg → ADRSType alg → MˡType ℓ alg → TˡOutType alg
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