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
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "Use camelCase" #-}
module  Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Hash where

import Clash.Prelude.Safe hiding (fold, unzip)



import Data.Proxy (Proxy(..))

import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics

import Clash.Crypto.Hash.SHA.Specification as Spec
import Clash.Crypto.Hash.MGF1.Specification as MGF1Spec
import GHC.TypeNats.Proof (Rewrite(..), using)
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple, DivTimes, ModTimes
  )

---------------------------------------------------------------------------
-- Hashfunctions class that is discribed in section 4.1 of FIPS 205.
-- This is only the interface.
--
---------------------------------------------------------------------------
class SLH_DSA_hash (sha ∷ SHAVersion) (security ∷ SecurityLevel) where
  _PRFᵐˢᵍ ∷ ∀ (alg ∷ SLH_DSA) ℓ . (KnownSLH_DSAParameters alg, KnownNat ℓ) ⇒ SKPrfType alg → Opt_randType alg → MType ℓ → PRFᵐˢᵍOutType alg
  _Hᵐˢᵍ   ∷ ∀ (alg ∷ SLH_DSA) ℓ . (KnownSLH_DSAParameters alg, KnownNat ℓ) ⇒ RType alg → PKSeedType alg → PKRootType alg → MType ℓ →  HᵐˢᵍOutType alg
  _PRF    ∷ ∀ (alg ∷ SLH_DSA)   . (KnownSLH_DSAParameters alg)             ⇒ PKSeedType alg → SKSeedType alg → ADRSType alg → PRFOutType alg
  _Tˡ     ∷ ∀ (alg ∷ SLH_DSA) ℓ . (KnownSLH_DSAParameters alg, KnownNat ℓ) ⇒ PKSeedType alg → ADRSType alg → MˡType ℓ alg → TˡOutType alg
  _H      ∷ ∀ (alg ∷ SLH_DSA)   . (KnownSLH_DSAParameters alg)             ⇒ PKSeedType alg → ADRSType alg → M²Type alg → HOutType alg
  _F      ∷ ∀ (alg ∷ SLH_DSA)   . (KnownSLH_DSAParameters alg)             ⇒ PKSeedType alg → ADRSType alg → M¹Type alg → FOutType alg

-- import Clash.Crypto.Hash.SHA as SHA
-- import Clash.Crypto.MAC.HMAC as HMAC
-- import Clash.Crypto.Hash.MGF1.Streaming as MGF1
-- import GHC.TypeNats.Proof (Rewrite(..), using)
-- import Data.Constraint.Nat.Extra
--   ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
--   , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple 
--   )
-- import Language.Haskell.Unicode (type (≤))
instance SLH_DSA_hash SHATwo SecurityOne where 
    -- No functional function of HMAC sha exists.
    -- _PRFᵐˢᵍ ∷ (KnownNat ℓ) ⇒ Proxy alg → SKPrfType alg → Opt_randType alg → MType ℓ → PRFᵐˢᵍOutType alg
    -- _PRFᵐˢᵍ _ skPrfType opt_rand m  = 
    -- _Hᵐˢᵍ   ∷  ∀ (alg ∷ SLH_DSA) ℓ . (KnownSLH_DSAParameters alg, KnownNat ℓ) ⇒ RType alg → PKSeedType alg → PKRootType alg → MType ℓ →  HᵐˢᵍOutType alg
    -- _Hᵐˢᵍ r pkSeed pkRoot m   
    --     | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    --     , Rewrite ← using @(DivTimes (((N alg + N alg) + N alg) + ℓ) ByteSize) 
    --     =  -- truncˡ 
    --         (unconcatBitVector#   (MGF1Spec.mgf1 
    --             @SHA256 
    --             @(M alg) -- maskLen
    --             @((N alg + N alg + Div (MessageDigestSize SHA256) ByteSize) * ByteSize) -- ℓ 
    --             @(MessageDigestSize SHA256) -- hLen
    --                 (toInt @(N alg + N alg + Div (MessageDigestSize SHA256) ByteSize) @ByteSize @0 
    --                 (r ‖ pkSeed ‖ (hashed r pkSeed pkRoot m)))))
    --         where
    --             hashed ∷ RType alg → PKSeedType alg → PKRootType alg → MType ℓ → Vec (Div (MessageDigestSize SHA256) ByteSize) ByteType
    --             hashed r pkSeed pkRoot m
    --                     | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    --                      , Rewrite ← using @(DivTimes (((N alg + N alg) + N alg) + ℓ) ByteSize) 
    --                 = unconcatBitVector# (Spec.hash 
    --                 @SHA256 
    --                 @((N alg + N alg + N alg + ℓ) * ByteSize) 
    --                     (toInt @(Div ((N alg + N alg + N alg + ℓ) * ByteSize)  ByteSize) @ByteSize @0 
    --                     (r ‖ pkSeed ‖ pkRoot ‖ m)))

    _PRF    ∷ ∀ (alg :: SLH_DSA).  (KnownSLH_DSAParameters alg) ⇒ PKSeedType alg → SKSeedType alg → ADRSType alg → PRFOutType alg
    _PRF   pkSeed skSeed adrs 
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        = truncˡ (unconcatBitVector# (Spec.hash 
                @SHA256 
                @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (SKSeedType alg)) 
                    (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (SKSeedType alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ skSeed))))
  
    _Tˡ     ∷ ∀ (alg :: SLH_DSA) ℓ.  ( KnownSLH_DSAParameters alg, KnownNat ℓ) ⇒ PKSeedType alg → ADRSType alg → MˡType ℓ alg → TˡOutType alg
    _Tˡ   pkSeed adrs ml
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        , Rewrite ← using @(DivTimes (((N alg + (64 - N alg))
                            + (((((LayerAddressSize alg + TreeAddressSize alg) + TypeSize alg)
                                 + 4)
                                + 4)
                               + 4))
                           + (ℓ * N alg)) ByteSize) 
        = truncˡ (unconcatBitVector# (Spec.hash 
                @SHA256 
                @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (MˡType ℓ alg)) 
                    (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (MˡType ℓ alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ ml))))

    _H      ∷ ∀ (alg :: SLH_DSA).  (KnownSLH_DSAParameters alg) ⇒ PKSeedType alg → ADRSType alg → M²Type alg → HOutType alg
    _H pkSeed adrs m2
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        , Rewrite ← using @(DivTimes (((N alg + (64 - N alg))
                            + (((((LayerAddressSize alg + TreeAddressSize alg) + TypeSize alg)
                                 + 4)
                                + 4)
                               + 4))
                           + (2 * N alg)) ByteSize)
        = truncˡ (unconcatBitVector# (Spec.hash 
                @SHA256 
                @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M²Type alg)) 
                    (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M²Type alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ m2))))

    _F      ∷ ∀ (alg :: SLH_DSA).  (KnownSLH_DSAParameters alg) ⇒ PKSeedType alg → ADRSType alg → M¹Type alg → FOutType alg
    _F pkSeed adrs m1 
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        = truncˡ (unconcatBitVector# (Spec.hash 
                @SHA256 
                @(BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M¹Type alg)) 
                    (toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (M¹Type alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ m1))))

