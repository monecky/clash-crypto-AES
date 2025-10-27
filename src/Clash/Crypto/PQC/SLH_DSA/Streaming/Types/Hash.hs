{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Types.Hash
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic types covering the fundamentals of FIPS 205.
All subscript are superscripts, since not all subscripts are 
defined in unicode. But for superscript there are.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}

module Clash.Crypto.PQC.SLH_DSA.Streaming.Types.Hash (
     SLH_DSA_hashStreamFact
    , SLH_DSA_hashStream(..)
    , _FStream
    , _HStream
    , _TˡStream
    , _PRFStream
    , _HᵐˢᵍStream
    , _PRFᵐˢᵍStream
) where
import Clash.Prelude
import Clash.Sized.BitVector (BitVector)
import Clash.Sized.Vector (Vec)
import Clash.Class.BitPack (BitPack)
import Clash.XException (NFDataX)
import Data.Eq (Eq)
import Data.Type.Equality
import Data.Enum (Enum, Bounded)
import Data.Kind (Type)
import Data.Ord (Ord)
import Data.Typeable (Typeable)
import GHC.Show (Show)

import GHC.Generics (Generic)
import GHC.TypeLits
import Data.Proxy (Proxy(..))
import Data.Type.Bool (If)
import Clash.Crypto.Hash.SHA as SHA
import Clash.Crypto.PQC.SLH_DSA.Specification.Types.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Types.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Signal.Channel
import Clash.Signal.DataStream
import Clash.Signal.Delayed.Extra
import Clash.Signal.Extra (apWhen)
class (KnownSLH_DSAParameters alg) ⇒ SLH_DSA_hashStream  (sha ∷ SHAVersion) (security ∷ SecurityLevel) (alg ∷ SLH_DSA)where
  -- Since a DataStream is used for flexible size messages and that is neded for algorithm 19, 20, PRFᵐˢᵍ and Hᵐˢᵍ, need to take a stream as input.
  _PRFᵐˢᵍStreaming ∷ ∀ sha security alg ℓ dom . (KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ, KnownSLH_DSAParameters alg) 
                  ⇒ Proxy alg → Channel dom (SKPrfType alg, Opt_randType alg, MType ℓ) → Channel dom (PRFᵐˢᵍOutType alg)
  _HᵐˢᵍStreaming   ∷ ∀ sha security alg ℓ dom . (KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ) 
                  ⇒ Proxy alg → Channel dom (RType alg, PKSeedType alg, PKRootType alg, MType ℓ) →  Channel dom (HᵐˢᵍOutType alg)
  _PRFStreaming    ∷ (KnownDomain dom, HiddenClockResetEnable dom) ⇒ Channel dom (PKSeedType alg,  SKSeedType alg, ADRSType alg) → Channel dom (PRFOutType alg)
  _TˡStreaming     ∷ ∀ sha security alg ℓ dom . (KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ) 
                  ⇒ Channel dom (PKSeedType alg, ADRSType alg, MˡType ℓ alg) → Channel dom (TˡOutType alg)
  _HStreaming      ∷ (KnownDomain dom, HiddenClockResetEnable dom) ⇒ Channel dom (PKSeedType alg, ADRSType alg, M²Type alg) → Channel dom (HOutType alg)
  _FStreaming      ∷ (KnownDomain dom, HiddenClockResetEnable dom) ⇒ Channel dom (PKSeedType alg, ADRSType alg, M¹Type alg) → Channel dom (FOutType alg)
  -- type CeilXDivY ∷ Nat → Nat → Nat
type family  SLH_DSA_hashStreamFact (alg ∷ SLH_DSA) where
    SLH_DSA_hashStreamFact alg = SLH_DSA_hashStream (SHAVersionSLH_DSA alg) (SecurityLevelSLH_DSA alg) alg
_PRFᵐˢᵍStream ∷ ∀ alg ℓ dom . (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ) ⇒ Channel dom (SKPrfType alg, Opt_randType alg, MType ℓ) → Channel dom (PRFᵐˢᵍOutType alg)
_PRFᵐˢᵍStream 
  | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
  = _PRFᵐˢᵍStreaming  @(SHAVersionSLH_DSA alg) @(SecurityLevelSLH_DSA alg) @alg @ℓ alg
_HᵐˢᵍStream ∷ ∀ alg ℓ dom . (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ) ⇒ Channel dom (RType alg, PKSeedType alg, PKRootType alg, MType ℓ) →  Channel dom (HᵐˢᵍOutType alg)
_HᵐˢᵍStream 
  | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
  = _HᵐˢᵍStreaming  @(SHAVersionSLH_DSA alg) @(SecurityLevelSLH_DSA alg) @alg @ℓ alg
_PRFStream ∷ ∀ alg dom . (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownDomain dom, HiddenClockResetEnable dom) ⇒ Channel dom (PKSeedType alg,  SKSeedType alg, ADRSType alg) → Channel dom (PRFOutType alg)
_PRFStream = _PRFStreaming  @(SHAVersionSLH_DSA alg) @(SecurityLevelSLH_DSA alg) @alg
_TˡStream ∷ ∀ alg ℓ dom . (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ) ⇒  Channel dom (PKSeedType alg, ADRSType alg, MˡType ℓ alg) → Channel dom (TˡOutType alg)
_TˡStream =  _TˡStreaming @(SHAVersionSLH_DSA alg) @(SecurityLevelSLH_DSA alg) @alg @ℓ
_HStream ∷ ∀ alg dom . (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownDomain dom, HiddenClockResetEnable dom) ⇒ Channel dom (PKSeedType alg, ADRSType alg, M²Type alg) → Channel dom (HOutType alg)
_HStream = _HStreaming  @(SHAVersionSLH_DSA alg) @(SecurityLevelSLH_DSA alg) @alg
_FStream ∷ ∀ alg dom . (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownDomain dom, HiddenClockResetEnable dom) ⇒ Channel dom (PKSeedType alg, ADRSType alg, M¹Type alg) → Channel dom (FOutType alg)
_FStream = _FStreaming  @(SHAVersionSLH_DSA alg) @(SecurityLevelSLH_DSA alg) @alg 