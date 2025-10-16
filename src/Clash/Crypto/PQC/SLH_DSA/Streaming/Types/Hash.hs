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
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}

module Clash.Crypto.PQC.SLH_DSA.Streaming.Types.Hash (
    SLH_DSA_hashStream(..)
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
import Clash.Signal.Channel
import Clash.Signal.DataStream
import Clash.Signal.Delayed.Extra
import Clash.Signal.Extra (apWhen)
class SLH_DSA_hashStream (alg ∷ SLH_DSA) where
  _PRFᵐˢᵍStream ∷ (KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ , Div (640 + (ℓ * 8)) 8 ~  80 + ℓ
            , Mod (640 + (ℓ * 8)) 8 ~ 0, Mod (1152 + (ℓ * 8)) 8 ~ 0, Div (1152 + (ℓ * 8)) 8 ~ (144 + ℓ)) ⇒ Proxy alg → Channel dom (SKPrfType alg, Opt_randType alg, MType ℓ) → Channel dom (PRFᵐˢᵍOutType alg)
  _HᵐˢᵍStream   ∷ (KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ, 1 <= Div (384 + (ℓ * 8)) 8 * 8, Div (384 + (ℓ * 8)) 8 ~ (48 + ℓ), Mod (384 + (ℓ * 8)) 8 ~ 0) 
          ⇒ Proxy alg → Channel dom (RType alg, PKSeedType alg, PKRootType alg, MType ℓ) →  Channel dom (HᵐˢᵍOutType alg)
  _PRFStream    ∷ (KnownDomain dom, HiddenClockResetEnable dom) ⇒ Proxy alg → Channel dom (PKSeedType alg,  SKSeedType alg, ADRSType alg) → Channel dom (PRFOutType alg)
  _TˡStream     ∷ (KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ
                  , Div (688 + ((ℓ * 16) * 8)) 8 ~ (86 + (ℓ * 16))
                  , Mod ((86 + (ℓ * 16)) * 8) 8 ~ 0
                  ) ⇒ Proxy alg → Channel dom (PKSeedType alg, ADRSType alg, MˡType ℓ alg) → Channel dom (TˡOutType alg)
  _HStream      ∷ (KnownDomain dom, HiddenClockResetEnable dom) ⇒ Proxy alg → Channel dom (PKSeedType alg, ADRSType alg, M²Type alg) → Channel dom (HOutType alg)
  _FStream      ∷ (KnownDomain dom, HiddenClockResetEnable dom) ⇒ Proxy alg → Channel dom (PKSeedType alg, ADRSType alg, M¹Type alg) → Channel dom (FOutType alg)