{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
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
module  Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash where
import Clash.Prelude
import Clash.Signal.Channel
import Clash.Signal.DataStream
import Clash.Signal.Delayed.Extra
import Clash.Signal.Extra (apWhen)
import Clash.Prelude.Safe hiding (fold, unzip)


import GHC.Records (HasField(..))

import Unsafe.Coerce (unsafeCoerce)

import Data.Proxy (Proxy(..))
import Clash.Prelude
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Streaming.Types
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Crypto.Hash.SHA.Specification as Spec
import Clash.Crypto.Hash.MGF1.Specification as MGF1Spec
import Clash.Crypto.Hash.SHA as SHA
import Clash.Crypto.MAC.HMAC as HMAC
import Clash.Crypto.Hash.MGF1.Streaming as MGF1
import GHC.TypeNats.Proof (Rewrite(..), using)
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple, DivTimes, ModTimes
  )
import Language.Haskell.Unicode (type (≤))

instance SLH_DSA_hashStream SLH_DSA_SHA2_128s where 
  -- TODO make a DataStream as input because algorithm 19
    _PRFᵐˢᵍStream ∷  ∀ (alg :: SLH_DSA) dom (ℓ ∷ Nat) . (KnownDomain dom, HiddenClockResetEnable dom, alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSAParameters alg, KnownNat ℓ
            , Mod (1152 + (ℓ * 8)) 8 ~ 0
            , Div (1152 + (ℓ * 8)) 8 ~ (144 + ℓ)
            , Div (640 + (ℓ * 8)) 8 ~ (80 + ℓ)
            , Mod (640 + (ℓ * 8)) 8 ~ 0) 
            ⇒ Proxy alg → Channel dom (SKPrfType alg, Opt_randType alg, MType ℓ) → Channel dom (PRFᵐˢᵍOutType alg)
    _PRFᵐˢᵍStream _ input  
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
            = fmap makeOutput (HMAC.hmac @SHA512 (serializeHMAC @ByteSize transfer))
                where
                transfer = fmap go input
                makeOutput output = truncˡ (unconcatBitVector# output)
                go ∷ ∀ ℓ . (KnownNat ℓ, Div (1152 + (ℓ * 8)) 8 ~ (144 + ℓ),  Div (640 + (ℓ * 8)) 8 ~  80 + ℓ) ⇒ (PKSeedType alg, Opt_randType alg, MType ℓ)  → BitVector (1152 + (ℓ * 8))
                go (skPrf, opt_rand, m) = toInt @(Div ((BlockSize SHA512)  +  BitSize (Opt_randType alg) + BitSize (MType ℓ)) ByteSize) @ByteSize @0 
                    (toByte @(Div (BlockSize SHA512) ByteSize) @ByteSize @1024 (resize (pack skPrf)) ‖  opt_rand ‖  m)
  -- TODO make a DataStream as input because algorithm 19, 20
    _HᵐˢᵍStream   ∷  ∀ (alg :: SLH_DSA) dom (ℓ ∷ Nat) . (KnownDomain dom, HiddenClockResetEnable dom, alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSAParameters alg,  KnownNat ℓ) 
                ⇒ Proxy alg → Channel dom (RType alg, PKSeedType alg, PKRootType alg , MType ℓ) →  Channel dom (HᵐˢᵍOutType alg)
    _HᵐˢᵍStream _ input
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        , Rewrite ← using @(ModTimes (N alg + N alg + N alg + ℓ) ByteSize) 
        = fmap makeOutput (MGF1.mgf1Stream @SHA256 @(M alg) transfer)
            where 
                shaResult ∷ Channel dom (Digest SHA256)
                shaResult 
                      | Rewrite ← using @(ModTimes (N alg + N alg + N alg + ℓ) ByteSize) 
                      = SHA.sha @SHA256 (serializeHash @ByteSize transfer⁰)
                    where
                        transfer⁰ ∷ (KnownNat ℓ) ⇒ Channel dom (BitVector ((N alg + N alg + N alg + ℓ) * ByteSize))
                        transfer⁰ 
                                | Rewrite ← using @(ModTimes (N alg + N alg + N alg + ℓ) ByteSize) 
                                = fmap go⁰ input
                        go⁰ ∷  (RType alg, PKSeedType alg, PKRootType alg, MType ℓ)  → BitVector ((N alg + N alg + N alg + ℓ) * ByteSize)
                        go⁰ (r⁰, pkSeed⁰, pkRoot⁰, m⁰) = concatBitVector# (r⁰ ‖ pkSeed⁰ ‖ pkRoot⁰ ‖ m⁰)
                transfer = liftA2 (++#) (fmap go input) (shaResult)
                makeOutput output = truncˡ (unconcatBitVector# output)
                go ∷ (KnownNat ℓ, KnownSLH_DSAParameters alg) ⇒ (RType alg, PKSeedType alg, PKRootType alg , MType ℓ)  → BitVector ((N alg + N alg) * ByteSize)
                go (r, pkSeed, pkRoot, m) = concatBitVector# (r ‖ pkSeed)


    _PRFStream    ∷ ∀ (alg :: SLH_DSA) dom .  (KnownDomain dom, HiddenClockResetEnable dom, alg ~ SLH_DSA_SHA2_128s, KnownSLH_DSAParameters alg) 
                  ⇒  Proxy alg → Channel dom (PKSeedType alg, SKSeedType alg, ADRSType alg) → Channel dom (PRFOutType alg)
    _PRFStream   _  input
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        = fmap makeOutput (SHA.sha @SHA256 (serializeHash @ByteSize transfer))
            where
            transfer = fmap go input
            makeOutput output = truncˡ (unconcatBitVector# output)
            go (pkSeed, skSeed, adrs) = toInt @(Div (BitSize (PKSeedType alg)  + 64 * ByteSize - BitSize (NBlockType alg) + BitSize (ADRSType alg) + BitSize (SKSeedType alg)) 8) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ skSeed)
    -- TODO make a Datastream as input, since the variable ℓ
    _TˡStream     ∷ ∀  (alg :: SLH_DSA) dom  (ℓ ∷ Nat).  (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg, KnownNat ℓ) 
                  ⇒ Proxy alg → Channel dom (PKSeedType alg, ADRSType alg, MˡType ℓ alg) → Channel dom (TˡOutType alg)
    _TˡStream   _ input
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        , Rewrite ← using @(ModTimes (64 + ADRSTypeVectorSize alg + ℓ * N alg) ByteSize) 
        = fmap makeOutput (SHA.sha @SHA256 (serializeHash @ByteSize transfer))
            where
            transfer = fmap go input
            makeOutput output = truncˡ (unconcatBitVector# output)
            go ∷ (KnownNat ℓ, KnownSLH_DSAParameters alg) ⇒ (PKSeedType alg, ADRSType alg, MˡType ℓ alg)  → BitVector ((64 + ADRSTypeVectorSize alg + ℓ * N alg) * ByteSize)
            go (pkSeed, adrs, ml) 
                | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                = concatBitVector# (pkSeed ‖ unconcatBitVector# @(64 - N alg) @ByteSize 0x0 ‖ getADRSVector adrs ‖ ml)

    _HStream      ∷ ∀ (alg :: SLH_DSA) dom .  (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg) 
                  ⇒ Proxy alg → Channel dom (PKSeedType alg, ADRSType alg, M²Type alg) → Channel dom (HOutType alg)
    _HStream _ input
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        , Rewrite ← using @(ModTimes (64 + ADRSTypeVectorSize alg + 2 * N alg) ByteSize)
        = fmap makeOutput (SHA.sha @SHA256 (serializeHash @ByteSize transfer))
            where
            transfer = fmap go input
            makeOutput output = truncˡ (unconcatBitVector# output)
            go ∷ (KnownSLH_DSAParameters alg) ⇒ (PKSeedType alg, ADRSType alg, M²Type alg)  → BitVector ((64 + ADRSTypeVectorSize alg + 2 * N alg) * ByteSize)
            go (pkSeed, adrs, m2) 
                | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                = concatBitVector# (pkSeed ‖ unconcatBitVector# @(64 - N alg) @ByteSize 0x0 ‖ getADRSVector adrs ‖ m2)


    _FStream      ∷ ∀ (alg :: SLH_DSA) dom .  (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg) 
                  ⇒ Proxy alg → Channel dom (PKSeedType alg, ADRSType alg, M¹Type alg) → Channel dom (FOutType alg)
    _FStream _ input
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        , Rewrite ← using @(ModTimes (64 + ADRSTypeVectorSize alg + N alg) ByteSize) 
        = fmap makeOutput (SHA.sha @SHA256 (serializeHash @ByteSize transfer))
            where
            transfer = fmap go input
            makeOutput output = truncˡ (unconcatBitVector# output)
            go ∷ (KnownSLH_DSAParameters alg) ⇒ (PKSeedType alg, ADRSType alg, M¹Type alg)  → BitVector ((64 + ADRSTypeVectorSize alg + N alg) * ByteSize)
            go (pkSeed, adrs, m1) 
                | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                = concatBitVector# (pkSeed ‖ unconcatBitVector# @(64 - N alg) @ByteSize 0x0 ‖ getADRSVector adrs ‖ m1)





-- TODO a function that convert a Channel (BitVector ℓ) to DataStream  dom (Index n) (BitVector n)
-- Inspiration can be taken of a mealy machine and hmac serialisation is taken.
serializeHash ∷ ∀ (n ∷ Nat) (dom ∷ Domain) a . (KnownDomain dom, HiddenClockResetEnable dom) ⇒ 
    ( BitPack a, KnownNat (BitSize a), KnownNat n
  , 1 ≤ n, 1 ≤ BitSize a, BitSize a `Mod` n ~ 0) ⇒ 
    Channel  dom a → 
    -- ^ streamed input that needs to be split up.
    DataStream dom () (Index n) (BitVector n)
serializeHash input
  | Rewrite ← using @(KeepsPositiveIfMultiple (BitSize a) n)
  , Rewrite ← using @(CancelMultiple (BitSize a) n)
    = leToPlusKN @1 @(BitSize a `Div` n)
  $ mealy (~~>)
      ( repeat neval ∷ Vec (BitSize a `Div` n) (BitVector n)
      , 0 ∷ Index ((BitSize a `Div` n) + 1)
      ) (liftA2 (,) (content input) (hasUpdates input))
 where
  (buf, n) ~~> (Just _, False) | n > 0 = -- 
    ((buf <<+ neval, satPred SatBound n), frame $ head buf)
   where
    frame | n == maxBound = Start ()
          | n > 1         = Middle
          | otherwise     = End 0

  _ ~~> (Just x, True)  = -- (Just x, True) equivalent to 
    ((bitCoerce x, maxBound), Idle)

  (buf, n) ~~> _ =
    ((buf, n), if n > 0 then NoData else Idle)

  -- a value that should never be evaluated
  neval = error "Clash.Crypto.MAC.HMAC.serializeEn: Mealy"
type ChunksPerInput a n = Div (BitSize a) n


serializeHMAC
  ∷ ∀ (n ∷ Nat) (dom ∷ Domain) a
   . ( KnownDomain dom
     , HiddenClockResetEnable dom
     , BitPack a
     , KnownNat (BitSize a)
     , KnownNat n
     , 1 ≤ n
     , 1 ≤ BitSize a
     , BitSize a `Mod` n ~ 0
     , BitSize a ~ Div (BitSize a) n * n
     )
  ⇒ Channel dom a
  → DataStream dom (Index (Div (BlockSize SHA512) 8 + 1)) () (BitVector n)
serializeHMAC input
  | Rewrite ← using @(KeepsPositiveIfMultiple (BitSize a) n)
  , Rewrite ← using @(CancelMultiple (BitSize a) n)
  = errorX "TODO: Not implemented yet"
--     leToPlusKN @1 @(ChunksPerInput a n)
--   $ mealy step
--       ( repeat poison ∷ Vec (ChunksPerInput a n) (BitVector n)
--       , 0 ∷ Index (ChunksPerInput a n + 1)
--       )
--       (liftA2 (,) (content input) (hasUpdates input))
--  where


--   step ∷ (Vec (ChunksPerInput a n) (BitVector n), Index (ChunksPerInput a n + 1))
--        → (Maybe a, Bool)
--        → ( (Vec (ChunksPerInput a n) (BitVector n), Index (ChunksPerInput a n + 1))
--          , Frame (Index n) () (BitVector n)
--          )

--   step (buf, i) (Just _, False) | i > 0 =
--     let chunk = buf !! 0
--         buf'  = buf <<+ poison
--         i'    = satPred SatBound i
--         idx   = fromIntegral (natToNum @(ChunksPerInput a n) - i)
--         frame
--           | i == natToNum @(ChunksPerInput a n) = Start idx chunk
--           | i == 1                              = End () chunk
--           | otherwise                           = Middle chunk
--     in ((buf' , i'), frame)

--   step _ (Just x, True) =
--     let chunks = bitCoerce x :: Vec (ChunksPerInput a n) (BitVector n)
--     in ((chunks, maxBound), Idle)

--   step st@(_, i) _ =
--     (st, if i > 0 then NoData else Idle)

--   poison = errorX "serializeHMAC: unreachable poison value"
