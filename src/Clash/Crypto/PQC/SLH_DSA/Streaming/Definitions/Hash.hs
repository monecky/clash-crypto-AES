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
{-# OPTIONS_GHC -fno-max-relevant-binds #-}
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
import Clash.Crypto.PQC.SLH_DSA.Streaming.Types.Hash
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Crypto.Hash.SHA.Specification as Spec
import Clash.Crypto.Hash.MGF1.Specification as MGF1Spec
import Clash.Crypto.Hash.SHA as SHA
import Clash.Crypto.MAC.HMAC as HMAC
import Clash.Crypto.Hash.MGF1.Streaming as MGF1
import GHC.TypeNats.Proof (Rewrite(..), using)
import GHC.TypeLits
import GHC.TypeLits.Extra
import Data.Proxy
import Data.Constraint
import Unsafe.Coerce
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple, DivTimes, ModTimes
  )
import Language.Haskell.Unicode (type (≤))

instance (KnownSLH_DSAParameters alg) ⇒ SLH_DSA_hashStream SHATwo SecurityOne (alg ∷ SLH_DSA) where 
    _PRFᵐˢᵍStreaming ∷ ∀ sha security alg dom . 
                    (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg)
                  ⇒ Proxy alg 
                  →  Channel dom (SKPrfType alg, Opt_randType alg) 
                  →  DataStream dom () () (ByteType)
                  →  Channel dom (PRFᵐˢᵍOutType alg)
    _PRFᵐˢᵍStreaming alg inputC inputD  
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        , Rewrite ← using @(ModTimes (Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize + N alg) ByteSize)
        , Rewrite ← using @(ModTimes (N alg + N alg) ByteSize)
            = fmap makeOutput (HMAC.hmac @(SHAVersionPRFᵐˢᵍSLH_DSA alg) ( mapStart (\y → maxBound ∷ Index ((BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg) `Div` ByteSize) + 1)) ( mapEnd (const ()) (serializePrepend transfer inputD)))) 
            where
                transfer = fmap go inputC
                makeOutput ∷ Digest (SHAVersionPRFᵐˢᵍSLH_DSA alg) → PRFᵐˢᵍOutType alg
                makeOutput output 
                  | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                  , Rewrite ← using @(DivTimes (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)
                  , Rewrite ← using @(ModTimes (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)
                  , Rewrite ← using @(CancelMultiple (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)
                  = takeI @(N alg) @(Div (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize - N alg) (unconcatBitVector# @(Div (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize) @(ByteSize) output)       
                go ∷ (KnownSLH_DSAParameters alg) 
                  ⇒ (SKPrfType alg, Opt_randType alg) 
                  → BitVector ((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize + N alg) * ByteSize)
                go (skPrf, opt_rand)
                    | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                    = concatBitVector# (skPrf ‖ unconcatBitVector# @((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize) - N alg) @ByteSize 0x0 ‖ opt_rand)

                    
    _HᵐˢᵍStreaming   ∷ ∀ sha security alg dom s . (KnownDomain dom, HiddenClockResetEnable dom,KnownSLH_DSAParameters alg) 
                  ⇒ Proxy alg 
                  → Channel dom (RType alg, PKSeedType alg, PKRootType alg) 
                  → DataStream dom () () (ByteType) 
                  →  Channel dom (HᵐˢᵍOutType alg)
    _HᵐˢᵍStreaming _ inputC inputD
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        = fmap makeOutput (MGF1.mgf1Stream @SHA256 @(M alg) transfer)
            where 
                shaResult ∷ Channel dom (Digest SHA256)
                shaResult 
                      | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                      , Rewrite ← using @(DivTimes (((N alg + N alg) + N alg) * ByteSize)  ByteSize)
                      , Rewrite ← using @(ModTimes ((N alg + N alg) + N alg)  ByteSize)
                      = SHA.sha @SHA256 ( mapEnd (const (0 :: Index ByteSize)) (serializePrepend transfer⁰ inputD))
                    where
                        transfer⁰ ∷ Channel dom (BitVector ((N alg + N alg + N alg) * ByteSize))
                        transfer⁰ 
                                = fmap go⁰ inputC
                        go⁰ ∷  (RType alg, PKSeedType alg, PKRootType alg)  → BitVector ((N alg + N alg + N alg) * ByteSize)
                        go⁰ (r⁰, pkSeed⁰, pkRoot⁰) 
                          | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                          = concatBitVector# (r⁰ ‖ pkSeed⁰ ‖ pkRoot⁰)
                -- transfer ∷ Channel dom (BitVector ((MessageDigestSize SHA256) + (N alg + N alg) * ByteSize))
                transfer = liftA2 (++#) (fmap go inputC) (shaResult)
                makeOutput ∷ BitVector (M alg * ByteSize) → HᵐˢᵍOutType alg
                makeOutput output 
                   | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                   = unconcatBitVector# output
                go ∷ (KnownSLH_DSAParameters alg) ⇒ (RType alg, PKSeedType alg, PKRootType alg)  → BitVector ((N alg + N alg) * ByteSize)
                go (r, pkSeed, pkRoot) 
                  | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                  = concatBitVector# (r ‖ pkSeed)

                 

    _PRFStreaming    ∷ ∀ (alg :: SLH_DSA) dom .  (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg) 
                  ⇒   Channel dom (PKSeedType alg, SKSeedType alg, ADRSType alg) → Channel dom (PRFOutType alg)
    _PRFStreaming     input
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        , Rewrite ← using @(ModTimes (64 + ADRSTypeVectorSize alg + N alg) ByteSize) 
        = fmap makeOutput (SHA.sha @SHA256 (serializeHash @ByteSize transfer))
            where
            transfer = fmap go input
            makeOutput output = truncˡ (unconcatBitVector# output)
            go ∷ (KnownSLH_DSAParameters alg) ⇒ (PKSeedType alg, SKSeedType alg, ADRSType alg)  → BitVector ((64 + ADRSTypeVectorSize alg + N alg) * ByteSize)
            go (pkSeed, skSeed, adrs) 
                    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
                    = toInt @(64 + ADRSTypeVectorSize alg + N alg) @ByteSize @0 
                    (pkSeed ‖ toByte @(64 - N alg) @ByteSize @(ByteSize * (64 - N alg)) @0 0x0 ‖ getADRSVector adrs ‖ skSeed)
    _TˡStreaming     ∷ ∀ sha security alg ℓ dom . (KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ, KnownSLH_DSAParameters alg) 
                  ⇒ Channel dom (PKSeedType alg, ADRSType alg, MˡType ℓ alg) → Channel dom (TˡOutType alg)
    _TˡStreaming    input
        | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
        , Rewrite ← using @(ModTimes (64 + ADRSTypeVectorSize alg + ℓ * N alg) ByteSize) 
        = fmap makeOutput (SHA.sha @SHA256 (serializeHash @ByteSize transfer))
            where
            transfer ∷ Channel dom (BitVector ((64 + ADRSTypeVectorSize alg + ℓ * N alg) * ByteSize))
            transfer 
              | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
              = fmap go input
            makeOutput ∷ Digest SHA256 → TˡOutType alg
            makeOutput output 
              | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
              = truncˡ (unconcatBitVector# output)
            go ∷ (KnownNat ℓ, KnownSLH_DSAParameters alg) ⇒ (PKSeedType alg, ADRSType alg, MˡType ℓ alg)  → BitVector ((64 + ADRSTypeVectorSize alg + ℓ * N alg) * ByteSize)
            go (pkSeed, adrs, ml) 
                | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                = concatBitVector# (pkSeed ‖ unconcatBitVector# @(64 - N alg) @ByteSize 0x0 ‖ getADRSVector adrs ‖ ml)

    _HStreaming      ∷ (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg) 
                  ⇒  Channel dom (PKSeedType alg, ADRSType alg, M²Type alg) → Channel dom (HOutType alg)
    _HStreaming input
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


    _FStreaming      ∷ (KnownSLH_DSAParameters alg, KnownDomain dom, HiddenClockResetEnable dom) ⇒ Channel dom (PKSeedType alg, ADRSType alg, M¹Type alg) → Channel dom (FOutType alg)
    _FStreaming input
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


serializeHash ∷ ∀ (n ∷ Nat)  a (dom ∷ Domain) . (KnownDomain dom, HiddenClockResetEnable dom) ⇒ 
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
  neval = error "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash.serializeEn: Mealy"

-- This methode combines a channel with a dataStream by prepending
-- Since we don't know when the user start sending data and we don't want to miss any. 
-- We store it in a buffer.
-- Assumption the datastream doesn't start before the channel has send the fresh label.s
serializePrepend
  ∷ ∀ a (dom ∷ Domain) . (KnownDomain dom, HiddenClockResetEnable dom) ⇒ 
    ( BitPack a, KnownNat (BitSize a)
  , 1 ≤ ByteSize, 1 ≤ BitSize a, BitSize a `Mod` ByteSize ~ 0) ⇒ 
    Channel  dom a
    -- -- ^ streamed input that needs to be split up and preprend
    →  DataStream dom () () (ByteType)
  → DataStream dom () () (ByteType)
serializePrepend inputC inputD
  | Rewrite ← using @(KeepsPositiveIfMultiple (BitSize a) ByteSize)
  , Rewrite ← using @(CancelMultiple (BitSize a) ByteSize)
  , Rewrite ← using @(KeepsPositiveIfMultiple (BitSize a) ByteSize)
  , Rewrite ← using @(CancelMultiple (BitSize a) ByteSize)
  , Rewrite ← using @(DivTimes (BitSize a) ByteSize)
    = leToPlusKN @1 @(BitSize a `Div` ByteSize)
  $ mealy (~~>)
      ( repeat neval ∷ Vec (BitSize a `Div` ByteSize) (ByteType)
      , 0 ∷ Index ((BitSize a `Div` ByteSize) + 1)
      , False
      , repeat neval ∷ Vec (BitSize a `Div` ByteSize) (ByteType)
      , 0 ∷ Index ((BitSize a `Div` ByteSize) + 2)
      , False
      , False
      ) (liftA3 (,,) (content inputC) (hasUpdates inputC) (inputD))
 where
  (~~>) ∷ ∀ a1 . (BitPack a1, BitSize a1 `Mod` ByteSize ~ 0, 1 ≤ ByteSize, 1 ≤ BitSize a1) 
    ⇒  (Vec (BitSize a1 `Div` ByteSize) (BitVector ByteSize) -- channel buffer
        , Index ((BitSize a1 `Div` ByteSize) + 1) -- channel pointer
        , Bool -- Sending stored Channel
        , Vec (BitSize a1 `Div` ByteSize) (BitVector ByteSize) -- data stream buffer
        , Index ((BitSize a1 `Div` ByteSize) + 2) -- data stream pointer
        , Bool -- Sending stored DataStream
        , Bool -- End combi
        ) 
    → (Maybe a1, Bool, Frame () () (ByteType)) 
    → (
        (Vec (BitSize a1 `Div` ByteSize) (BitVector ByteSize) -- channel buffer
        , Index ((BitSize a1 `Div` ByteSize) + 1) -- channel pointer
        , Bool -- Sending stored Channel
        , Vec (BitSize a1 `Div` ByteSize) (BitVector ByteSize) -- data stream buffer
        , Index ((BitSize a1 `Div` ByteSize) + 2) -- data stream pointer
        , Bool -- Sending stored DataStream
        , Bool -- End combi
        )
      , Frame () () (ByteType))
  (~~>) state@(buffC, idxC, busyC, buffD, idxD, busyD, endD) input@(maybeC, updataC, prependFrame) 
    = (
      (
        goBuffC maybeC updataC prependFrame busyC busyD
      , goIdxC maybeC updataC prependFrame busyC busyD
      , goBusyC maybeC updataC prependFrame busyC
      , goBuffD maybeC updataC prependFrame
      , goIdxD maybeC updataC prependFrame busyC busyD
      , goBusyD maybeC updataC prependFrame busyD
      , goEndD maybeC updataC prependFrame busyC busyD
      )
      , goFrame maybeC updataC prependFrame busyC busyD)
        where
          vectorC ∷ a1 → Vec (BitSize a1 `Div` ByteSize) (BitVector ByteSize)
          vectorC x
              |Rewrite ← using @(DivTimes (BitSize a1) ByteSize)
              , Rewrite ← using @(CancelMultiple (BitSize a1) ByteSize)
              = bitCoerce x
          goIdxC ∷ Maybe a1 → Bool → Frame s () (ByteType) → Bool → Bool
                   → Index ((BitSize a1 `Div` ByteSize) + 1)
          goIdxC (Just x) True _ False False = maxBound
          goIdxC _ _ _ True _ = satPred SatBound idxC
          goIdxC _ _ _ _ _ = idxC
          goBuffC ∷ Maybe a1 → Bool → Frame () () (ByteType) → Bool → Bool
              → Vec (BitSize a1 `Div` ByteSize) (ByteType)
          goBuffC _ _ _ True _ = buffC <<+ neval --ignore new input
          goBuffC (Just x) True _ False _ = vectorC x
          goBuffC (Just x) False _ _ _ = buffC <<+ neval
          goBuffC Nothing _ _ _ _= (repeat 0x0 ∷ Vec (BitSize a1 `Div` ByteSize) (ByteType))
          goBuffC _ _ _ _ _ = buffC
          goIdxD ∷ Maybe a1 → Bool → Frame () () (ByteType) → Bool → Bool
                   → Index ((BitSize a1 `Div` ByteSize) + 2)
          goIdxD _ _ (Start _ _) _ _   = satSucc SatBound minBound
          goIdxD _ _ NoData _    False = idxD
          goIdxD _ _ Idle   _    False = idxD
          goIdxD _ _ NoData False True = satPred SatBound idxD
          goIdxD _ _ Idle   False True = satPred SatBound idxD
          goIdxD _ _ _      False True = idxD
          goIdxD _ _ (Middle _)  _  _  = satSucc SatBound idxD
          goIdxD _ _ (End _ _)   _  _  = satSucc SatBound idxD
          goIdxD _ _ _         _  _    = idxD
          goBuffD ∷ Maybe a1 → Bool → Frame () () (ByteType)
              → Vec (BitSize a1 `Div` ByteSize) (ByteType)
          goBuffD _ _ (Start _ y) = y +>> (repeat 0x0 ∷ Vec (BitSize a1 `Div` ByteSize) (ByteType))
          goBuffD _ _ (Middle y) = y +>> buffD
          goBuffD _ _ (End _ y) = y +>> buffD
          goBuffD _ _ _ = buffD
          goFrame ∷ Maybe a1 → Bool → Frame () () (ByteType) → Bool → Bool
              →  Frame () () (BitVector ByteSize)
          goFrame (Just x) True _ False False = NoData 
          goFrame _ _ _ True _ 
            | idxC == maxBound = Start () (buffC !! 0)
            | idxC /= 1 = Middle (buffC !! 0)
            | idxC == 1 = Middle (buffC !! 0) 
          goFrame _ _ _ False True 
            | endD, idxD > 1      = Middle (buffD !! (satPred SatBound idxD))
            | endD, idxD == 1      = End () (buffD !! (satPred SatBound idxD))
            | idxD >= 1            = Middle (buffD !! (satPred SatBound idxD))
            | otherwise = Idle
          goFrame _ _ _ _ _ = NoData

          goBusyC ∷ Maybe a1 → Bool → Frame () () (ByteType) → Bool
              → Bool
          goBusyC _ _ _ True 
            | idxC /= 1 = True
            | idxC == 1 = False
          goBusyC (Just x) True _ _= True
          goBusyC (Just x) False _ _= False
          goBusyC _ _ _ _= busyC
          
          goBusyD ∷ Maybe a1 → Bool → Frame () () (ByteType) → Bool
              → Bool
          goBusyD _ _ _ True 
            | idxD /= 1 = True
            | endD, idxD == 1 = False
            | otherwise = True
          goBusyD _ _ (Start _ _) _= True
          goBusyD _ _ _ _= busyD
          goEndD ∷  Maybe a1 → Bool → Frame () () (ByteType) → Bool → Bool
              → Bool
          goEndD _ _ (End _ _) _ _ = True
          goEndD _ _ (Start _ _) _ _ = False
          goEndD _ _ _ _ _ = endD
  neval = error "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash.HMAC.serializeEn: Mealy"
transferToC ∷ ∀ a n dom. (KnownDomain dom, HiddenClockResetEnable dom) ⇒ (BitPack a, KnownNat n, BitSize a `Mod` n ~ 0, 1 ≤ n)  
            ⇒ DataStream dom () () (BitVector n) → Channel dom a 
transferToC = channel . mealy (~~>) 
    -- Starting state
    (repeat 0x0 ∷ Vec (BitSize a `Div` n) (BitVector n)
    , 0 ∷ Index ((BitSize a `Div` n) + 1) 
    , Clear
    , True
    )
    where
      (~~>) ∷ ∀ a1 n1 . (BitPack a1, KnownNat n1, BitSize a1 `Mod` n1 ~ 0, 1 ≤ n1) 
              ⇒  ( -- Current state
                  Vec (BitSize a1 `Div` n1) (BitVector n1) -- PK and addrnd buffer
                  , Index ((BitSize a1 `Div` n1) + 1) -- Counter
                  , ProviderAction
                  , Bool -- prevent send end twice
                  ) 
              → (Frame () () (BitVector n1)) 
              → ( -- Next state
                  (Vec (BitSize a1 `Div` n1) (BitVector n1) -- PK and addrnd buffer
                  , Index ((BitSize a1 `Div` n1) + 1) -- Counter
                  ,ProviderAction
                  , Bool
                  )
                  -- Output
                , (a1, ProviderAction))
      (~~>) state@(vObject, counter, prevProviderAction, isEndSend) frame = 
        ((goBuff frame counter, goIdx frame counter, goProviderAction frame counter prevProviderAction, goisEndSend frame),
         ((unpacked (goBuff frame counter)), (goProviderAction frame counter prevProviderAction)))
        where 
          goBuff ∷ Frame s e (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Vec (BitSize a1 `Div` n1) (BitVector n1)
          goBuff (Start _ x) idx = vObject <<+ x
          goBuff (Middle x) idx
            | idx /= 1, idx /= 0 = vObject <<+ x
            | otherwise = vObject
          goBuff (End _ x) idx
            | idx == 2 = vObject <<+ x
            | otherwise = vObject 
          goBuff _ _ = vObject
          goIdx ∷ Frame s e (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Index ((BitSize a1 `Div` n1) + 1)
          goIdx (Start _ _) idx = maxBound
          goIdx (Middle _) idx       = satPred SatBound idx
          goIdx (End _ _) idx       = satPred SatBound idx
          goIdx _ idx       = idx
          goProviderAction ∷ Frame s e (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → ProviderAction → ProviderAction
          goProviderAction (Start _ x) _ _ = Keep
          goProviderAction (Middle x) idx prev
            | idx == 2 = Release
            | idx == 1 = Keep
            | idx == 0 = Keep
            | otherwise = prev
          goProviderAction (End _ x) _  _
            | isEndSend = Keep
            | otherwise = Release
          goProviderAction Idle _ _ = Keep
          goProviderAction NoData _ _ = Keep
          -- Goal to ensure to focus on 1 action at the same time
          goisEndSend ∷ Frame s e (BitVector n1) → Bool 
          goisEndSend (Middle x)
            | counter == 2 = True
            | otherwise = isEndSend
          goisEndSend (End _ x) = True
          goisEndSend (Start _ x) = False
          goisEndSend _ = isEndSend
      unpacked ∷ ∀ a n . (BitPack a, KnownNat n, 1 ≤ n, Mod (BitSize a) n ~ 0) ⇒ Vec (BitSize a `Div` n) (BitVector n) → a
      unpacked 
        | Rewrite ← using @(DivTimes (BitSize a) n)
        , Rewrite ← using @(CancelMultiple (BitSize a) n)
        = unpack . concatBitVector#
      neval = error "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.SLH.serializeEn: Mealy"
-- Ignores the Div BitSize a n frames and continures from there
transferToD ∷ ∀ a n dom. (KnownDomain dom, HiddenClockResetEnable dom) ⇒ (BitPack a, KnownNat n, BitSize a `Mod` n ~ 0, 1 ≤ n)  
            ⇒ DataStream dom () () (BitVector n) → DataStream dom () () (BitVector n) 
transferToD = mealy  ((~~>) @a @n)
    -- Starting state
    ( 0 ∷ Index ((BitSize a `Div` n) + 1) 
    , False
    )
    where
      (~~>) ∷ ∀ a1 n1 . (BitPack a1, KnownNat n1, BitSize a1 `Mod` n1 ~ 0, 1 ≤ n1) ⇒  ( -- Current state
                  Index ((BitSize a1 `Div` n1) + 1) -- Counter
                  , Bool
                  ) 
              → Frame () () (BitVector n1) 
              → ( -- Next state
                  (Index ((BitSize a1 `Div` n1) + 1) -- Counter
                  , Bool
                  )
                  -- Output
                , Frame () () (BitVector n1))
      (~~>) state@(counter, isStarted) frame = ((goIdx @a1 @n1 frame counter, (counter == 2) && (goIdx @a1 @n1 frame counter == 1)), (goFrame @a1 @n1 frame counter isStarted))
        where 
          goFrame ∷ ∀ a1 n1 . (BitPack a1, KnownNat n1, BitSize a1 `Mod` n1 ~ 0, 1 ≤ n1) 
              ⇒ Frame () () (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Bool → Frame () () (BitVector n1)
          goFrame (Start _ x) idx isStarted
            | natToNum @( BitSize a1 `Div` n1 ) == 0  = Start () 0xff
            | otherwise  = NoData
          goFrame (Middle x) idx isStarted
            | idx /= 1  = Middle x
            | idx == 1  = Start () x
            | otherwise = Idle
          goFrame (End _ x) idx isStarted = End () x
          goFrame NoData idx isStarted = NoData
          goFrame Idle idx isStarted = Idle
          goIdx ∷ ∀ a1 n1 . (BitPack a1, KnownNat n1, BitSize a1 `Mod` n1 ~ 0, 1 ≤ n1) 
              ⇒ Frame () () (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Index ((BitSize a1 `Div` n1) + 1)
          goIdx (Start _ _) idx      = maxBound
          goIdx (Middle _) idx       
            | idx /= 0 = satPred SatBound idx
            | otherwise = idx
          goIdx (End _ _) idx        = satPred SatBound idx
          goIdx _ idx                = idx
      neval = error "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.SLH.serializeEn: Mealy"

