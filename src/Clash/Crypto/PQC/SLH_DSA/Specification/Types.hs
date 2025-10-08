{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Types
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

module Clash.Crypto.PQC.SLH_DSA.Specification.Types where
import Clash.Sized.BitVector (BitVector)
import Clash.Sized.Vector (Vec)
import Clash.Class.BitPack (BitPack)
import Clash.XException (NFDataX)
import Data.Eq (Eq)
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
---------------------------------------------------------------------------
-- Parameters that define SLH_DSA defined in FIPS205
-- Parameters according Table 2
--
---------------------------------------------------------------------------
type SLH_DSA ∷ Type
data SLH_DSA =
    SLH_DSA_SHA2_128s
  | SLH_DSA_SHAKE_128s
  | SLH_DSA_SHA2_128f
  | SLH_DSA_SHAKE_128f
  | SLH_DSA_SHA2_192s
  | SLH_DSA_SHAKE_192s
  | SLH_DSA_SHA2_192f
  | SLH_DSA_SHAKE_192f
  | SLH_DSA_SHA2_256s
  | SLH_DSA_SHAKE_256s
  | SLH_DSA_SHA2_256f
  | SLH_DSA_SHAKE_256f
  deriving
    ( Generic
    , NFDataX
    , BitPack
    , Eq
    , Ord
    , Show
    , Enum
    , Bounded
    , Typeable
    )

type SLH_DSA_SHA ∷ SLH_DSA → SHA.SHA
type family SLH_DSA_SHA (alg ∷ SLH_DSA) where
  {-TODO:When the right implementation exist of SHA other algorithms can be added-}
  SLH_DSA_SHA SLH_DSA_SHA2_128s  = SHA.SHA256
  -- SLH_DSA_SHA SLH_DSA_SHAKE_128s = SHA.SHA256
  SLH_DSA_SHA SLH_DSA_SHA2_128f  = SHA.SHA256
  -- SLH_DSA_SHA SLH_DSA_SHAKE_128f = SHA.SHA256
  SLH_DSA_SHA SLH_DSA_SHA2_192s  = SHA.SHA512
  -- SLH_DSA_SHA SLH_DSA_SHAKE_192s = SHA.SHA512
  SLH_DSA_SHA SLH_DSA_SHA2_192f  = SHA.SHA512
  -- SLH_DSA_SHA SLH_DSA_SHAKE_192f = SHA.SHA512
  SLH_DSA_SHA SLH_DSA_SHA2_256s  = SHA.SHA512
  -- SLH_DSA_SHA SLH_DSA_SHAKE_256s = SHA.SHA512
  SLH_DSA_SHA SLH_DSA_SHA2_256f  = SHA.SHA512
  -- SLH_DSA_SHA SLH_DSA_SHAKE_256f = SHA.SHA512
  SLH_DSA_SHA _                  = SHA.SHA512
-- According to Table 2 of FIPS 205
type N ∷ SLH_DSA → Nat
type family N (alg ∷ SLH_DSA) where
  N SLH_DSA_SHA2_128s  = 16
  N SLH_DSA_SHAKE_128s = 16
  N SLH_DSA_SHA2_128f  = 16
  N SLH_DSA_SHAKE_128f = 16
  N SLH_DSA_SHA2_192s  = 24
  N SLH_DSA_SHAKE_192s = 24
  N SLH_DSA_SHA2_192f  = 24
  N SLH_DSA_SHAKE_192f = 24
  N SLH_DSA_SHA2_256s  = 32
  N SLH_DSA_SHAKE_256s = 32
  N SLH_DSA_SHA2_256f  = 32
  N SLH_DSA_SHAKE_256f = 32
  N _                  = 32
type H ∷ SLH_DSA → Nat
type family H (alg ∷ SLH_DSA) where
  H SLH_DSA_SHA2_128s  = 63
  H SLH_DSA_SHAKE_128s = 63
  H SLH_DSA_SHA2_128f  = 66
  H SLH_DSA_SHAKE_128f = 66
  H SLH_DSA_SHA2_192s  = 63
  H SLH_DSA_SHAKE_192s = 63
  H SLH_DSA_SHA2_192f  = 66
  H SLH_DSA_SHAKE_192f = 66
  H SLH_DSA_SHA2_256s  = 64
  H SLH_DSA_SHAKE_256s = 64
  H SLH_DSA_SHA2_256f  = 68
  H SLH_DSA_SHAKE_256f = 68
  H _                  = 68
type D ∷ SLH_DSA → Nat
type family D (alg ∷ SLH_DSA) where
  D SLH_DSA_SHA2_128s  = 7
  D SLH_DSA_SHAKE_128s = 7
  D SLH_DSA_SHA2_128f  = 22
  D SLH_DSA_SHAKE_128f = 22
  D SLH_DSA_SHA2_192s  = 7
  D SLH_DSA_SHAKE_192s = 7
  D SLH_DSA_SHA2_192f  = 22
  D SLH_DSA_SHAKE_192f = 22
  D SLH_DSA_SHA2_256s  = 8
  D SLH_DSA_SHAKE_256s = 8
  D SLH_DSA_SHA2_256f  = 17
  D SLH_DSA_SHAKE_256f = 17
  D _                  = 17

type H' ∷ SLH_DSA → Nat
type family H' (alg ∷ SLH_DSA) where
  H' SLH_DSA_SHA2_128s  = 9
  H' SLH_DSA_SHAKE_128s = 9
  H' SLH_DSA_SHA2_128f  = 3
  H' SLH_DSA_SHAKE_128f = 3
  H' SLH_DSA_SHA2_192s  = 9
  H' SLH_DSA_SHAKE_192s = 9
  H' SLH_DSA_SHA2_192f  = 3
  H' SLH_DSA_SHAKE_192f = 3
  H' SLH_DSA_SHA2_256s  = 8
  H' SLH_DSA_SHAKE_256s = 8
  H' SLH_DSA_SHA2_256f  = 4
  H' SLH_DSA_SHAKE_256f = 4
  H' _                  = 4
type A ∷ SLH_DSA → Nat
type family A (alg ∷ SLH_DSA) where
  A SLH_DSA_SHA2_128s  = 12
  A SLH_DSA_SHAKE_128s = 12
  A SLH_DSA_SHA2_128f  = 6
  A SLH_DSA_SHAKE_128f = 6
  A SLH_DSA_SHA2_192s  = 14
  A SLH_DSA_SHAKE_192s = 14
  A SLH_DSA_SHA2_192f  = 8
  A SLH_DSA_SHAKE_192f = 8
  A SLH_DSA_SHA2_256s  = 14
  A SLH_DSA_SHAKE_256s = 14
  A SLH_DSA_SHA2_256f  = 9
  A SLH_DSA_SHAKE_256f = 9
  A _                  = 9
type K ∷ SLH_DSA → Nat
type family K (alg ∷ SLH_DSA) where
  K SLH_DSA_SHA2_128s  = 14
  K SLH_DSA_SHAKE_128s = 14
  K SLH_DSA_SHA2_128f  = 33
  K SLH_DSA_SHAKE_128f = 33
  K SLH_DSA_SHA2_192s  = 17
  K SLH_DSA_SHAKE_192s = 17
  K SLH_DSA_SHA2_192f  = 33
  K SLH_DSA_SHAKE_192f = 33
  K SLH_DSA_SHA2_256s  = 22
  K SLH_DSA_SHAKE_256s = 22
  K SLH_DSA_SHA2_256f  = 35
  K SLH_DSA_SHAKE_256f = 35
  K _                  = 35
type Lgʷ ∷ SLH_DSA → Nat
type family Lgʷ (alg ∷ SLH_DSA) where
  Lgʷ SLH_DSA_SHA2_128s  = 4
  Lgʷ SLH_DSA_SHAKE_128s = 4
  Lgʷ SLH_DSA_SHA2_128f  = 4
  Lgʷ SLH_DSA_SHAKE_128f = 4
  Lgʷ SLH_DSA_SHA2_192s  = 4
  Lgʷ SLH_DSA_SHAKE_192s = 4
  Lgʷ SLH_DSA_SHA2_192f  = 4
  Lgʷ SLH_DSA_SHAKE_192f = 4
  Lgʷ SLH_DSA_SHA2_256s  = 4
  Lgʷ SLH_DSA_SHAKE_256s = 4
  Lgʷ SLH_DSA_SHA2_256f  = 4
  Lgʷ SLH_DSA_SHAKE_256f = 4
  Lgʷ _                  = 4
type M ∷ SLH_DSA → Nat
type family M (alg ∷ SLH_DSA) where
  M SLH_DSA_SHA2_128s  = 30
  M SLH_DSA_SHAKE_128s = 30
  M SLH_DSA_SHA2_128f  = 34
  M SLH_DSA_SHAKE_128f = 34
  M SLH_DSA_SHA2_192s  = 39
  M SLH_DSA_SHAKE_192s = 39
  M SLH_DSA_SHA2_192f  = 42
  M SLH_DSA_SHAKE_192f = 42
  M SLH_DSA_SHA2_256s  = 47
  M SLH_DSA_SHAKE_256s = 47
  M SLH_DSA_SHA2_256f  = 49
  M SLH_DSA_SHAKE_256f = 49
  M _                  = 49
type SecurityCategory ∷ SLH_DSA → Nat
type family SecurityCategory (alg ∷ SLH_DSA) where
  SecurityCategory SLH_DSA_SHA2_128s  = 1
  SecurityCategory SLH_DSA_SHAKE_128s = 1
  SecurityCategory SLH_DSA_SHA2_128f  = 1
  SecurityCategory SLH_DSA_SHAKE_128f = 1
  SecurityCategory SLH_DSA_SHA2_192s  = 3
  SecurityCategory SLH_DSA_SHAKE_192s = 3
  SecurityCategory SLH_DSA_SHA2_192f  = 3
  SecurityCategory SLH_DSA_SHAKE_192f = 3
  SecurityCategory SLH_DSA_SHA2_256s  = 5
  SecurityCategory SLH_DSA_SHAKE_256s = 5
  SecurityCategory SLH_DSA_SHA2_256f  = 5
  SecurityCategory SLH_DSA_SHAKE_256f = 5
  SecurityCategory _                  = 1
type Pk_bytes ∷ SLH_DSA → Nat
type family Pk_bytes (alg ∷ SLH_DSA) where
  Pk_bytes SLH_DSA_SHA2_128s  = 32
  Pk_bytes SLH_DSA_SHAKE_128s = 32
  Pk_bytes SLH_DSA_SHA2_128f  = 32
  Pk_bytes SLH_DSA_SHAKE_128f = 32
  Pk_bytes SLH_DSA_SHA2_192s  = 48
  Pk_bytes SLH_DSA_SHAKE_192s = 48
  Pk_bytes SLH_DSA_SHA2_192f  = 48
  Pk_bytes SLH_DSA_SHAKE_192f = 48
  Pk_bytes SLH_DSA_SHA2_256s  = 64
  Pk_bytes SLH_DSA_SHAKE_256s = 64
  Pk_bytes SLH_DSA_SHA2_256f  = 64
  Pk_bytes SLH_DSA_SHAKE_256f = 64
  Pk_bytes _                  = 64
type Sig_bytes ∷ SLH_DSA → Nat
type family Sig_bytes (alg ∷ SLH_DSA) where
  Sig_bytes SLH_DSA_SHA2_128s  = 7_856
  Sig_bytes SLH_DSA_SHAKE_128s = 7_856
  Sig_bytes SLH_DSA_SHA2_128f  = 17_088
  Sig_bytes SLH_DSA_SHAKE_128f = 17_088
  Sig_bytes SLH_DSA_SHA2_192s  = 16_224
  Sig_bytes SLH_DSA_SHAKE_192s = 16_224
  Sig_bytes SLH_DSA_SHA2_192f  = 35_664
  Sig_bytes SLH_DSA_SHAKE_192f = 35_664
  Sig_bytes SLH_DSA_SHA2_256s  = 29_792
  Sig_bytes SLH_DSA_SHAKE_256s = 29_792
  Sig_bytes SLH_DSA_SHA2_256f  = 49_856
  Sig_bytes SLH_DSA_SHAKE_256f = 49_856
  Sig_bytes _                  = 49_856
-- Page 17 of FIPS 205
type W ∷ SLH_DSA → Nat
type W (alg ∷ SLH_DSA) = 2 ^ Lgʷ alg
type Len¹ ∷ SLH_DSA → Nat
type Len¹ (alg ∷ SLH_DSA) = If (8 * N alg `Mod` Lgʷ alg <=? (0 ∷ Nat)) (8 * N alg `Div` Lgʷ alg + 0) (8 * N alg `Div` Lgʷ alg + 1)
-- Ceil Round If (a `Mod`b <=? (0 ∷ Nat)) (a `Div` b + 0) (a `Div` b + 1)
-- Floor Round (a `Div` b)
type Len² ∷ SLH_DSA → Nat
type Len² (alg ∷ SLH_DSA) = (Log2 ((Len¹ alg) * (W alg - 1)) `Div` Lgʷ alg) + 1  
type Len ∷ SLH_DSA → Nat
type Len (alg ∷ SLH_DSA) = Len¹ alg + Len² alg
-- Page 29 Figure 14
type T ∷ SLH_DSA → Nat
type T (alg ∷ SLH_DSA) = 2 ^ A alg 
---------------------------------------------------------------------------
-- Types of objects
-- 
--
---------------------------------------------------------------------------
-- | The "Message" type.
type Message (ℓ ∷ Nat) = BitVector ℓ
type BlockType  (alg ∷ SLH_DSA) = Vec (N alg) ByteType
type NibbleSize = 4
type NibbleType = BitVector NibbleSize
type ByteSize = NibbleSize * 2
type ByteType = BitVector ByteSize

---------------------------------------------------------------------------
-- Types of objects
-- According table 15, 16
--
---------------------------------------------------------------------------


type SKSeedType (alg ∷ SLH_DSA) = BlockType alg
type SKRootType (alg ∷ SLH_DSA) = BlockType alg
type PKSeedType (alg ∷ SLH_DSA) = BlockType alg
type PKRootType (alg ∷ SLH_DSA) = BlockType alg
data SK (alg ∷ SLH_DSA)= SK {
  seed ∷ SKSeedType alg,
  root ∷ SKRootType alg
} deriving     ( Generic
    , Show
    , Typeable
    )
{- TODO verify if it works undecidable instance-}
deriving instance (KnownNat (N alg)) ⇒ BitPack (SK alg)
deriving instance (KnownNat (N alg)) ⇒ NFDataX (SK alg)
deriving instance (KnownNat (N alg)) ⇒ Eq      (SK alg)
deriving instance (KnownNat (N alg)) ⇒ Ord     (SK alg)
-- deriving instance (KnownNat (N alg)) ⇒ Bounded (SK alg)
data PK (alg ∷ SLH_DSA)= PK {
  seed ∷ PKSeedType alg,
  root ∷ PKRootType alg
} deriving     ( Generic
    , Show
    , Typeable
    )
{- TODO verify if it works undecidable instance-}
deriving instance (KnownNat (N alg)) ⇒ BitPack (PK alg)
deriving instance (KnownNat (N alg)) ⇒ NFDataX (PK alg)
deriving instance (KnownNat (N alg)) ⇒ Eq      (PK alg)
deriving instance (KnownNat (N alg)) ⇒ Ord     (PK alg)
-- deriving instance (KnownNat (N alg)) ⇒ Bounded (PK alg)
-- According figure 15
data PrivateKey (alg ∷ SLH_DSA) = PrivateKey {
  private ∷ SK alg,
  public ∷ PK alg
} deriving     ( Generic
    , Show
    , Typeable
    )
deriving anyclass instance (KnownNat (N alg)) ⇒ BitPack (PrivateKey alg)
deriving anyclass instance (KnownNat (N alg)) ⇒ NFDataX (PrivateKey alg)
deriving anyclass instance (KnownNat (N alg)) ⇒ Eq      (PrivateKey alg)
deriving anyclass instance (KnownNat (N alg)) ⇒ Ord     (PrivateKey alg)
-- According figure 16
newtype PublicKey (alg ∷ SLH_DSA) = PublicKey {
  public ∷ PK alg
} deriving     ( Generic
    , Show
    , Typeable
    )
deriving newtype instance (KnownNat (N alg)) ⇒ BitPack (PublicKey alg)
deriving newtype instance (KnownNat (N alg)) ⇒ NFDataX (PublicKey alg)
deriving newtype instance (KnownNat (N alg)) ⇒ Eq      (PublicKey alg)
deriving newtype instance (KnownNat (N alg)) ⇒ Ord     (PublicKey alg)
---------------------------------------------------------------------------
-- SLH-DSA Signature Generation Types 9.2 in SLH_DSA
-- according Figure 17 in FIPS205
--
---------------------------------------------------------------------------
type RType (alg ∷ SLH_DSA) = BlockType alg
type SIGᶠᵒʳˢType (alg ∷ SLH_DSA) = Vec ((N alg) * (K alg) * (1 + A alg)) ByteType
type SIGᴴᵀType (alg ∷ SLH_DSA) = Vec ((N alg) * (H alg + (D alg) * (Len alg))) ByteType

---------------------------------------------------------------------------
-- ADRS that is define in SLH_DSA 
-- according Table 2/ Figure 18 in FIPS205
--
---------------------------------------------------------------------------
type LayerAddressType  = Vec 1 ByteType
type TreeAddressType   = Vec 8 ByteType
type TypeType          = Vec 1 ByteType
type DataType          = Vec 12 ByteType
data ADRSᶜType         = ADRSᶜType {
  layerAddress ∷ LayerAddressType,
  treeAddress  ∷ TreeAddressType,
  typeAddress  ∷ TypeType,
  dataAddress  ∷ DataType
} deriving     ( Generic
              , Show
              , Typeable
              , BitPack 
              , NFDataX 
              , Eq      
              , Ord     
              )

---------------------------------------------------------------------------
-- WOTS that is define in SLH_DSA 
-- according Figure 10 in FIPS205
--
---------------------------------------------------------------------------
type SIGʷᵒᵗˢPlusType (alg ∷ SLH_DSA) = Vec (Len alg) (Vec (N alg) ByteType) -- 0 .. len -1


---------------------------------------------------------------------------
-- XMSS that is define in SLH_DSA 
-- according Figure 11 in FIPS205
--
---------------------------------------------------------------------------
type AUTHType (alg ∷ SLH_DSA) = Vec (H' alg) (Vec (N alg) ByteType) -- 0 .. h'- 1
data XMSSType (alg ∷ SLH_DSA) = XMSSType {
  sig_ots ∷ SIGʷᵒᵗˢPlusType alg,
  auth ∷ AUTHType alg
} deriving     ( Generic
    , Show
    , Typeable
    )
deriving anyclass instance (KnownNat (N alg), KnownNat (H' alg), KnownNat (Len alg)) ⇒ BitPack (XMSSType alg)
deriving anyclass instance (KnownNat (N alg), KnownNat (H' alg), KnownNat (Len alg)) ⇒ NFDataX (XMSSType alg)
deriving anyclass instance (KnownNat (N alg), KnownNat (H' alg), KnownNat (Len alg)) ⇒ Eq      (XMSSType alg)
deriving anyclass instance (KnownNat (N alg), KnownNat (H' alg), KnownNat (Len alg)) ⇒ Ord     (XMSSType alg)
---------------------------------------------------------------------------
-- HT that is define in SLH_DSA 
-- according Figure 13 in FIPS205
--
---------------------------------------------------------------------------
type HTType (alg ∷ SLH_DSA) = Vec (D alg)  (XMSSType alg)-- 0 .. d- 1
---------------------------------------------------------------------------
-- FORS that is define in SLH_DSA 
-- according Figure 14 in FIPS205
--
---------------------------------------------------------------------------
type PrivateKeyValueTreeType (alg ∷ SLH_DSA) = BlockType alg
type AUTHTreeType (alg ∷ SLH_DSA) = Vec (A alg) (BlockType alg)
data ElemForsType (alg ∷ SLH_DSA) = ElemForsType {
  privateKeyValueElem ∷ PrivateKeyValueTreeType alg,
  authElem ∷ AUTHTreeType alg
} deriving     ( Generic
    , Show
    , Typeable
    )
deriving anyclass instance (KnownNat (N alg), KnownNat (A alg)) ⇒ BitPack (ElemForsType alg)
deriving anyclass instance (KnownNat (N alg), KnownNat (A alg)) ⇒ NFDataX (ElemForsType alg)
deriving anyclass instance (KnownNat (N alg), KnownNat (A alg)) ⇒ Eq      (ElemForsType alg)
deriving anyclass instance (KnownNat (N alg), KnownNat (A alg)) ⇒ Ord     (ElemForsType alg)

type FORSType (alg ∷ SLH_DSA) = Vec (K alg) (ElemForsType alg)-- 0 .. k- 1


---------------------------------------------------------------------------
-- Hashfunctions that define SLH_DSA defined in FIPS205
-- Hashfunctions according chapter 11
--
---------------------------------------------------------------------------
class SLH_DSA_hash (alg ∷ SLH_DSA) where
  _Hᵐˢᵍ ∷ Proxy alg → (SK alg)
  _PRF ∷ Proxy alg → BlockType alg
  _PRFᵐˢᵍ ∷ Proxy alg → BlockType alg
  _F ∷ Proxy alg → BlockType alg
  _H ∷ Proxy alg → BlockType alg
  _Tˡ ∷ Proxy alg → BlockType alg