{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.RandomAddress
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Methodes regards random address, to use valid address to test with, to match the python version.
-}

{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.RandomAddress
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.RandomAddress'
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# LANGUAGE MagicHash #-}

module Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.RandomAddress (genAdrs, genAdrsType) where

import Clash.Prelude
import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog
import Clash.Crypto.PQC.SLH_DSA.General.General

import Control.Monad.IO.Class

import System.IO (appendFile)
import qualified Data.List as List
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions
import Clash.Hedgehog.Sized.BitVector (genDefinedBitVector)
import Clash.Crypto.PQC.SLH_DSA
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Signal.Channel
import Data.Monoid (First(..))
import Data.Maybe (fromMaybe)
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
import  Clash.Crypto.PQC.SLH_DSA.Streaming.Types
import Clash.Signal.DataStream
import Clash.Signal.Channel
import Clash.Signal.Channel.Extra 
import Language.Haskell.Unicode (type (≤))
import GHC.TypeNats.Proof (Rewrite(..), using)

import GHC.TypeLits.Extra
import Data.Proxy
import Data.Constraint
import Unsafe.Coerce
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple, DivTimes, ModTimes
  )
-- Testing HMAC
import Clash.Crypto.Hash.SHA.Specification
import Clash.Crypto.Hash.SHA as SHA
import Clash.Crypto.MAC.HMAC as HMAC
import qualified Data.ByteString.Char8 as BC
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import System.Process (readProcess)
import GHC.Utils.Misc (fstOf3, sndOf3,thdOf3)

-----------------------------------------
-- Generate a valid random address
--
-----------------------------------------
genAdrs ∷ ∀ (alg ∷ SLH_DSA) . KnownSLH_DSAParameters alg ⇒ BitVector (BitSize (ADRSType alg)) → BitVector (BitSize (ADRSType alg))
genAdrs genadrs
    | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
    = getADRSBitVector genadrs²
      where
        genadrs⁰ ∷ ADRSType alg
        genadrs⁰ 
          | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
          = unpack genadrs
        -- Get the correct type
        gentype ∷ ADRSTypeType
        gentype = getTypeAsType genadrs⁰
        -- Clear all unnessary fields and set type.
        genadrs¹ ∷ ADRSType alg
        genadrs¹ 
          | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
          = setTypeAndClear genadrs⁰ gentype
        -- Set back nessary fields and set type.
        genadrs² ∷ ADRSType alg 
        genadrs²
              | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
              = genadrs³ genadrs¹ genadrs⁰ gentype
          where
            genadrs³ ∷ ADRSType alg → ADRSType alg → ADRSTypeType → ADRSType alg 
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ }  WOTS_HASH       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
             }  WOTS_PK       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                  }

            genadrs³ adrs¹ ADRSType{                  
              chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } TREE       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {          
                      chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } FORS_TREE       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
             }  FORS_ROOTS       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ }  WOTS_PRF       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } FORS_PRF       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } _       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
genAdrsType ∷ ∀ (alg ∷ SLH_DSA) . KnownSLH_DSAParameters alg ⇒ BitVector (BitSize (ADRSType alg)) → ADRSTypeType → BitVector (BitSize (ADRSType alg))
genAdrsType genadrs gentype
    | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
    = getADRSBitVector genadrs²
      where
        genadrs⁰ ∷ ADRSType alg
        genadrs⁰ 
          | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
          = unpack genadrs
        -- Clear all unnessary fields and set type.
        genadrs¹ ∷ ADRSType alg
        genadrs¹ 
          | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
          = setTypeAndClear genadrs⁰ gentype
        -- Set back nessary fields and set type.
        genadrs² ∷ ADRSType alg 
        genadrs²
              | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
              = genadrs³ genadrs¹ genadrs⁰ gentype
          where
            genadrs³ ∷ ADRSType alg → ADRSType alg → ADRSTypeType → ADRSType alg 
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ }  WOTS_HASH       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
             }  WOTS_PK       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                  }

            genadrs³ adrs¹ ADRSType{                  
              chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } TREE       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {          
                      chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } FORS_TREE       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
             }  FORS_ROOTS       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ }  WOTS_PRF       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } FORS_PRF       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } _       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
------
-- Address methode for testing purposes
--
-----
getTypeAsBv ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → BitVector 4
getTypeAsBv ADRSType{typeAddress = typeAddress} 
       | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg  
       =  v2bv (dropI (bv2v (pack typeAddress)))
getTypeAsType ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → ADRSTypeType
getTypeAsType adrs 
       | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg  
       =  match (getTypeAsBv adrs)
        where
          match ∷ BitVector 4 → ADRSTypeType
          match $(bitPattern "0000") = WOTS_HASH
          match $(bitPattern "0001") = WOTS_PK
          match $(bitPattern "0010") = TREE
          match $(bitPattern "0011") = FORS_TREE
          match $(bitPattern "0100") = FORS_ROOTS
          match $(bitPattern "0101") = WOTS_PRF
          match $(bitPattern "0110") = FORS_PRF
          match $(bitPattern "....") = WOTS_HASH
