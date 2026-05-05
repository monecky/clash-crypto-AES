{-|
Module      : Clash.Crypto.Cipher.AES.Specification
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Formalized AES specification according to
[FIPS PUB 197: Advanced Encryption Standard
(AES)](https://doi.org/10.6028/NIST.FIPS.197-upd1).

Note that this formalization adds an "@_@"-symbol to function names
that start with capital letter in the aforementioned document, to work
around the syntactic restrictions of Haskell. To keep the notation
consistent, the symbol is added to some function names starting with a
small letter as well.
-}

module Clash.Crypto.Cipher.AES.Specification
  ( -- * Functions from the FIPS standard
    AESFunctions(..)
  , aesFunctional
    -- * Additional Evidence
  , KnownAES(..), AESFacts(..)
    -- * Types
  , AES(..), InType, OutType, StateType, WType
  , WordType, KeyType, Nr, Nk, Nb, WordSize
    -- * Definitions
  , AESConstants, (⊕), RoundWType
  , subBytes, invSubBytes
  , mixColumns, invMixColumns
  , shiftRows, invShiftRows
  , addRoundKey, invAddRoundKey
    -- * Constants
  , mX, aMixColumns, aInvMixColumns, xySBox, xyInvSBox
  ) where

import Clash.Crypto.Cipher.AES.Specification.Properties
import Clash.Crypto.Cipher.AES.Specification.Algorithm
import Clash.Crypto.Cipher.AES.Specification.Constants
import Clash.Crypto.Cipher.AES.Specification.Definitions
import Clash.Crypto.Cipher.AES.Specification.Types

aesFunctional ∷ ∀ (alg ∷ AES) → KnownAES alg ⇒ InType alg → KeyType alg → OutType alg
aesFunctional alg input key
  | AESFacts ← knownAES alg
  = cipher alg input (keyExpansion alg key)
