{-|
Module      : Clash.Crypto.Blockcipher.AES.Specification.Definitions
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic definitions covering the fundamentals of FIPS 197.
-}

{-# LANGUAGE Safe #-}

module Clash.Crypto.Cipher.AES.Specification.Definitions where

import Clash.Prelude.Safe

import Clash.Crypto.Cipher.AES.Specification.Types
import Clash.Crypto.Cipher.AES.Specification.Constants

------------------------------
-- Section 4: Preliminaries --
------------------------------

-- | Section 4.1: Addition in GF(2⁸).
(⊕) ∷ Byte → Byte → Byte
(⊕) = xor

-- | Section 4.2: Multiplication in GF(2⁸) (Equation 4.5).
xTimes ∷ Byte → Byte
xTimes x = if msb x == high then y ⊕ 0b00011011 else y
 where
  y = shiftL x 1

-- | Equation 4.4.
(•) ∷ Byte → Byte → Byte
x • y = foldl (⊕) 0x00
  $ zipWith (\b z →  if b then z else 0x00) (reverse $ unpack x)
  $ iterateI xTimes y

-- | Section 4.3: Multiplication of Words by a Fixed Matrix in GF(2⁸).
matrixMultiplication ∷
  (KnownNat m, KnownNat n) ⇒
  Vec m (Vec n Byte) →
  Vec n Byte →
  Vec m Byte
matrixMultiplication a b =
  foldl (⊕) 0x00 . zipWith (•) b <$> a

-- | Equation 4.9: Matrix multiplication based on two vectors as neded
-- by MixColumns() and InvMixColumns().
vectorMatrixMultiplication ∷
  KnownNat n ⇒
  Vec n Byte →
  Vec n Byte →
  Vec n Byte
vectorMatrixMultiplication =
  matrixMultiplication . transpose . iterateI (`rotateRightS` d1)

------------------------------------------------------------------
-- Section 5.1 and 5.3: Cipher and invCipher support functions  --
------------------------------------------------------------------

-- | Section 5.1.1: SubBytes() according to Equations 5.2, 5.3, and
-- 5.4, but implemented with Table 4.
subBytes ∷ AESState alg → AESState alg
subBytes = map $ map $ sBox xySBox

-- | Value selector for the given SBox matrix.
sBox ∷
  Vec (2 * BitSize Byte) (Vec (2 * BitSize Byte) Byte) →
  Byte →
  Byte
sBox m (unpack @(Vec 2 (BitVector (BitSize Byte `Div` 2))) → a) =
  (m !! at d0 a) !! at d1 a

-- | Section 5.1.2: ShiftRows() (Equation 5.5)
shiftRows ∷ AESState alg → AESState alg
shiftRows state = transpose $ zipWith rotateLeft (transpose state) indicesI

-- | Section 5.1.3: MixColumns() (Equation 5.7, 5.8)
mixColumns ∷ AESState alg → AESState alg
mixColumns = fmap $ vectorMatrixMultiplication aMixColumns

-- | Section 5.1.4: AddRoundKey() (Equation 5.9)
addRoundKey ∷ AESState alg → AESRoundKey alg → AESState alg
addRoundKey = zipWith $ zipWith (⊕)

-- | Section 5.3.1: InvShiftRows() (Equation 5.12)
invShiftRows ∷ AESState alg → AESState alg
invShiftRows state = transpose $ zipWith rotateRight (transpose state) indicesI

-- | Section 5.3.2: InvSubBytes() (implemented with Table 6)
invSubBytes ∷ AESState alg → AESState alg
invSubBytes = map $ map $ sBox xyInvSBox

-- | Section 5.3.3: the inverse of MixColumns() (Equation 5.14, 5.15)
invMixColumns ∷ AESState alg → AESState alg
invMixColumns = fmap $ vectorMatrixMultiplication aInvMixColumns

-- | Section 5.3.4: InvAddRoundKey() (Equation 5.9)
invAddRoundKey ∷ AESState alg → AESRoundKey alg → AESState alg
invAddRoundKey = addRoundKey

---------------------------------------------------------
-- Section 5.2 and 5.3: keyexpansion support functions --
---------------------------------------------------------

-- | Equation 5.10
rotWord ∷ AESWord → AESWord
rotWord word = rotateLeftS word d1

-- | Equation 5.11
subWord ∷ AESWord → AESWord
subWord = map $ sBox xySBox

-- | Word variant of '⊕'
xorWord ∷ AESWord → AESWord → AESWord
xorWord = zipWith (⊕)

-- | Table 5
_Rcon ∷ RoundConstants
_Rcon = transpose $ iterateI xTimes
  <$> 0x01 :> 0x00 :> 0x00 :> 0x00 :> Nil
