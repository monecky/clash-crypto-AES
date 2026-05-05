{-|
Module      : Clash.Crypto.Cipher.AES.Specification.Algorithm
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Algorithmic reference implementation of FIPS 197 using a purely
functional description.
-}

{-# LANGUAGE Safe #-}

module Clash.Crypto.Cipher.AES.Specification.Algorithm where

import Clash.Prelude.Safe

import Clash.Crypto.Cipher.AES.Specification.Types
import Clash.Crypto.Cipher.AES.Specification.Definitions

-- | Implementation of
class AESFunctions (alg ∷ AES) where
  -- Algorithm 1 of FIPS 197
  cipher ∷ ∀ x → x ~ alg ⇒ InType alg → WType alg → OutType alg
  -- Algorithm 2 of FIPS 197
  keyExpansion ∷ ∀ x → x ~ alg ⇒ KeyType alg → WType alg
  -- Algorithm 3 of FIPS 197
  invCipher ∷ ∀ x → x ~ alg ⇒ InType alg → WType alg → OutType alg
  -- Algorithm 4 of FIPS 197
  eqInvCipher ∷ ∀ x → x ~ alg ⇒ InType alg → WType alg → OutType alg
  -- Algorithm 5 of FIPS 197
  keyExpansionIEC ∷ ∀ x → x ~ alg ⇒ KeyType alg → WType alg

instance AESFunctions AES128 where

-- The keyexpansion function as written in Algorithm 2 and as illustrate in 6
--  keys
-- k1 = wl    ==> formula(wl⊹3) ⊕ wl    ==> wl⊹4
-- k2 = wl⊹1  ==> wl            ⊕ wl⊹1  ==> wl⊹5
-- k3 = wl⊹2  ==> wl⊹1          ⊕ wl⊹2  ==> wl⊹6
-- k4 = wl⊹3  ==> wl⊹2          ⊕ wl⊹3  ==> wl⊹7
--    keyExpansion ∷ Proxy AES128 → KeyType AES128 → WType AES128
  keyExpansion alg key = concat (scanl middelCalculation key (iterateI (+1) 0))
   where
    middelCalculation ∷ KeyType AES128 → Integer → KeyType AES128
    middelCalculation ws i = postscanl xorWord (partWord ws i)  ws
     where
      partWord w1s index = xorWord (subWord (rotWord (last w1s))) (_Rcon alg !! index)

  cipher _ input w1s = addRoundKey (shiftRows (subBytes(rounds input w1s))) (last (wInWords w1s))
   where
    rounds ∷ InType AES128 → WType AES128 → StateType AES128
    rounds input1 ws = foldl mutation (addRoundKey  input1 (head (wInWords ws))) (init (tail (wInWords ws)))
    wInWords ∷ WType AES128 → Vec (Nr AES128 + 1) (RoundWType AES128)
    wInWords = unconcat (SNat ∷ SNat (Nb AES128))
    -- Algorithm 1 codeline 5-8 as a function
    mutation ∷ StateType alg → RoundWType alg → StateType alg
    mutation state = addRoundKey (mixColumns ( shiftRows (subBytes state)))

  invCipher _ input ws = invAddRoundKey (invSubBytes (invShiftRows (rounds input ws))) (last (wInWords ws))
   where
    rounds ∷ InType AES128 → WType AES128 → StateType AES128
    rounds input1 w1s = foldl mutation (invAddRoundKey input1 (head (wInWords w1s))) (init (tail (wInWords ws)))
    wInWords ∷ WType AES128 → Vec (Nr AES128 + 1) (RoundWType AES128)
    wInWords words1 = reverse (unconcat (SNat ∷ SNat (Nb alg )) words1)
    -- Algorithm 2 codeline 5-8 as a function
    mutation ∷ StateType alg → RoundWType alg → StateType alg
    mutation state w = invMixColumns (invAddRoundKey ( invSubBytes (invShiftRows state)) w)

  eqInvCipher _ input1 ws = invAddRoundKey (invShiftRows (invSubBytes (rounds input1 ws))) (last (wInWords ws))
   where
    rounds ∷ InType AES128 → WType AES128 → StateType AES128
    rounds input w1s = foldl mutation (invAddRoundKey input (head (wInWords w1s))) (init (tail (wInWords ws)))
    wInWords ∷ WType AES128 → Vec (Nr AES128 + 1) (RoundWType AES128)
    wInWords words1 = reverse (unconcat (SNat ∷ SNat (Nb AES128)) words1)
    -- Algorithm 3 codeline 5-8 as a function
    mutation ∷ StateType alg → RoundWType alg → StateType alg
    mutation state = invAddRoundKey (invMixColumns (invShiftRows (invSubBytes state)))

  keyExpansionIEC alg key = concat (head (orignal key):>Nil ++ map invMixColumns (init (tail (orignal key))) ++ last (orignal key):>Nil)
   where
    orignal ∷ KeyType AES128 →  Vec (Nr AES128 + 1) (RoundWType AES128)
    orignal w1s = wInWords (keyExpansion alg w1s)
    wInWords ∷ WType AES128 → Vec (Nr AES128 + 1) (RoundWType AES128)
    wInWords = unconcat (SNat ∷ SNat (Nb AES128))

instance AESFunctions AES192 where
    -- Similiar fashion as for AES128
    -- The keyexpansion function as written in Algorithm 2 and as illustrate in 7
  keyExpansion alg key = takeI (keyExpansionInBlocks key)
   where
    keyExpansionInBlocks ∷ KeyType AES192 → Vec (Nk AES192 * Nr AES192) (WordType AES192)
    keyExpansionInBlocks key1 = concat (scanl middelCalculation key1 (iterateI (+1) 0))
     where
      middelCalculation ∷ KeyType AES192 → Integer → KeyType AES192
      middelCalculation ws i = postscanl xorWord (partWord ws i)  ws
       where
        partWord w1s index = xorWord (subWord (rotWord (last w1s))) (_Rcon alg !! index)

  cipher _ input w1s = addRoundKey (shiftRows (subBytes(rounds input w1s))) (last (wInWords w1s))
   where
    rounds ∷ InType AES192 → WType AES192 → StateType AES192
    rounds input1 ws = foldl mutation (addRoundKey  input1 (head (wInWords ws))) (init (tail (wInWords ws)))
    wInWords ∷ WType AES192 → Vec (Nr AES192 + 1) (RoundWType AES192)
    wInWords = unconcat (SNat ∷ SNat (Nb AES192))
    -- Algorithm 1 codeline 5-8 as a function
    mutation ∷ StateType alg → RoundWType alg → StateType alg
    mutation state = addRoundKey (mixColumns ( shiftRows (subBytes state)))

  invCipher _ input ws = invAddRoundKey (invSubBytes (invShiftRows (rounds input ws))) (last (wInWords ws))
   where
    rounds ∷ InType AES192 → WType AES192 → StateType AES192
    rounds input1 w1s = foldl mutation (invAddRoundKey input1 (head (wInWords w1s))) (init (tail (wInWords ws)))
    wInWords ∷ WType AES192 → Vec (Nr AES192 + 1) (RoundWType AES192)
    wInWords words1 = reverse (unconcat (SNat ∷ SNat (Nb AES192)) words1)
    -- Algorithm 3 codeline 5-8 as a function
    mutation ∷ StateType alg → RoundWType alg → StateType alg
    mutation state w = invMixColumns (invAddRoundKey ( invSubBytes (invShiftRows state)) w)

  eqInvCipher _ input1 ws = invAddRoundKey (invShiftRows (invSubBytes (rounds input1 ws))) (last (wInWords ws))
   where
    rounds ∷ InType AES192 → WType AES192 → StateType AES192
    rounds input w1s = foldl mutation (invAddRoundKey input (head (wInWords w1s))) (init (tail (wInWords ws)))
    wInWords ∷ WType AES192 → Vec (Nr AES192 + 1) (RoundWType AES192)
    wInWords words1 = reverse (unconcat (SNat ∷ SNat (Nb AES192)) words1)
    -- Algorithm 4 codeline 5-8 as a function
    mutation ∷ StateType alg → RoundWType alg → StateType alg
    mutation state = invAddRoundKey (invMixColumns ( invShiftRows (invSubBytes  state)))

  keyExpansionIEC alg key = concat (head (orignal key):>Nil ++ map invMixColumns (init (tail (orignal key))) ++ last (orignal key):>Nil)
   where
    orignal ∷  KeyType AES192 →  Vec (Nr AES192 + 1) (RoundWType AES192)
    orignal w1s = wInWords (keyExpansion alg w1s)
    wInWords ∷ WType AES192 → Vec (Nr AES192 + 1) (RoundWType AES192)
    wInWords = unconcat (SNat ∷ SNat (Nb AES192))

instance AESFunctions AES256 where
  -- The keyexpansion function as written in Algorithm 2 and as illustrate in 8
  keyExpansion alg key = takeI (keyExpansionInBlocks key)
   where
    keyExpansionInBlocks ∷ KeyType AES256 → Vec (Nk AES256 * (Nr AES256 + 3)) (WordType AES256)
    keyExpansionInBlocks key1 = concat (scanl middelCalculation key1 (iterateI (+1) 0))
     where
      middelCalculation ∷ KeyType AES256 → Integer → KeyType AES256
      middelCalculation w1s i = firstPart w1s i ++ secondPart w1s i
       where
        firstPart ws i1 = postscanl xorWord (partWord ws i1) (firstSplit ws)
        firstSplit = takeI @(Nk AES256 `Div` 2)
        secondPart ws i1 = postscanl xorWord (subWord (last (firstPart ws i1))) (secondSplit ws)
        secondSplit = dropI @(Nk AES256 `Div` 2)
        partWord ws index = xorWord (subWord (rotWord (last ws))) (_Rcon alg !! index)

  cipher _ input w1s = addRoundKey (shiftRows (subBytes(rounds input w1s))) (last (wInWords w1s))
   where
    rounds ∷ InType AES256 → WType AES256 → StateType AES256
    rounds input1 ws = foldl mutation (addRoundKey input1 (head (wInWords ws))) (init (tail (wInWords ws)))
    wInWords ∷ WType AES256 → Vec (Nr AES256 + 1) (RoundWType AES256)
    wInWords = unconcat (SNat ∷ SNat (Nb AES256))
    -- Algorithm 1 codeline 5-8 as a function
    mutation ∷ StateType alg → RoundWType alg → StateType alg
    mutation state = addRoundKey (mixColumns ( shiftRows (subBytes state)))

  invCipher _ input ws = invAddRoundKey (invSubBytes (invShiftRows (rounds input ws))) (last (wInWords ws))
   where
    rounds ∷ InType AES256 → WType AES256 → StateType AES256
    rounds input1 w1s = foldl mutation (invAddRoundKey input1 (head (wInWords w1s))) (init (tail (wInWords ws)))
    wInWords ∷ WType AES256 → Vec (Nr AES256 + 1) (RoundWType AES256)
    wInWords words1 = reverse (unconcat (SNat ∷ SNat (Nb AES256)) words1)
    -- Algorithm 3 codeline 5-8 as a function
    mutation ∷ StateType alg → RoundWType alg → StateType alg
    mutation state w = invMixColumns (invAddRoundKey ( invSubBytes (invShiftRows state)) w)

  eqInvCipher _ input1 ws = invAddRoundKey (invShiftRows (invSubBytes (rounds input1 ws))) (last (wInWords ws))
   where
    rounds ∷ InType AES256 → WType AES256 → StateType AES256
    rounds input w1s = foldl mutation (invAddRoundKey input (head (wInWords w1s))) (init (tail (wInWords ws)))
    wInWords ∷ WType AES256 → Vec (Nr AES256 + 1) (RoundWType AES256)
    wInWords words1 = reverse (unconcat (SNat ∷ SNat (Nb AES256)) words1)
    -- Algorithm 4 codeline 5-8 as a function
    mutation ∷ StateType alg → RoundWType alg → StateType alg
    mutation state = invAddRoundKey (invMixColumns (invShiftRows (invSubBytes state)))

  keyExpansionIEC alg key = concat (head (orignal key):>Nil ++ map invMixColumns (init (tail (orignal key))) ++ last (orignal key):>Nil)
   where
    orignal ∷ KeyType AES256 →  Vec (Nr AES256 + 1) (RoundWType AES256)
    orignal w1s = wInWords (keyExpansion alg w1s)
    wInWords ∷ WType AES256 → Vec (Nr AES256 + 1) (RoundWType AES256)
    wInWords = unconcat (SNat ∷ SNat (Nb AES256))
