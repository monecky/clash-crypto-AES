{-|
Module      : Simulate.Clash.Crypto.Cipher.AES.Streaming.Algorithm
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.Cipher.AES.Streaming.Algorithm'.
-}

module Simulate.Clash.Crypto.Cipher.AES.Streaming.Algorithm
  ( tastyTests
  ) where

import Clash.Prelude
import Clash.Signal.Channel
import Data.Maybe (fromMaybe)
import Data.Monoid (First(..))

import Clash.Hedgehog.Sized.BitVector (genDefinedBitVector)
import Clash.Hedgehog.Sized.Vector
import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog

import Clash.Crypto.Cipher.AES
import Clash.Crypto.Cipher.AES.Specification as Spec
import Clash.Crypto.Cipher.AES.Streaming.Algorithm as Stream
import qualified Data.List as List

tastyTests :: TestTree
tastyTests = testGroup "Algorithm"
  [ localOption (HedgehogTestLimit (Just 10))
  $ testGroup "Verification equality of hardware and functional"
      [ testProperty "Cipher version AES128" $ cipherProperty AES128 Stream.cipherStream Spec.cipher
      , testProperty "Cipher version AES192" $ cipherProperty AES192 Stream.cipherStream Spec.cipher
      , testProperty "Cipher version AES256" $ cipherProperty AES256 Stream.cipherStream Spec.cipher

      , testProperty "InvCipher version AES128" $ cipherProperty AES128 Stream.invCipherStream Spec.invCipher
      , testProperty "InvCipher version AES192" $ cipherProperty AES192 Stream.invCipherStream Spec.invCipher
      , testProperty "InvCipher version AES256" $ cipherProperty AES256 Stream.invCipherStream Spec.invCipher

      , testProperty "EqInvCipher version AES128" $ cipherProperty AES128 Stream.eqInvCipherStream Spec.eqInvCipher
      , testProperty "EqInvCipher version AES192" $ cipherProperty AES192 Stream.eqInvCipherStream Spec.eqInvCipher
      , testProperty "EqInvCipher version AES256" $ cipherProperty AES256 Stream.eqInvCipherStream Spec.eqInvCipher

      , testProperty "KeyExpansion version AES128" $ keyExpansionProperty AES128 Stream.keyExpansionStream Spec.keyExpansion
      , testProperty "KeyExpansion version AES192" $ keyExpansionProperty AES192 Stream.keyExpansionStream Spec.keyExpansion
      , testProperty "KeyExpansion version AES256" $ keyExpansionProperty AES256 Stream.keyExpansionStream Spec.keyExpansion

      , testProperty "KeyExpansionIEC version AES128" $ keyExpansionProperty AES128 Stream.keyExpansionIECStream Spec.keyExpansionIEC
      , testProperty "KeyExpansionIEC version AES192" $ keyExpansionProperty AES192 Stream.keyExpansionIECStream Spec.keyExpansionIEC
      , testProperty "KeyExpansionIEC version AES256"
      $ keyExpansionProperty AES256 Stream.keyExpansionIECStream Spec.keyExpansionIEC
      ]
  ]

type CipherComponent dom =
 HiddenClockResetEnable dom ⇒
 ∀ (alg ∷ AES) → KnownAES alg ⇒
 Channel dom (InType alg, WType alg) ->
 Channel dom (OutType alg)

type CipherRefComponent alg =
  AESFunctions alg ⇒
  ∀ x → x ~ alg ⇒
  InType alg ->
  WType alg ->
  OutType alg

cipherProperty ∷
  KnownDomain System ⇒
  ∀ (alg ∷ AES) → KnownAES alg ⇒
  CipherComponent System →
  CipherRefComponent alg →
  Property
cipherProperty alg cipherComp cipherComp1
  | AESFacts ← knownAES alg
  = property $ do
    inputAsInType ← forAll $ genVec @(Nb alg) (genVec @(WordSize alg) genDefinedBitVector)
    wAsInType     ← forAll $ genVec @((Nr alg + 1) * 4) (genVec @(WordSize alg) genDefinedBitVector)
    let f' = compute (inputAsInType, wAsInType)
    f' === cipherComp1 alg inputAsInType wAsInType
    where
    compute input
        = fromMaybe (error "The returned list was empty")
            $ getFirst
            $ foldMap First
            $ sampleN @System 10000000
            $ withClockResetEnable @System clockGen resetGen enableGen
            $ newsfeed
            $ cipherComp alg
            $ channel
            $ fmap (input, )
            $ fromList
            $ Keep : Keep : Release : List.repeat Keep

type KeyExpansionComponent dom alg =
 (HiddenClockResetEnable dom, AESKeyExpansion alg) ⇒
 ∀ x → (x ~ alg, KnownAES alg) ⇒
 Channel dom (KeyType alg) →
 Channel dom (WType alg)

type KeyExpansionRefComponent alg =
  AESFunctions alg ⇒
  ∀ x → x ~ alg ⇒
  KeyType alg →
  WType alg

keyExpansionProperty ∷
  KnownDomain System ⇒
  ∀ (alg ∷ AES) → (KnownAES alg, AESKeyExpansion alg, KnownNat (Nr alg)) ⇒
  KeyExpansionComponent System alg →
  KeyExpansionRefComponent alg →
  Property
keyExpansionProperty alg keyComp keyComp1
  | AESFacts ← knownAES alg
  = property $ do
    keyAsInType   ← forAll $ genVec @(Nk alg) (genVec @(WordSize alg) genDefinedBitVector)
    let f' = compute keyAsInType
    f' === keyComp1 alg keyAsInType
    where
    compute input
        = fromMaybe (error "The returned list was empty")
            $ getFirst
            $ foldMap First
            $ sampleN @System 10000000
            $ withClockResetEnable @System clockGen resetGen enableGen
            $ newsfeed
            $ keyComp alg
            $ channel
            $ fmap (input, )
            $ fromList
            $ Keep : Keep : Release : List.repeat Keep
