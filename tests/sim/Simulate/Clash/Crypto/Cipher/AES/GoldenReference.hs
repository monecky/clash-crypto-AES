{-|
Module      : Simulate.Clash.Crypto.Cipher.AES.Specification
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.Cipher.AES'.
-}

module Simulate.Clash.Crypto.Cipher.AES.GoldenReference
  ( CryptoAES(..)
  ) where

import Clash.Prelude

import Crypto.Cipher.AES as Reference (AES128, AES192, AES256)
import Crypto.Cipher.Types
import Crypto.Error

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (length)

import qualified Clash.Crypto.Cipher.AES.Specification as Spec

class CryptoAES (alg ∷ Spec.AES) where
  encryptoECB :: ∀ x → x ~ alg ⇒ ByteString → ByteString → ByteString
  decryptoECB :: ∀ x → x ~ alg ⇒ ByteString → ByteString → ByteString

instance CryptoAES Spec.AES128      where
  encryptoECB _ key plainText = case cipherInit key of
    CryptoPassed (cipher1 :: AES128) -> ecbEncrypt cipher1 plainText
    CryptoFailed cipher1 -> error ("Cipher initialization failed" <> show cipher1)

  decryptoECB _ key cipherText = case cipherInit key of
    CryptoPassed (cipher1 ∷ AES128)-> ecbDecrypt cipher1 cipherText
    CryptoFailed cipher1 -> error ("Cipher initialization failed" <> show cipher1)


instance CryptoAES Spec.AES192    where
  encryptoECB _ key plainText = case cipherInit key of
    CryptoPassed (cipher1 :: AES192) -> ecbEncrypt cipher1 plainText
    CryptoFailed cipher1 -> error ("Cipher initialization failed" <> show (cipher1, BS.length key))

  decryptoECB _ key cipherText = case cipherInit key of
    CryptoFailed _ -> error "Cipher initialization failed"
    CryptoPassed (cipher1 ∷ AES192)-> ecbDecrypt cipher1 cipherText

instance CryptoAES Spec.AES256    where
  encryptoECB _ key plainText = case cipherInit key of
    CryptoPassed (cipher1 :: AES256) -> ecbEncrypt cipher1 plainText
    CryptoFailed cipher1 -> error ("Cipher initialization failed" <> show (cipher1, BS.length key))

  decryptoECB _ key cipherText = case cipherInit key of
    CryptoFailed _ -> error "Cipher initialization failed"
    CryptoPassed (cipher1 ∷ AES256)-> ecbDecrypt cipher1 cipherText