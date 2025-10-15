{-|
Module      : Clash.Crypto.Hash.SHA
Copyright   : Copyright © 2024-2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Streaming based secure hash algorithms according to
[FIPS PUB 180-4: Secure Hash Standard (SHS)](http://dx.doi.org/10.6028/NIST.FIPS.180-4).
-}

{-# LANGUAGE AllowAmbiguousTypes #-}

module Clash.Crypto.Hash.MGF1 (
    mgf1Stream
)where
import Clash.Crypto.Hash.MGF1.Streaming