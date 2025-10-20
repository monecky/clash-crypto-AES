{-|
Module      : Clash.Signal.Channel.Extra
Copyright   : Copyright © 2024-2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Some extra utility functions that extend the functionality of
'Clash.Signal.Delayed'.
-}

module Clash.Signal.Channel.Extra
  ( fstOf3C
  , sndOf3C
  , thdOf3C
  , zip3C
  ) where
import Clash.Signal.Channel
import Clash.Prelude
fstOf3C ∷ Channel dom (a,b,c) → Channel dom a
fstOf3C = fmap (\ (a, _, _) -> a)
sndOf3C ∷ Channel dom (a,b,c) → Channel dom b
sndOf3C = fmap (\ (_, b, _) -> b)
thdOf3C ∷ Channel dom (a,b,c) → Channel dom c
thdOf3C = fmap (\ (_, _, c) -> c)
zip3C ∷ Channel dom a → Channel dom b → Channel dom c → Channel dom (a,b,c)
zip3C = liftA3 (,,) 