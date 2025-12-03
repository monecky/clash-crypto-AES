{-|
Module      : Clash.Signal.Channel.Extra
Copyright   : Copyright © 2024-2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Some extra utility functions that extend the functionality of
'Clash.Signal.Channel'.
Tuple functions of the channel class
-}

module Clash.Signal.Channel.Extra
  ( fstC
  , sndC
  , fstOf3C
  , sndOf3C
  , thdOf3C
  , zip3C
  , fstOf4C
  , sndOf4C
  , thdOf4C
  , frtOf4C
  , zip4C  
  , fstOf5C
  , sndOf5C
  , thdOf5C
  , frtOf5C
  , fthOf5C
  , zip5C  
  , fstOf6C
  , sndOf6C
  , thdOf6C
  , frtOf6C
  , fthOf6C
  , sthOf6C
  , zip6C 
  ) where
import Clash.Signal.Channel
import Clash.Prelude
fstC ∷ Channel dom (a,b) → Channel dom a
fstC = fmap fst
sndC ∷ Channel dom (a,b) → Channel dom b
sndC = fmap snd
 

fstOf3C ∷ Channel dom (a,b,c) → Channel dom a
fstOf3C = fmap (\ (a, _, _) -> a)
sndOf3C ∷ Channel dom (a,b,c) → Channel dom b
sndOf3C = fmap (\ (_, b, _) -> b)
thdOf3C ∷ Channel dom (a,b,c) → Channel dom c
thdOf3C = fmap (\ (_, _, c) -> c)
zip3C   ∷ Channel dom a → Channel dom b → Channel dom c → Channel dom (a,b,c)
zip3C   = liftA3 (,,) 


fstOf4C ∷ Channel dom (a,b,c,d) → Channel dom a
fstOf4C = fmap (\ (a, _, _, _) -> a)
sndOf4C ∷ Channel dom (a,b,c,d) → Channel dom b
sndOf4C = fmap (\ (_, b, _, _) -> b)
thdOf4C ∷ Channel dom (a,b,c, d) → Channel dom c
thdOf4C = fmap (\ (_, _, c, _) -> c)
frtOf4C ∷ Channel dom (a,b,c,d) → Channel dom d
frtOf4C = fmap (\ (_, _, _, d) -> d)
zip4C   ∷ Channel dom a → Channel dom b → Channel dom c → Channel dom d → Channel dom (a,b,c,d)
zip4C   a b c d = (,,,) <$> a <*> b <*> c <*> d


fstOf5C ∷ Channel dom (a,b,c,d,e) → Channel dom a
fstOf5C = fmap (\ (a, _, _, _,_) -> a)
sndOf5C ∷ Channel dom (a,b,c,d,e) → Channel dom b
sndOf5C = fmap (\ (_, b, _, _,_) -> b)
thdOf5C ∷ Channel dom (a,b,c, d, e) → Channel dom c
thdOf5C = fmap (\ (_, _, c, _, _) -> c)
frtOf5C ∷ Channel dom (a,b,c,d,e) → Channel dom d
frtOf5C = fmap (\ (_, _, _, d, _) -> d)
fthOf5C ∷ Channel dom (a,b,c,d,e) → Channel dom e
fthOf5C = fmap (\ (_, _, _, _, e) -> e)
zip5C   ∷ Channel dom a → Channel dom b → Channel dom c → Channel dom d → Channel dom e → Channel dom (a,b,c,d,e)
zip5C   a b c d e = (,,,,) <$> a <*> b <*> c <*> d <*> e

fstOf6C ∷ Channel dom (a,b,c,d,e,f) → Channel dom a
fstOf6C = fmap (\ (a, _, _, _, _, _) -> a)
sndOf6C ∷ Channel dom (a,b,c,d,e,f) → Channel dom b
sndOf6C = fmap (\ (_, b, _, _, _, _) -> b)
thdOf6C ∷ Channel dom (a,b,c, d, e,f) → Channel dom c
thdOf6C = fmap (\ (_, _, c, _, _, _) -> c)
frtOf6C ∷ Channel dom (a,b,c,d,e,f) → Channel dom d
frtOf6C = fmap (\ (_, _, _, d, _, _) -> d)
fthOf6C ∷ Channel dom (a,b,c,d,e,f) → Channel dom e
fthOf6C = fmap (\ (_, _, _, _, e,_) -> e)
sthOf6C ∷ Channel dom (a,b,c,d,e,f) → Channel dom f
sthOf6C = fmap (\ (_, _, _, _, _, f) -> f)
zip6C   ∷ Channel dom a → Channel dom b → Channel dom c → Channel dom d → Channel dom e → Channel dom f → Channel dom (a,b,c,d,e,f)
zip6C   a b c d e f = (,,,,,) <$> a <*> b <*> c <*> d <*> e <*> f


