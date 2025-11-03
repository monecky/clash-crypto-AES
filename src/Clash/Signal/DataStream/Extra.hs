{-|
Module      : Clash.Signal.DataStream.Extra
Copyright   : Copyright © 2024-2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Some extra utility functions that extend the functionality of
'Clash.DataStream.Channel'.
-}
-- | Returns the content of the DataStream wrapped into a 'Maybe`.
content ∷ ∀ a dom. Channel dom a → Signal dom (Maybe a)
content c = getContent c <&> \case
  None    → Nothing
  Fresh x → Just x
  Old x   → Just x
