{-|
Module      : Clash.Crypto.Hash.SHA.Specification.Definitions
Copyright   : Copyright © 2024 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic definitions covering the fundamentals of of MGF1 from Appendix B.2.1 of RFC 8017 
-}

{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}

module Clash.Crypto.Hash.MGF1.Specification.Definitions where
