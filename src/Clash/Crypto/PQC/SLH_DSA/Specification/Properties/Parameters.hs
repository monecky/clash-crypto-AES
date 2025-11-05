{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Some properties that can be proven to be valid from the FIPS 205
specification.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
-- {-# LANGUAGE AllowAmbiguousTypes #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters where
import Data.Proxy (Proxy(..))

import Clash.Prelude
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.PQC.SLH_DSA.General.General (CeilXDivY)
import Clash.Crypto.Hash.SHA.Specification
import Clash.Crypto.Hash.SHA as SHA
data SLH_DSAParametersFacts (alg ∷ SLH_DSA) where
    SLH_DSAParametersFacts ∷
        ( KnownNat (N alg)
        , KnownNat (H alg)
        , KnownNat (D alg)
        , KnownNat (H' alg)
        , KnownNat (A alg)
        , KnownNat (K alg)
        , KnownNat (Lgʷ alg)
        , KnownNat (M alg)
        , KnownNat (W alg)
        , KnownNat (Len¹ alg)
        , KnownNat (Len² alg)
        , KnownNat (Len alg)
        , KnownNat (LayerAddressSize alg)
        , KnownNat (TreeAddressSize alg)
        , KnownNat (TypeSize alg)
        -- , KnownNat ℓ
        -- , (ℓ * N alg) ~ (((2 * N alg) + 3) * N alg)

        -- Expected to be neded at some point.
        -- , PrivateKey alg
        -- , PublicKey alg
        -- , SK alg
        -- , PK alg
        -- , 1 ≤ BitSize 
        , N alg ≤ 64 -- This constain is needed for Tˡ, PRF, F and H, for SLH_DSA based on SHA
        , KnownNat(m1), N alg + m1 ~ 32 -- This constain is at least needed for Tˡ, PRF, F and H, for SLH_DSA based on SHA
        -- Constrain for algorithm 7
        , Len¹ alg ≤ Div (N alg * ByteSize) (Lgʷ alg) 
        , (Len¹ alg + Div (N alg * ByteSize) (Lgʷ alg) - Len¹ alg) * Lgʷ alg ~ N alg * ByteSize
                , Len¹ alg ≤ Div (N alg * ByteSize) (Lgʷ alg) 
        , (Len¹ alg + Div (N alg * ByteSize) (Lgʷ alg) - Len¹ alg) * Lgʷ alg ~ N alg * ByteSize
        -- Algorithm 12
        , 1 ≤ D alg
        , KnownNat (m2), m2 + 1 ~ D alg 
        , D alg - 1 ~ m2
        -- Properties according p.17, TODO it can be delete since it holds for many more cases.
        -- This works as verification methode that the calculation is done right on Type level.
        -- , Lgʷ alg ~ 4
        -- , W alg ~ 16
        -- , Len¹ alg ~ 2 * N alg
        -- , Len² alg ~ 3
        -- , Len alg ~ 2 * N alg + 3
        -- Specification functional implementation constraints
        , Div
                          ((((N alg + (64 - N alg))
                             + (((((LayerAddressSize alg + TreeAddressSize alg) + TypeSize alg)
                                  + 4)
                                 + 4)
                                + 4))
                            + N alg)
                           * 8)
                          8
                        ~ (((N alg + (64 - N alg))
                            + (((((LayerAddressSize alg + TreeAddressSize alg) + TypeSize alg)
                                 + 4)
                                + 4)
                               + 4))
                           + N alg)
        -- H stream
        , Mod ((((N alg + N alg) * 8) + 256) + 32) 8  ~ 0
        , 1 ≤ N alg, 1 ≤ ((N alg + N alg) + N alg)
        -- FORS
        , KnownNat (MD alg)
        -- , (Mod (MD alg) 8 ~ 0)
        -- H msg constain
            -- security level 1
        , (M alg) * ByteSize ≤ (CeilXDivY ((M alg) * ByteSize) (MessageDigestSize SHA256) ) * MessageDigestSize SHA256
        , (M alg) * ByteSize ≤ 0x100000000 * MessageDigestSize SHA256 - 1
            -- security level 2
        , (M alg) * ByteSize ≤ (CeilXDivY ((M alg) * ByteSize) (MessageDigestSize SHA512) ) * MessageDigestSize SHA512
        , (M alg) * ByteSize ≤ 0x100000000 * MessageDigestSize SHA512 - 1
        -- PRFᵐˢᵍ constrains
        , KnownSHA (SHAVersionPRFᵐˢᵍSLH_DSA alg)
        ,  ByteSize <= BlockSize (SHAVersionPRFᵐˢᵍ (SHAVersionSLH_DSA alg) (SecurityLevelSLH_DSA alg))
        , N alg ≤ Div (BlockSize (SHAVersionPRFᵐˢᵍ (SHAVersionSLH_DSA alg) (SecurityLevelSLH_DSA alg))) ByteSize
        , 1 ≤  ((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)+ N alg) * ByteSize
        , Mod (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize ~ 0
        , KnownNat (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg))
        -- ALgorithm 19
        , (K alg * A alg) + 1 <= (M alg * ByteSize) + 1
        ) ⇒
        Proxy alg →
        SLH_DSAParametersFacts alg

-- | We utilize the type checker to provide evidence for all of the
-- required properties, which are proven automatically for each
-- instance of the class.
class    KnownSLH_DSAParameters alg                    where knownSLH_DSAParameters ∷ SLH_DSAParametersFacts alg
instance KnownSLH_DSAParameters SLH_DSA_SHA2_128s      where knownSLH_DSAParameters = SLH_DSAParametersFacts Proxy
instance KnownSLH_DSAParameters SLH_DSA_SHA2_128f      where knownSLH_DSAParameters = SLH_DSAParametersFacts Proxy
instance KnownSLH_DSAParameters SLH_DSA_SHA2_192s      where knownSLH_DSAParameters = SLH_DSAParametersFacts Proxy
instance KnownSLH_DSAParameters SLH_DSA_SHA2_192f      where knownSLH_DSAParameters = SLH_DSAParametersFacts Proxy
instance KnownSLH_DSAParameters SLH_DSA_SHA2_256s      where knownSLH_DSAParameters = SLH_DSAParametersFacts Proxy
instance KnownSLH_DSAParameters SLH_DSA_SHA2_256f      where knownSLH_DSAParameters = SLH_DSAParametersFacts Proxy
  {-TODO:When the right implementation exist of SHA other algorithms can be added-}

