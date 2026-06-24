{-# LANGUAGE MagicHash #-}
{-# LANGUAGE PostfixOperators #-}
{-# LANGUAGE OverloadedStrings #-}
module PllG where

import Prelude

import Domain

import Clash.Annotations.Primitive (Primitive(..), HDL(..), hasBlackBox)
import Clash.Backend (Backend)
import Clash.Netlist.Types (TemplateFunction(..), BlackBoxContext)
import Clash.Signal.Internal
  ( Signal, Clock(..), Reset(..), clockGen, resetGen
  , unsafeToActiveLow, unsafeFromActiveLow
  )

import qualified Clash.Netlist.Id as Id
import qualified Clash.Netlist.Types as N
import qualified Clash.Primitives.DSL as DSL

import Control.Arrow (second)
import Control.Monad.State (State)
import Data.List.Infinite (Infinite(..), (...))
import Data.String.Interpolate (__i)
import Data.Text (Text)
import Data.Text.Prettyprint.Doc.Extra (Doc)
import Text.Show.Pretty (ppShow)

ccGateMatePLL ∷ Clock CCGM1A1E1 → (Clock Dom24, Reset Dom24)
ccGateMatePLL clkIn =
  let (clkOut, lock) = ccGateMatePLL# clkIn
   in (clkOut, unsafeFromActiveLow lock)

ccGateMatePLL# ∷ Clock CCGM1A1E1 → (Clock Dom24, Signal Dom24 Bool)
ccGateMatePLL# Clock {} = (clockGen, unsafeToActiveLow resetGen)
{-# OPAQUE ccGateMatePLL# #-}
{-# ANN ccGateMatePLL# hasBlackBox #-}
{-# ANN ccGateMatePLL#
  let
    primName = show 'ccGateMatePLL#
    tfName = show 'ccGateMatePLLTF
  in InlineYamlPrimitive [Verilog, SystemVerilog] [__i|
    BlackBox:
      name: #{primName}
      kind: Declaration
      format: Haskell
      templateFunction: #{tfName}
  |] #-}

ccGateMatePLLTF ∷ TemplateFunction
ccGateMatePLLTF = TemplateFunction [clkSrc] (const True) gateMatePLLTF#
 where
  clkSrc :< _ = (0...)

gateMatePLLTF# ∷ Backend backend ⇒ BlackBoxContext → State backend Doc
gateMatePLLTF# bbCtx | [ clkSrc ] ← fst <$> DSL.tInputs bbCtx
                     , [ results ] ← DSL.tResults bbCtx   = do

  let componentName = ("CC_PLL" ∷ Text)

  instanceName ← Id.make $ componentName <> "_inst"
  DSL.declaration (componentName <> "_block") $ do
    (clkDst, pll_lock) ← DSL.untuple results ["cc_pll_clk_out", "cc_pll_lock_out"] >>= \case
      [a, b] → pure (a, b)
      _ → error (ppShow bbCtx)

    lock_stdy_o ← DSL.declare "cc_pll_lock_stdy_o" N.Bit
    clkoutp_90_o ← DSL.declare "cc_pll_clkoutp_90_o" N.Bit
    clkoutp_180_o ← DSL.declare "cc_pll_clkoutp_180_o" N.Bit
    clkoutp_270_o ← DSL.declare "cc_pll_clkoutp_270_o" N.Bit
    clkoutp_usr_ref_o ← DSL.declare "cc_pll_clkoutp_usr_ref_o" N.Bit
    cc_low ← DSL.assign "cc_low" DSL.Low

    let
      generics ∷ [(Text, DSL.TExpr)]
      generics = second DSL.litTExpr <$>
        [ ("REF_CLK", "10.0")
        , ("OUT_CLK", "24.0")
        , ("PERF_MD", "ECONOMY")
        , ("LOW_JITTER", 1)
        , ("CI_FILTER_CONST", 2)
        , ("CP_FILTER_CONST", 4)
        ]

      inPorts ∷ [(Text, DSL.TExpr)]
      inPorts =
        [ ("CLK_REF", clkSrc)
        , ("USR_CLK_REF", cc_low)
        , ("CLK_FEEDBACK", cc_low)
        , ("USR_LOCKED_STDY_RST", cc_low)
        ]

      outPorts ∷ [(Text, DSL.TExpr)]
      outPorts =
        [ ("CLK0", clkDst)
        , ("CLK90", clkoutp_90_o)
        , ("CLK180", clkoutp_180_o)
        , ("CLK270", clkoutp_270_o)
        , ("CLK_REF_OUT", clkoutp_usr_ref_o)
        , ("USR_PLL_LOCKED_STDY", lock_stdy_o)
        , ("USR_PLL_LOCKED", pll_lock)
        ]

    DSL.instDecl
      N.Empty
      (Id.unsafeMake componentName)
      instanceName
      generics
      inPorts
      outPorts

gateMatePLLTF# bbCtx = error (ppShow bbCtx)
