//===-- ArgumentPromotion.h - Promote by-reference arguments --------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_IPO_ARGUMENTPROMOTION_H
#define LLVM_TRANSFORMS_IPO_ARGUMENTPROMOTION_H

#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

struct ArgumentPromotionPass : PassInfoMixin<ArgumentPromotionPass> {
  /// The maximum number of elements to expand, or 0 for unlimited.
  unsigned MaxElements = 3;
  PreservedAnalyses run(CallGraphSCC &C, AnalysisManager &AM);
};

}

#endif // LLVM_TRANSFORMS_IPO_ARGUMENTPROMOTION_H
