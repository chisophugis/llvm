//===- PruneEH.h - Pass which deletes unused exception handlers -----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_IPO_PRUNEEH_H
#define LLVM_TRANSFORMS_IPO_PRUNEEH_H

#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

struct PruneEHPass : PassInfoMixin<PruneEHPass> {
  PreservedAnalyses run(CallGraphSCC &C, AnalysisManager &AM);
};

}

#endif // LLVM_TRANSFORMS_IPO_PRUNEEH_H
