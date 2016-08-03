//===- PassManager.cpp - Infrastructure for managing & running IR passes --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/PassManager.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/LLVMContext.h"

using namespace llvm;

// Explicit template instantiations for core template typedefs.
namespace llvm {
template class PassManager<Module>;
template class PassManager<Function>;

struct ParentIRUnitTrackingAnalysisResultModel
    : public detail::AnalysisResultConcept {
  bool invalidate(TypeErasedIRUnitID IR, const PreservedAnalyses &PA) override {
    return !PA.preserved(ParentIRUnitTrackingAnalysis<Module>::ID());
  }
};

struct ParentIRUnitTrackingAnalysisModel : public detail::AnalysisPassConcept {
  std::unique_ptr<detail::AnalysisResultConcept> run(TypeErasedIRUnitID IR,
                                                     AnalysisManager &AM) {
    return make_unique<ParentIRUnitTrackingAnalysisResultModel>();
  }
  StringRef name() override { return "ParentIRUnitTrackingAnalysisModel"; }
};

detail::AnalysisPassConcept &
getParentIRUnitTrackingAnalysisPassConcept() {
  static ParentIRUnitTrackingAnalysisModel Instance;
  return Instance;
}

}
