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

template struct ParentIRUnitTrackingAnalysis<Module>;
template struct ParentIRUnitTrackingAnalysis<Function>;
}
