//===- CGSCCPassManager.cpp - Managing & running CGSCC passes -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/CGSCCPassManager.h"

using namespace llvm;

// Explicit instantiations for the core proxy templates.
namespace llvm {
template class PassManager<CallGraphSCC>;
template class AnalysisManager<CallGraphSCC>;
template class InnerAnalysisManagerProxy<CGSCCAnalysisManager, Module>;
template class OuterAnalysisManagerProxy<ModuleAnalysisManager, CallGraphSCC>;
template class InnerAnalysisManagerProxy<FunctionAnalysisManager, CallGraphSCC>;
template class OuterAnalysisManagerProxy<CGSCCAnalysisManager, Function>;
}
