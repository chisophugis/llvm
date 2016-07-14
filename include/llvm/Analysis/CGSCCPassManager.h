//===- CGSCCPassManager.h - Call graph pass management ----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This header provides classes for managing passes over SCCs of the call
/// graph. These passes form an important component of LLVM's interprocedural
/// optimizations. Because they operate on the SCCs of the call graph, and they
/// traverse the graph in post order, they can effectively do pair-wise
/// interprocedural optimizations for all call edges in the program. At each
/// call site edge, the callee has already been optimized as much as is
/// possible. This in turn allows very accurate analysis of it for IPO.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_ANALYSIS_CGSCCPASSMANAGER_H
#define LLVM_ANALYSIS_CGSCCPASSMANAGER_H

#include "llvm/ADT/SCCIterator.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/CallGraphSCCPass.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

extern template class PassManager<CallGraphSCC>;
/// \brief The CGSCC pass manager.
///
/// See the documentation for the PassManager template for details. It runs
/// a sequency of SCC passes over each SCC that the manager is run over. This
/// typedef serves as a convenient way to refer to this construct.
typedef PassManager<CallGraphSCC> CGSCCPassManager;

extern cl::opt<unsigned> MaxCGSCCIterations;

/// \brief The core module pass which does a post-order walk of the SCCs and
/// runs a CGSCC pass over each one.
///
/// Designed to allow composition of a CGSCCPass(Manager) and
/// a ModulePassManager.
template <typename CGSCCPassT>
class ModuleToPostOrderCGSCCPassAdaptor
    : public PassInfoMixin<ModuleToPostOrderCGSCCPassAdaptor<CGSCCPassT>> {
public:
  explicit ModuleToPostOrderCGSCCPassAdaptor(CGSCCPassT Pass, bool DebugLogging = false)
      : Pass(std::move(Pass)), DebugLogging(DebugLogging) {}
  // We have to explicitly define all the special member functions because MSVC
  // refuses to generate them.
  ModuleToPostOrderCGSCCPassAdaptor(
      const ModuleToPostOrderCGSCCPassAdaptor &Arg)
      : Pass(Arg.Pass), DebugLogging(Arg.DebugLogging) {}
  ModuleToPostOrderCGSCCPassAdaptor(ModuleToPostOrderCGSCCPassAdaptor &&Arg)
      : Pass(std::move(Arg.Pass)), DebugLogging(Arg.DebugLogging) {}
  friend void swap(ModuleToPostOrderCGSCCPassAdaptor &LHS,
                   ModuleToPostOrderCGSCCPassAdaptor &RHS) {
    using std::swap;
    swap(LHS.Pass, RHS.Pass);
    swap(LHS.DebugLogging, RHS.DebugLogging);
  }
  ModuleToPostOrderCGSCCPassAdaptor &
  operator=(ModuleToPostOrderCGSCCPassAdaptor RHS) {
    swap(*this, RHS);
    return *this;
  }

  /// \brief Runs the CGSCC pass across every SCC in the module.
  PreservedAnalyses run(Module &M, AnalysisManager &AM) {
    CallGraph &CG = AM.getResult<CallGraphAnalysis>(M);

    // XXX: no existing CGSCC passes use this.
    //bool Changed = doInitialization(CG);

    // Walk the callgraph in bottom-up SCC order.
    scc_iterator<CallGraph*> CGI = scc_begin(&CG);

    PreservedAnalyses PA = PreservedAnalyses::all();
    std::vector<std::unique_ptr<CallGraphSCC>> SCCs;
    while (!CGI.isAtEnd()) {
      const std::vector<CallGraphNode *> &NodeVec = *CGI;
      SCCs.emplace_back(llvm::make_unique<CallGraphSCC>(CG, &CGI, NodeVec));
      // Copy the current SCC and increment past it so that the pass can hack
      // on the SCC if it wants to without invalidating our iterator.
      ++CGI;
      CallGraphSCC &CurSCC = *SCCs.back();
      for (int i = 0; i < (int)MaxCGSCCIterations; i++) {

        PreservedAnalyses PassPA = Pass.run(CurSCC, AM);

        PassPA = AM.invalidate(CurSCC, std::move(PassPA));

        PA.intersect(std::move(PassPA));

        if (CurSCC.DevirtualizedCall) {
          DEBUG_WITH_TYPE("new-cgscc-pm", {
            dbgs() << "Devirtualized call " << i << "\n";
            CurSCC.print(dbgs());
            dbgs() << "\n";
          });

          // Reset this flag and keep looping.
          CurSCC.DevirtualizedCall = false;
          continue;
        }
        break;
      }
    }

    // CallGraphAnalysis holds AssertingVH and must be invalidated eagerly so
    // that other passes don't delete stuff from under it.
    AM.invalidate<CallGraphAnalysis>(M);

    // XXX: The only use of this for CGSCC passes is in the inliner which
    // just calls removeDeadFunctions. What to do about this?
    // Should we just do a run of globaldce after the CGSCC visitation is
    // done?
    //Changed |= doFinalization(CG);
    return PA;
  }

private:
  CGSCCPassT Pass;
  bool DebugLogging;
};

/// \brief A function to deduce a function pass type and wrap it in the
/// templated adaptor.
template <typename CGSCCPassT>
ModuleToPostOrderCGSCCPassAdaptor<CGSCCPassT>
createModuleToPostOrderCGSCCPassAdaptor(CGSCCPassT Pass, bool DebugLogging = false) {
  return ModuleToPostOrderCGSCCPassAdaptor<CGSCCPassT>(std::move(Pass), DebugLogging);
}

/// \brief Adaptor that maps from a SCC to its functions.
///
/// Designed to allow composition of a FunctionPass(Manager) and
/// a CGSCCPassManager.
template <typename FunctionPassT>
class CGSCCToFunctionPassAdaptor
    : public PassInfoMixin<CGSCCToFunctionPassAdaptor<FunctionPassT>> {
public:
  explicit CGSCCToFunctionPassAdaptor(FunctionPassT Pass, bool DebugLogging = false)
      : Pass(std::move(Pass)), DebugLogging(DebugLogging) {}
  // We have to explicitly define all the special member functions because MSVC
  // refuses to generate them.
  CGSCCToFunctionPassAdaptor(const CGSCCToFunctionPassAdaptor &Arg)
      : Pass(Arg.Pass), DebugLogging(Arg.DebugLogging) {}
  CGSCCToFunctionPassAdaptor(CGSCCToFunctionPassAdaptor &&Arg)
      : Pass(std::move(Arg.Pass)), DebugLogging(Arg.DebugLogging) {}
  friend void swap(CGSCCToFunctionPassAdaptor &LHS,
                   CGSCCToFunctionPassAdaptor &RHS) {
    using std::swap;
    swap(LHS.Pass, RHS.Pass);
    swap(LHS.DebugLogging, RHS.DebugLogging);
  }
  CGSCCToFunctionPassAdaptor &operator=(CGSCCToFunctionPassAdaptor RHS) {
    swap(*this, RHS);
    return *this;
  }

  /// \brief Runs the function pass across every function in the module.
  PreservedAnalyses run(CallGraphSCC &C, AnalysisManager &AM) {
    // XXX: enable after adding ostream operator for CallGraphSCC.
    //if (DebugLogging)
    //  dbgs() << "Running function passes across an SCC: " << C << "\n";

    PreservedAnalyses PA = PreservedAnalyses::all();
    for (CallGraphNode *N : C) {
      Function *F = N->getFunction();
      // XXX: CallGraphSCC may have a null function (for the special "calls
      // external" and "called by external") nodes.
      // Also, there may be declarations.
      if (!F || F->isDeclaration())
        continue;
      PreservedAnalyses PassPA = Pass.run(*F, AM);

      // We know that the function pass couldn't have invalidated any other
      // function's analyses (that's the contract of a function pass), so
      // directly handle the function analysis manager's invalidation here.
      // Also, update the preserved analyses to reflect that once invalidated
      // these can again be preserved.
      PassPA = AM.invalidate(*F, std::move(PassPA));

      // Then intersect the preserved set so that invalidation of module
      // analyses will eventually occur when the module pass completes.
      PA.intersect(std::move(PassPA));
    }

    C.DevirtualizedCall = RefreshCallGraph(C, C.getCallGraph(), false);
    PA.preserve<CallGraphAnalysis>();

    // FIXME: We need to update the call graph here to account for any deleted
    // edges!
    return PA;
  }

private:
  FunctionPassT Pass;
  bool DebugLogging;
};

static inline IRUnitKind getIRUnitKindID(CallGraphSCC *) { return IRK_CGSCC; }

/// \brief A function to deduce a function pass type and wrap it in the
/// templated adaptor.
template <typename FunctionPassT>
CGSCCToFunctionPassAdaptor<FunctionPassT>
createCGSCCToFunctionPassAdaptor(FunctionPassT Pass, bool DebugLogging = false) {
  return CGSCCToFunctionPassAdaptor<FunctionPassT>(std::move(Pass),
                                                   DebugLogging);
}
}

#endif
