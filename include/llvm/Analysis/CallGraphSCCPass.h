//===- CallGraphSCCPass.h - Pass that operates BU on call graph -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the CallGraphSCCPass class, which is used for passes which
// are implemented as bottom-up traversals on the call graph.  Because there may
// be cycles in the call graph, passes of this type operate on the call-graph in
// SCC order: that is, they process function bottom-up, except for recursive
// functions, which they process all at once.
//
// These passes are inherently interprocedural, and are required to keep the
// call graph up-to-date if they do anything which could modify it.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_ANALYSIS_CALLGRAPHSCCPASS_H
#define LLVM_ANALYSIS_CALLGRAPHSCCPASS_H

#include "llvm/Analysis/CallGraph.h"
#include "llvm/Pass.h"
#include "llvm/PassSupport.h"

namespace llvm {

class CallGraphNode;
class CallGraph;
class PMStack;
class CallGraphSCC;

class CallGraphSCCPass : public Pass {
public:
  explicit CallGraphSCCPass(char &pid) : Pass(PT_CallGraphSCC, pid) {}

  /// createPrinterPass - Get a pass that prints the Module
  /// corresponding to a CallGraph.
  Pass *createPrinterPass(raw_ostream &O,
                          const std::string &Banner) const override;

  using llvm::Pass::doInitialization;
  using llvm::Pass::doFinalization;

  /// doInitialization - This method is called before the SCC's of the program
  /// has been processed, allowing the pass to do initialization as necessary.
  virtual bool doInitialization(CallGraph &CG) {
    return false;
  }

  /// runOnSCC - This method should be implemented by the subclass to perform
  /// whatever action is necessary for the specified SCC.  Note that
  /// non-recursive (or only self-recursive) functions will have an SCC size of
  /// 1, where recursive portions of the call graph will have SCC size > 1.
  ///
  /// SCC passes that add or delete functions to the SCC are required to update
  /// the SCC list, otherwise stale pointers may be dereferenced.
  ///
  virtual bool runOnSCC(CallGraphSCC &SCC) = 0;

  /// doFinalization - This method is called after the SCC's of the program has
  /// been processed, allowing the pass to do final cleanup as necessary.
  virtual bool doFinalization(CallGraph &CG) {
    return false;
  }

  /// Assign pass manager to manager this pass
  void assignPassManager(PMStack &PMS, PassManagerType PMT) override;

  ///  Return what kind of Pass Manager can manage this pass.
  PassManagerType getPotentialPassManagerType() const override {
    return PMT_CallGraphPassManager;
  }

  /// getAnalysisUsage - For this class, we declare that we require and preserve
  /// the call graph.  If the derived class implements this method, it should
  /// always explicitly call the implementation here.
  void getAnalysisUsage(AnalysisUsage &Info) const override;

protected:
  /// Optional passes call this function to check whether the pass should be
  /// skipped. This is the case when optimization bisect is over the limit.
  bool skipSCC(CallGraphSCC &SCC) const;
};

/// CallGraphSCC - This is a single SCC that a CallGraphSCCPass is run on.
class CallGraphSCC {
  CallGraph &CG; // The call graph for this SCC.
  void *Context; // The CGPassManager object that is vending this.
  std::vector<CallGraphNode*> Nodes;
public:

  // XXX: hack for CGSCC pass manager to pass stuff back up to the
  // ModuleToPostOrderCGSCCPassAdaptor's main visitation loop.
  // Also, this should really be called "revisit this SCC".
  bool DevirtualizedCall = false;

  CallGraphSCC(CallGraph &cg, void *context) : CG(cg), Context(context) {}

  // The vector is copied.
  CallGraphSCC(CallGraph &cg, void *context, std::vector<CallGraphNode *> nodes)
      : CG(cg), Context(context), Nodes(nodes) {}

  void initialize(CallGraphNode *const *I, CallGraphNode *const *E) {
    Nodes.assign(I, E);
  }

  bool isSingular() const { return Nodes.size() == 1; }
  unsigned size() const { return Nodes.size(); }

  /// ReplaceNode - This informs the SCC and the pass manager that the specified
  /// Old node has been deleted, and New is to be used in its place.
  void ReplaceNode(CallGraphNode *Old, CallGraphNode *New);

  typedef std::vector<CallGraphNode *>::const_iterator iterator;
  iterator begin() const { return Nodes.begin(); }
  iterator end() const { return Nodes.end(); }

  CallGraph &getCallGraph() { return CG; }
  StringRef getName() {
    if (!Nodes.empty())
      if (CallGraphNode *Node = Nodes.front())
        if (Function *F = Node->getFunction())
          return F->getName();
    return "Null SCC";
  }
  void print(raw_ostream &OS) {
    if (Nodes.empty() || !Nodes.front() || !Nodes.front()->getFunction()) {
      OS << "Null SCC";
      return;
    }
    for (CallGraphNode *Node : Nodes) {
      if (!Node || !Node->getFunction()) {
        OS << "null ";
        continue;
      }
      OS << Node->getFunction()->getName() << " ";
    }
  }
};

/// Scan the functions in the specified CFG and resync the
/// callgraph with the call sites found in it.  This is used after
/// FunctionPasses have potentially munged the callgraph, and can be used after
/// CallGraphSCC passes to verify that they correctly updated the callgraph.
///
/// This function returns true if it devirtualized an existing function call,
/// meaning it turned an indirect call into a direct call.  This happens when
/// a function pass like GVN optimizes away stuff feeding the indirect call.
/// This never happens in checking mode.
///
bool RefreshCallGraph(CallGraphSCC &CurSCC, CallGraph &CG, bool IsCheckingMode);

void initializeDummyCGSCCPassPass(PassRegistry &);

/// This pass is required by interprocedural register allocation. It forces
/// codegen to follow bottom up order on call graph.
class DummyCGSCCPass : public CallGraphSCCPass {
public:
  static char ID;
  DummyCGSCCPass() : CallGraphSCCPass(ID) {
    PassRegistry &Registry = *PassRegistry::getPassRegistry();
    initializeDummyCGSCCPassPass(Registry);
  };
  bool runOnSCC(CallGraphSCC &SCC) override { return false; }
  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }
};

} // End llvm namespace

#endif
