//===-- SymbolRewriter.h - Symbol Rewriting Pass ----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the prototypes and definitions related to the Symbol
// Rewriter pass.
//
// The Symbol Rewriter pass takes a set of rewrite descriptors which define
// transformations for symbol names.  These can be either single name to name
// trnsformation or more broad regular expression based transformations.
//
// All the functions are re-written at the IR level.  The Symbol Rewriter itself
// is exposed as a module level pass.  All symbols at the module level are
// iterated.  For any matching symbol, the requested transformation is applied,
// updating references to it as well (a la RAUW).  The resulting binary will
// only contain the rewritten symbols.
//
// By performing this operation in the compiler, we are able to catch symbols
// that would otherwise not be possible to catch (e.g. inlined symbols).
//
// This makes it possible to cleanly transform symbols without resorting to
// overly-complex macro tricks and the pre-processor.  An example of where this
// is useful is the sanitizers where we would like to intercept a well-defined
// set of functions across the module.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_UTILS_SYMBOLREWRITER_H
#define LLVM_TRANSFORMS_UTILS_SYMBOLREWRITER_H

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include <list>

namespace llvm {
class MemoryBuffer;

namespace yaml {
class KeyValueNode;
class MappingNode;
class ScalarNode;
class Stream;
}

namespace SymbolRewriter {
/// The basic entity representing a rewrite operation.  It serves as the base
/// class for any rewrite descriptor.  It has a certain set of specializations
/// which describe a particular rewrite.
///
/// The RewriteMapParser can be used to parse a mapping file that provides the
/// mapping for rewriting the symbols.  The descriptors individually describe
/// whether to rewrite a function, global variable, or global alias.  Each of
/// these can be selected either by explicitly providing a name for the ones to
/// be rewritten or providing a (posix compatible) regular expression that will
/// select the symbols to rewrite.  This descriptor list is passed to the
/// SymbolRewriter pass.
class RewriteDescriptor {
  RewriteDescriptor(const RewriteDescriptor &) = delete;

  const RewriteDescriptor &
  operator=(const RewriteDescriptor &) = delete;

public:
  enum class Type {
    Invalid,        /// invalid
    Function,       /// function - descriptor rewrites a function
    GlobalVariable, /// global variable - descriptor rewrites a global variable
    NamedAlias,     /// named alias - descriptor rewrites a global alias
  };

  virtual ~RewriteDescriptor() {}

  Type getType() const { return Kind; }

  virtual bool performOnModule(Module &M) = 0;

protected:
  explicit RewriteDescriptor(Type T) : Kind(T) {}

private:
  const Type Kind;
};

typedef std::list<std::unique_ptr<RewriteDescriptor>> RewriteDescriptorList;

class RewriteMapParser {
public:
  bool parse(const std::string &MapFile, RewriteDescriptorList *Descriptors);

private:
  bool parse(std::unique_ptr<MemoryBuffer> &MapFile, RewriteDescriptorList *DL);
  bool parseEntry(yaml::Stream &Stream, yaml::KeyValueNode &Entry,
                  RewriteDescriptorList *DL);
  bool parseRewriteFunctionDescriptor(yaml::Stream &Stream,
                                      yaml::ScalarNode *Key,
                                      yaml::MappingNode *Value,
                                      RewriteDescriptorList *DL);
  bool parseRewriteGlobalVariableDescriptor(yaml::Stream &Stream,
                                            yaml::ScalarNode *Key,
                                            yaml::MappingNode *Value,
                                            RewriteDescriptorList *DL);
  bool parseRewriteGlobalAliasDescriptor(yaml::Stream &YS, yaml::ScalarNode *K,
                                         yaml::MappingNode *V,
                                         RewriteDescriptorList *DL);
};
}

ModulePass *createRewriteSymbolsPass();
ModulePass *createRewriteSymbolsPass(SymbolRewriter::RewriteDescriptorList &);

class RewriteSymbolPass : public PassInfoMixin<RewriteSymbolPass> {
public:
  RewriteSymbolPass() { loadAndParseMapFiles(); }
  RewriteSymbolPass(SymbolRewriter::RewriteDescriptorList &DL) {
    Descriptors.splice(Descriptors.begin(), DL);
  }

  RewriteSymbolPass(RewriteSymbolPass &&Other)
      : Descriptors(std::move(Other.Descriptors)) {}

  PreservedAnalyses run(Module &M, AnalysisManager &AM);

  // Glue for old PM
  bool runImpl(Module &M);

private:
  void loadAndParseMapFiles();

  SymbolRewriter::RewriteDescriptorList Descriptors;  
};
}

#endif //LLVM_TRANSFORMS_UTILS_SYMBOLREWRITER_H
