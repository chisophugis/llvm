//===- PassManager.h - Pass management infrastructure -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// This header defines various interfaces for pass management in LLVM. There
/// is no "pass" interface in LLVM per se. Instead, an instance of any class
/// which supports a method to 'run' it over a unit of IR can be used as
/// a pass. A pass manager is generally a tool to collect a sequence of passes
/// which run over a particular IR construct, and run each of them in sequence
/// over each such construct in the containing IR construct. As there is no
/// containing IR construct for a Module, a manager for passes over modules
/// forms the base case which runs its managed passes in sequence over the
/// single module provided.
///
/// The core IR library provides managers for running passes over
/// modules and functions.
///
/// * FunctionPassManager can run over a Module, runs each pass over
///   a Function.
/// * ModulePassManager must be directly run, runs each pass over the Module.
///
/// Note that the implementations of the pass managers use concept-based
/// polymorphism as outlined in the "Value Semantics and Concept-based
/// Polymorphism" talk (or its abbreviated sibling "Inheritance Is The Base
/// Class of Evil") by Sean Parent:
/// * http://github.com/sean-parent/sean-parent.github.com/wiki/Papers-and-Presentations
/// * http://www.youtube.com/watch?v=_BpMYeUFXv8
/// * http://channel9.msdn.com/Events/GoingNative/2013/Inheritance-Is-The-Base-Class-of-Evil
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_IR_PASSMANAGER_H
#define LLVM_IR_PASSMANAGER_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManagerInternal.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/TypeName.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/type_traits.h"
#include <list>
#include <memory>
#include <vector>

namespace llvm {

/// \brief An abstract set of preserved analyses following a transformation pass
/// run.
///
/// When a transformation pass is run, it can return a set of analyses whose
/// results were preserved by that transformation. The default set is "none",
/// and preserving analyses must be done explicitly.
///
/// There is also an explicit all state which can be used (for example) when
/// the IR is not mutated at all.
class PreservedAnalyses {
public:
  // We have to explicitly define all the special member functions because MSVC
  // refuses to generate them.
  PreservedAnalyses() {}
  PreservedAnalyses(const PreservedAnalyses &Arg)
      : PreservedPassIDs(Arg.PreservedPassIDs) {}
  PreservedAnalyses(PreservedAnalyses &&Arg)
      : PreservedPassIDs(std::move(Arg.PreservedPassIDs)) {}
  friend void swap(PreservedAnalyses &LHS, PreservedAnalyses &RHS) {
    using std::swap;
    swap(LHS.PreservedPassIDs, RHS.PreservedPassIDs);
  }
  PreservedAnalyses &operator=(PreservedAnalyses RHS) {
    swap(*this, RHS);
    return *this;
  }

  /// \brief Convenience factory function for the empty preserved set.
  static PreservedAnalyses none() { return PreservedAnalyses(); }

  /// \brief Construct a special preserved set that preserves all passes.
  static PreservedAnalyses all() {
    PreservedAnalyses PA;
    PA.PreservedPassIDs.insert((void *)AllPassesID);
    return PA;
  }

  /// \brief Mark a particular pass as preserved, adding it to the set.
  template <typename PassT> void preserve() { preserve(PassT::ID()); }

  /// \brief Mark an abstract PassID as preserved, adding it to the set.
  void preserve(void *PassID) {
    if (!areAllPreserved())
      PreservedPassIDs.insert(PassID);
  }

  /// \brief Intersect this set with another in place.
  ///
  /// This is a mutating operation on this preserved set, removing all
  /// preserved passes which are not also preserved in the argument.
  void intersect(const PreservedAnalyses &Arg) {
    if (Arg.areAllPreserved())
      return;
    if (areAllPreserved()) {
      PreservedPassIDs = Arg.PreservedPassIDs;
      return;
    }
    for (void *P : PreservedPassIDs)
      if (!Arg.PreservedPassIDs.count(P))
        PreservedPassIDs.erase(P);
  }

  /// \brief Intersect this set with a temporary other set in place.
  ///
  /// This is a mutating operation on this preserved set, removing all
  /// preserved passes which are not also preserved in the argument.
  void intersect(PreservedAnalyses &&Arg) {
    if (Arg.areAllPreserved())
      return;
    if (areAllPreserved()) {
      PreservedPassIDs = std::move(Arg.PreservedPassIDs);
      return;
    }
    for (void *P : PreservedPassIDs)
      if (!Arg.PreservedPassIDs.count(P))
        PreservedPassIDs.erase(P);
  }

  /// \brief Query whether a pass is marked as preserved by this set.
  template <typename PassT> bool preserved() const {
    return preserved(PassT::ID());
  }

  /// \brief Query whether an abstract pass ID is marked as preserved by this
  /// set.
  bool preserved(void *PassID) const {
    return PreservedPassIDs.count((void *)AllPassesID) ||
           PreservedPassIDs.count(PassID);
  }

  /// \brief Query whether all of the analyses in the set are preserved.
  bool preserved(PreservedAnalyses Arg) {
    if (Arg.areAllPreserved())
      return areAllPreserved();
    for (void *P : Arg.PreservedPassIDs)
      if (!preserved(P))
        return false;
    return true;
  }

  /// \brief Test whether all passes are preserved.
  ///
  /// This is used primarily to optimize for the case of no changes which will
  /// common in many scenarios.
  bool areAllPreserved() const {
    return PreservedPassIDs.count((void *)AllPassesID);
  }

private:
  // Note that this must not be -1 or -2 as those are already used by the
  // SmallPtrSet.
  static const uintptr_t AllPassesID = (intptr_t)(-3);

  SmallPtrSet<void *, 2> PreservedPassIDs;
};

// The key used for holding analyses registered in the analysis manager.
struct AnalysisKey {
  void *AnalysisID;
  IRUnitKind IRUnitKindID;
};

static inline IRUnitKind getIRUnitKindID(Function *) { return IRK_Function; }
static inline IRUnitKind getIRUnitKindID(Module *) { return IRK_Module; }

// Provide DenseMapInfo for AnalysisKey
template <> struct DenseMapInfo<AnalysisKey> {
  static inline AnalysisKey getEmptyKey() { return {nullptr, IRK_Module}; }
  static inline AnalysisKey getTombstoneKey() {
    return {nullptr, IRK_Function};
  }
  static unsigned getHashValue(const AnalysisKey &Val) {
    return hash_combine(Val.AnalysisID, Val.IRUnitKindID);
  }
  static bool isEqual(const AnalysisKey &LHS, const AnalysisKey &RHS) {
    return LHS.AnalysisID == RHS.AnalysisID &&
           LHS.IRUnitKindID == RHS.IRUnitKindID;
  }
};

/// A CRTP mix-in to automatically provide informational APIs needed for
/// passes.
///
/// This provides some boiler plate for types that are passes.
template <typename DerivedT> struct PassInfoMixin {
  /// Returns the name of the derived pass type.
  static StringRef name() {
    StringRef Name = getTypeName<DerivedT>();
    if (Name.startswith("llvm::"))
      Name = Name.drop_front(strlen("llvm::"));
    return Name;
  }
};

/// A CRTP mix-in to automatically provide informational APIs needed for
/// analysis passes.
///
/// This provides some boiler plate for types that are analysis passes. It
/// automatically mixes in \c PassInfoMixin and adds informational APIs
/// specifically used for analyses.
template <typename DerivedT>
struct AnalysisInfoMixin : PassInfoMixin<DerivedT> {
  /// Returns an opaque, unique ID for this pass type.
  ///
  /// Note that this requires the derived type provide a static member whose
  /// address can be converted to a void pointer.
  ///
  /// FIXME: The only reason the derived type needs to provide this rather than
  /// this mixin providing it is due to broken implementations which cannot
  /// correctly unique a templated static so that they have the same addresses
  /// for each instantiation and are definitively emitted once for each
  /// instantiation. The only currently known platform with this limitation are
  /// Windows DLL builds, specifically building each part of LLVM as a DLL. If
  /// we ever remove that build configuration, this mixin can provide the
  /// static PassID as well.
  static void *ID() { return (void *)&DerivedT::PassID; }
};

namespace detail {

/// \brief A CRTP base used to implement analysis managers.
///
/// This class template serves as the boiler plate of an analysis manager. Any
/// analysis manager can be implemented on top of this base class. Any
/// implementation will be required to provide specific hooks:
///
/// - getResultImpl
/// - getCachedResultImpl
/// - invalidateImpl
///
/// The details of the call pattern are within.
///
/// Note that there is also a generic analysis manager template which implements
/// the above required functions along with common datastructures used for
/// managing analyses. This base class is factored so that if you need to
/// customize the handling of a specific IR unit, you can do so without
/// replicating *all* of the boilerplate.
template <typename DerivedT>
class AnalysisManagerBase {
  DerivedT *derived_this() { return static_cast<DerivedT *>(this); }
  const DerivedT *derived_this() const {
    return static_cast<const DerivedT *>(this);
  }

  AnalysisManagerBase(const AnalysisManagerBase &) = delete;
  AnalysisManagerBase &operator=(const AnalysisManagerBase &) = delete;

protected:
  typedef detail::AnalysisResultConcept ResultConceptT;
  typedef detail::AnalysisPassConcept PassConceptT;

  // FIXME: Provide template aliases for the models when we're using C++11 in
  // a mode supporting them.

  // We have to explicitly define all the special member functions because MSVC
  // refuses to generate them.
  AnalysisManagerBase() {}
  AnalysisManagerBase(AnalysisManagerBase &&Arg)
      : AnalysisPasses(std::move(Arg.AnalysisPasses)) {}
  AnalysisManagerBase &operator=(AnalysisManagerBase &&RHS) {
    AnalysisPasses = std::move(RHS.AnalysisPasses);
    return *this;
  }

public:
  /// \brief Get the result of an analysis pass for this module.
  ///
  /// If there is not a valid cached result in the manager already, this will
  /// re-run the analysis to produce a valid result.
  template <typename PassT, typename IRUnitT>
  typename PassT::Result &getResult(IRUnitT &IR) {
    AnalysisKey AK = {PassT::ID(), getIRUnitKindID(&IR)};
    assert(AnalysisPasses.count(AK) &&
           "This analysis pass was not registered prior to being queried");

    ResultConceptT &ResultConcept = derived_this()->getResultImpl(AK, IR);
    typedef detail::AnalysisResultModel<IRUnitT, PassT, typename PassT::Result>
        ResultModelT;
    return static_cast<ResultModelT &>(ResultConcept).Result;
  }

  /// \brief Get the cached result of an analysis pass for this module.
  ///
  /// This method never runs the analysis.
  ///
  /// \returns null if there is no cached result.
  template <typename PassT, typename IRUnitT>
  typename PassT::Result *getCachedResult(IRUnitT &IR) const {
    AnalysisKey AK = {PassT::ID(), getIRUnitKindID(&IR)};
    assert(AnalysisPasses.count(AK) &&
           "This analysis pass was not registered prior to being queried");

    ResultConceptT *ResultConcept = derived_this()->getCachedResultImpl(AK, IR);
    if (!ResultConcept)
      return nullptr;

    typedef detail::AnalysisResultModel<IRUnitT, PassT, typename PassT::Result>
        ResultModelT;
    return &static_cast<ResultModelT *>(ResultConcept)->Result;
  }

  /// \brief Register an analysis pass with the manager.
  ///
  /// The argument is a callable whose result is a pass. This allows passing in
  /// a lambda to construct the pass.
  ///
  /// The pass type registered is the result type of calling the argument. If
  /// that pass has already been registered, then the argument will not be
  /// called and this function will return false. Otherwise, the pass type
  /// becomes registered, with the instance provided by calling the argument
  /// once, and this function returns true.
  ///
  /// While this returns whether or not the pass type was already registered,
  /// there in't an independent way to query that as that would be prone to
  /// risky use when *querying* the analysis manager. Instead, the only
  /// supported use case is avoiding duplicate registry of an analysis. This
  /// interface also lends itself to minimizing the number of times we have to
  /// do lookups for analyses or construct complex passes only to throw them
  /// away.
  template <typename IRUnitT, typename PassBuilderT>
  bool registerPass(PassBuilderT PassBuilder) {
    typedef decltype(PassBuilder()) PassT;
    typedef detail::AnalysisPassModel<IRUnitT, PassT> PassModelT;

    AnalysisKey AK = {PassT::ID(), getIRUnitKindID((IRUnitT *)nullptr)};
    auto &PassPtr = AnalysisPasses[AK];
    if (PassPtr)
      // Already registered this pass type!
      return false;

    // Construct a new model around the instance returned by the builder.
    PassPtr.reset(new PassModelT(PassBuilder()));
    return true;
  }

  /// \brief Invalidate a specific analysis pass for an IR module.
  ///
  /// Note that the analysis result can disregard invalidation.
  template <typename PassT, typename IRUnitT> void invalidate(IRUnitT &IR) {
    AnalysisKey AK = {PassT::ID(), getIRUnitKindID(&IR)};
    assert(AnalysisPasses.count(AK) &&
           "This analysis pass was not registered prior to being invalidated");
    derived_this()->invalidateImpl(AK, IR);
  }

  /// \brief Invalidate analyses cached for an IR unit.
  ///
  /// Walk through all of the analyses pertaining to this unit of IR and
  /// invalidate them unless they are preserved by the PreservedAnalyses set.
  /// We accept the PreservedAnalyses set by value and update it with each
  /// analyis pass which has been successfully invalidated and thus can be
  /// preserved going forward. The updated set is returned.
  template <typename IRUnitT>
  PreservedAnalyses invalidate(IRUnitT &IR, PreservedAnalyses PA) {
    return derived_this()->invalidateImpl(IR, std::move(PA));
  }

protected:
  /// \brief Lookup a registered analysis pass.
  PassConceptT &lookupPass(AnalysisKey AK) {
    typename AnalysisPassMapT::iterator PI = AnalysisPasses.find(AK);
    assert(PI != AnalysisPasses.end() &&
           "Analysis passes must be registered prior to being queried!");
    return *PI->second;
  }

  /// \brief Lookup a registered analysis pass.
  const PassConceptT &lookupPass(AnalysisKey AK) const {
    typename AnalysisPassMapT::const_iterator PI = AnalysisPasses.find(AK);
    assert(PI != AnalysisPasses.end() &&
           "Analysis passes must be registered prior to being queried!");
    return *PI->second;
  }

private:
  /// \brief Map type from module analysis pass ID to pass concept pointer.
  typedef DenseMap<AnalysisKey, std::unique_ptr<PassConceptT>> AnalysisPassMapT;

  /// \brief Collection of module analysis passes, indexed by ID.
  AnalysisPassMapT AnalysisPasses;
};

} // End namespace detail

struct PerIRUnitAnalysisResultListElement;
struct DependentTrackingNode {
  std::list<PerIRUnitAnalysisResultListElement>::iterator Dependent;

  // This is a backpointer to allow deletion by somebody with just an
  // iterator.
  std::list<DependentTrackingNode> &OwnerList;
};
struct PerIRUnitAnalysisResultListElement {
  PerIRUnitAnalysisResultListElement(
      AnalysisKey AK_,
      std::unique_ptr<detail::AnalysisResultConcept> AnalysisResult_,
      TypeErasedIRUnitID ID_)
      : AK(AK_), Result(std::move(AnalysisResult_)), ID(ID_) {}
  AnalysisKey AK;
  std::unique_ptr<detail::AnalysisResultConcept> Result;
  std::list<DependentTrackingNode> Dependents;
  std::vector<std::list<DependentTrackingNode>::iterator>
      DependentTrackingNodesThatPointAtMe;

  // This is needed so that we can invalidate this analysis result with
  // just an iterator to this struct.
  TypeErasedIRUnitID ID;
};

/// \brief A generic analysis pass manager with lazy running and caching of
/// results.
///
/// This analysis manager can be used for any IR unit where the address of the
/// IR unit sufficies as its identity. It manages the cache for a unit of IR via
/// the address of each unit of IR cached.
class AnalysisManager : public detail::AnalysisManagerBase<AnalysisManager> {
  friend class detail::AnalysisManagerBase<AnalysisManager>;
  typedef detail::AnalysisManagerBase<AnalysisManager> BaseT;
  typedef typename BaseT::ResultConceptT ResultConceptT;
  typedef typename BaseT::PassConceptT PassConceptT;

public:
  // Most public APIs are inherited from the CRTP base class.

  /// \brief Construct an empty analysis manager.
  ///
  /// A flag can be passed to indicate that the manager should perform debug
  /// logging.
  AnalysisManager(bool DebugLogging = false) : DebugLogging(DebugLogging) {}

  // We have to explicitly define all the special member functions because MSVC
  // refuses to generate them.
  AnalysisManager(AnalysisManager &&Arg)
      : BaseT(std::move(static_cast<BaseT &>(Arg))),
        AnalysisResults(std::move(Arg.AnalysisResults)),
        DebugLogging(std::move(Arg.DebugLogging)) {}
  AnalysisManager &operator=(AnalysisManager &&RHS) {
    BaseT::operator=(std::move(static_cast<BaseT &>(RHS)));
    AnalysisResults = std::move(RHS.AnalysisResults);
    DebugLogging = std::move(RHS.DebugLogging);
    return *this;
  }

  /// \brief Returns true if the analysis manager has an empty results cache.
  bool empty() const {
    assert(AnalysisResults.empty() == AnalysisResultLists.empty() &&
           "The storage and index of analysis results disagree on how many "
           "there are!");
    return AnalysisResults.empty();
  }

  /// \brief Clear the analysis result cache.
  ///
  /// This routine allows cleaning up when the set of IR units itself has
  /// potentially changed, and thus we can't even look up a a result and
  /// invalidate it directly. Notably, this does *not* call invalidate functions
  /// as there is nothing to be done for them.
  void clear() {
    AnalysisResults.clear();
    AnalysisResultLists.clear();
  }

private:
  AnalysisManager(const AnalysisManager &) = delete;
  AnalysisManager &operator=(const AnalysisManager &) = delete;

  /// \brief List of function analysis pass IDs and associated concept pointers.
  ///
  /// Requires iterators to be valid across appending new entries and arbitrary
  /// erases. Provides both the pass ID and concept pointer such that it is
  /// half of a bijection and provides storage for the actual result concept.
  /// Also does dependency tracking.
  typedef std::list<PerIRUnitAnalysisResultListElement> AnalysisResultListT;


  /// \brief Get an analysis result, running the pass if necessary.
  template <typename IRUnitT>
  ResultConceptT &getResultImpl(AnalysisKey AK, IRUnitT &IR) {
    typename AnalysisResultMapT::iterator RI;
    bool Inserted;
    std::tie(RI, Inserted) = AnalysisResults.insert(
        std::make_pair(std::make_pair(AK, static_cast<TypeErasedIRUnitID>(&IR)),
                       typename AnalysisResultListT::iterator()));

    AnalysisResultListT::iterator ThisResult = RI->second;

    // If we don't have a cached result for this function, look up the pass and
    // run it to produce a result, which we then add to the cache.
    if (Inserted) {
      auto &P = this->lookupPass(AK);
      if (DebugLogging)
        dbgs() << "Running analysis: " << P.name() << "\n";
      std::unique_ptr<AnalysisResultListT> &ResultListPtr =
          AnalysisResultLists[static_cast<TypeErasedIRUnitID>(&IR)];
      if (!ResultListPtr)
        ResultListPtr = make_unique<AnalysisResultListT>();
      AnalysisResultListT &ResultList = *ResultListPtr;
      ResultList.emplace_back(
          AK, std::unique_ptr<detail::AnalysisResultConcept>(nullptr),
          static_cast<TypeErasedIRUnitID>(&IR));
      PerIRUnitAnalysisResultListElement &E = ResultList.back();
      ThisResult = std::prev(ResultList.end());
      RI->second = ThisResult;
      InFlightAnalysesStack.push_back(ThisResult);
      E.Result = P.run(static_cast<TypeErasedIRUnitID>(&IR), *this);
      InFlightAnalysesStack.pop_back();
    }

    // Add dependency tracking links.
    if (!InFlightAnalysesStack.empty()) {
      auto I = InFlightAnalysesStack.back();
      ThisResult->Dependents.push_back({I, ThisResult->Dependents});
      I->DependentTrackingNodesThatPointAtMe.push_back(
          std::prev(ThisResult->Dependents.end()));
    }

    return *ThisResult->Result;
  }

  /// \brief Get a cached analysis result or return null.
  template <typename IRUnitT>
  ResultConceptT *getCachedResultImpl(AnalysisKey AK, IRUnitT &IR) const {
    typename AnalysisResultMapT::const_iterator RI = AnalysisResults.find(
        std::make_pair(AK, static_cast<TypeErasedIRUnitID>(&IR)));
    bool Cached = RI != AnalysisResults.end();
    if (!Cached)
      return nullptr;
    AnalysisResultListT::iterator ThisResult = RI->second;
    // Add dependency tracking links.
    if (!InFlightAnalysesStack.empty()) {
      auto I = InFlightAnalysesStack.back();
      ThisResult->Dependents.push_back({I, ThisResult->Dependents});
      I->DependentTrackingNodesThatPointAtMe.push_back(
          std::prev(ThisResult->Dependents.end()));
    }
    return ThisResult->Result.get();
  }

  /// \brief Invalidate a function pass result.
  template <typename IRUnitT> void invalidateImpl(AnalysisKey AK, IRUnitT &IR) {
    invalidateImplImpl(AK, static_cast<TypeErasedIRUnitID>(&IR));
  }

  /// \brief Invalidate a function pass result.
  /// This includes walking its dependencies and invalidating them.
  ///
  /// Returns an iterator to the next element in the list (after all
  /// dependencies have been invalidated, which may have removed elements
  /// from the list).
  typename AnalysisResultListT::iterator
  invalidateImplImpl(AnalysisKey AK, TypeErasedIRUnitID ID) {
    auto MapKey = std::make_pair(AK, ID);
    typename AnalysisResultMapT::iterator RI = AnalysisResults.find(MapKey);
    if (RI == AnalysisResults.end())
      return typename AnalysisResultListT::iterator();

    if (DebugLogging)
      dbgs() << "Invalidating analysis: " << this->lookupPass(AK).name()
             << "\n";
    auto I = RI->second;
    auto &L = *AnalysisResultLists[ID];
    auto &D = I->Dependents;
    // Invalidate all dependents.
    while (!D.empty()) {
      auto &Element = *D.front().Dependent;
      // This recursive call will delete (at least) this element of `D`.
      invalidateImplImpl(Element.AK, Element.ID);
    }
    // Remove any dependent tracking nodes that are tracking a dependency
    // on this analysis result.
    // This analysis result is about to be erased and those pointers can't
    // be allowed to dangle.
    for (auto DepNodeIt : I->DependentTrackingNodesThatPointAtMe)
      DepNodeIt->OwnerList.erase(DepNodeIt);

    auto Ret = L.erase(I); // This returns the iterator to the next element.
    AnalysisResults.erase(MapKey); // RI may have been invalidated, so use the key.
    return Ret;
  }

  /// \brief Invalidate the results for a function..
  template <typename IRUnitT>
  PreservedAnalyses invalidateImpl(IRUnitT &IR, PreservedAnalyses PA) {
    // Short circuit for a common case of all analyses being preserved.
    if (PA.areAllPreserved())
      return PA;

    if (DebugLogging)
      dbgs() << "Invalidating all non-preserved analyses for: " << IR.getName()
             << "\n";

    // Clear all the invalidated results associated specifically with this
    // function.
    SmallVector<AnalysisKey, 8> InvalidatedAnalysisKeys;
    std::unique_ptr<AnalysisResultListT> &ResultsListPtr =
        AnalysisResultLists[static_cast<TypeErasedIRUnitID>(&IR)];
    if (!ResultsListPtr)
      ResultsListPtr = make_unique<AnalysisResultListT>();
    AnalysisResultListT &ResultsList = *ResultsListPtr;
    for (typename AnalysisResultListT::iterator I = ResultsList.begin(),
                                                E = ResultsList.end();
         I != E;) {
      AnalysisKey AK = I->AK;

      // Pass the invalidation down to the pass itself to see if it thinks it is
      // necessary. The analysis pass can return false if no action on the part
      // of the analysis manager is required for this invalidation event.
      if (I->Result->invalidate(static_cast<TypeErasedIRUnitID>(&IR), PA))
        I = invalidateImplImpl(AK, static_cast<TypeErasedIRUnitID>(&IR));
      else
        ++I;

      // After handling each pass, we mark it as preserved. Once we've
      // invalidated any stale results, the rest of the system is allowed to
      // start preserving this analysis again.
      PA.preserve(AK.AnalysisID);
    }
    if (ResultsList.empty())
      AnalysisResultLists.erase(static_cast<TypeErasedIRUnitID>(&IR));

    // TODO: once dependency management is in place, make each IRUnit
    // depend on a dummy analysis on its "static parent" IRUnit (i.e. for a
    // function, the module, for a loop, the parent function).
    // Associating the function with an CGSCC will be more complicated. One
    // reason is that during inlining we want to call function analyses on
    // callers of the current function (BPI and BFI at least). But Tarjan's
    // algorithm discovers SCC's in a bottom-up fashion, so we still
    // haven't even created the SCC objects for the callers.
    std::vector<std::pair<AnalysisKey, TypeErasedIRUnitID>>
        AnalysisResultsKeysLocalCopy;
    for (auto &KV : AnalysisResults)
      AnalysisResultsKeysLocalCopy.push_back(KV.first);
    for (auto &P : AnalysisResultsKeysLocalCopy) {
      AnalysisKey AK = P.first;
      TypeErasedIRUnitID ID = P.second;
      // If this is for a larger or equal IRUnitTKind
      if (AK.IRUnitKindID >= getIRUnitKindID(&IR))
        continue;
      // The key may have been deleted from the map.
      // Don't try to reinvalidate.
      if (!AnalysisResults.count(P))
        continue;

      if (AK.IRUnitKindID == IRK_Function)
        invalidateImpl(*(Function *)ID, PA);
      if (AK.IRUnitKindID == IRK_Module)
        invalidateImpl(*(Module *)ID, PA);
      // FIXME: This would be a layering violation.
      // These types live in libAnalysis.
      // The solution would be to use an indirect interface that has to be
      // registered with the analysis manager.
      //if (AK.IRUnitKindID == IRK_Loop)
      //  invalidateImpl(*(Loop *)TypeErasedIRUnitID, PA);
      //if (AK.IRUnitKindID == IRK_CGSCC)
      //  invalidateImpl(*(LazyCallGraph::SCC *)TypeErasedIRUnitID, PA);
    }
    return PA;
  }

  /// \brief Map type from function pointer to our custom list type.
  typedef DenseMap<TypeErasedIRUnitID, std::unique_ptr<AnalysisResultListT>>
      AnalysisResultListMapT;

  /// \brief Map from function to a list of function analysis results.
  ///
  /// Provides linear time removal of all analysis results for a function and
  /// the ultimate storage for a particular cached analysis result.
  AnalysisResultListMapT AnalysisResultLists;

  /// \brief Map type from a pair of analysis ID and function pointer to an
  /// iterator into a particular result list.
  typedef DenseMap<std::pair<AnalysisKey, TypeErasedIRUnitID>,
                   typename AnalysisResultListT::iterator>
      AnalysisResultMapT;

  /// \brief Map from an analysis ID and function to a particular cached
  /// analysis result.
  AnalysisResultMapT AnalysisResults;

  /// \brief A stack of analyses currently being computed.
  SmallVector<AnalysisResultListT::iterator, 8> InFlightAnalysesStack;

  /// \brief A flag indicating whether debug logging is enabled.
  bool DebugLogging;
};

// FIXME: Temporary typedef's to avoid needing as much source churn.
typedef AnalysisManager FunctionAnalysisManager;
typedef AnalysisManager ModuleAnalysisManager;

/// \brief Manages a sequence of passes over units of IR.
///
/// A pass manager contains a sequence of passes to run over units of IR. It is
/// itself a valid pass over that unit of IR, and when over some given IR will
/// run each pass in sequence. This is the primary and most basic building
/// block of a pass pipeline.
template <typename IRUnitT>
class PassManager : public PassInfoMixin<PassManager<IRUnitT>> {
public:
  /// \brief Construct a pass manager.
  ///
  /// It can be passed a flag to get debug logging as the passes are run.
  PassManager(bool DebugLogging = false) : DebugLogging(DebugLogging) {}
  // We have to explicitly define all the special member functions because MSVC
  // refuses to generate them.
  PassManager(PassManager &&Arg)
      : Passes(std::move(Arg.Passes)),
        DebugLogging(std::move(Arg.DebugLogging)) {}
  PassManager &operator=(PassManager &&RHS) {
    Passes = std::move(RHS.Passes);
    DebugLogging = std::move(RHS.DebugLogging);
    return *this;
  }

  /// \brief Run all of the passes in this manager over the IR.
  PreservedAnalyses run(IRUnitT &IR, AnalysisManager &AM) {
    PreservedAnalyses PA = PreservedAnalyses::all();

    if (DebugLogging)
      dbgs() << "Starting " << getTypeName<IRUnitT>() << " pass manager run.\n";

    for (unsigned Idx = 0, Size = Passes.size(); Idx != Size; ++Idx) {
      if (DebugLogging)
        dbgs() << "Running pass: " << Passes[Idx]->name() << " on "
               << IR.getName() << "\n";

      PreservedAnalyses PassPA = Passes[Idx]->run(IR, AM);

      // Update the analysis manager as each pass runs and potentially
      // invalidates analyses. We also update the preserved set of analyses
      // based on what analyses we have already handled the invalidation for
      // here and don't need to invalidate when finished.
      PassPA = AM.invalidate(IR, std::move(PassPA));

      // Finally, we intersect the final preserved analyses to compute the
      // aggregate preserved set for this pass manager.
      PA.intersect(std::move(PassPA));

      // FIXME: Historically, the pass managers all called the LLVM context's
      // yield function here. We don't have a generic way to acquire the
      // context and it isn't yet clear what the right pattern is for yielding
      // in the new pass manager so it is currently omitted.
      //IR.getContext().yield();
    }

    if (DebugLogging)
      dbgs() << "Finished " << getTypeName<IRUnitT>() << " pass manager run.\n";

    return PA;
  }

  template <typename PassT> void addPass(PassT Pass) {
    typedef detail::PassModel<IRUnitT, PassT> PassModelT;
    Passes.emplace_back(new PassModelT(std::move(Pass)));
  }

private:
  typedef detail::PassConcept<IRUnitT> PassConceptT;

  PassManager(const PassManager &) = delete;
  PassManager &operator=(const PassManager &) = delete;

  std::vector<std::unique_ptr<PassConceptT>> Passes;

  /// \brief Flag indicating whether we should do debug logging.
  bool DebugLogging;
};

extern template class PassManager<Module>;
/// \brief Convenience typedef for a pass manager over modules.
typedef PassManager<Module> ModulePassManager;

extern template class PassManager<Function>;
/// \brief Convenience typedef for a pass manager over functions.
typedef PassManager<Function> FunctionPassManager;


/// \brief Trivial adaptor that maps from a module to its functions.
///
/// Designed to allow composition of a FunctionPass(Manager) and
/// a ModulePassManager.
///
/// Function passes run within this adaptor can rely on having exclusive access
/// to the function they are run over. They should not read or modify any other
/// functions! Other threads or systems may be manipulating other functions in
/// the module, and so their state should never be relied on.
/// FIXME: Make the above true for all of LLVM's actual passes, some still
/// violate this principle.
///
/// Function passes can also read the module containing the function, but they
/// should not modify that module outside of the use lists of various globals.
/// For example, a function pass is not permitted to add functions to the
/// module.
/// FIXME: Make the above true for all of LLVM's actual passes, some still
/// violate this principle.
template <typename FunctionPassT>
class ModuleToFunctionPassAdaptor
    : public PassInfoMixin<ModuleToFunctionPassAdaptor<FunctionPassT>> {
public:
  explicit ModuleToFunctionPassAdaptor(FunctionPassT Pass)
      : Pass(std::move(Pass)) {}
  // We have to explicitly define all the special member functions because MSVC
  // refuses to generate them.
  ModuleToFunctionPassAdaptor(const ModuleToFunctionPassAdaptor &Arg)
      : Pass(Arg.Pass) {}
  ModuleToFunctionPassAdaptor(ModuleToFunctionPassAdaptor &&Arg)
      : Pass(std::move(Arg.Pass)) {}
  friend void swap(ModuleToFunctionPassAdaptor &LHS,
                   ModuleToFunctionPassAdaptor &RHS) {
    using std::swap;
    swap(LHS.Pass, RHS.Pass);
  }
  ModuleToFunctionPassAdaptor &operator=(ModuleToFunctionPassAdaptor RHS) {
    swap(*this, RHS);
    return *this;
  }

  /// \brief Runs the function pass across every function in the module.
  PreservedAnalyses run(Module &M, AnalysisManager &AM) {
    PreservedAnalyses PA = PreservedAnalyses::all();
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      PreservedAnalyses PassPA = Pass.run(F, AM);

      // We know that the function pass couldn't have invalidated any other
      // function's analyses (that's the contract of a function pass), so
      // directly handle the function analysis manager's invalidation here and
      // update our preserved set to reflect that these have already been
      // handled.
      PassPA = AM.invalidate(F, std::move(PassPA));

      // Then intersect the preserved set so that invalidation of module
      // analyses will eventually occur when the module pass completes.
      PA.intersect(std::move(PassPA));
    }

    return PA;
  }

private:
  FunctionPassT Pass;
};

/// \brief A function to deduce a function pass type and wrap it in the
/// templated adaptor.
template <typename FunctionPassT>
ModuleToFunctionPassAdaptor<FunctionPassT>
createModuleToFunctionPassAdaptor(FunctionPassT Pass) {
  return ModuleToFunctionPassAdaptor<FunctionPassT>(std::move(Pass));
}

/// \brief A template utility pass to force an analysis result to be available.
///
/// This is a no-op pass which simply forces a specific analysis pass's result
/// to be available when it is run.
template <typename AnalysisT>
struct RequireAnalysisPass : PassInfoMixin<RequireAnalysisPass<AnalysisT>> {
  /// \brief Run this pass over some unit of IR.
  ///
  /// This pass can be run over any unit of IR and use any analysis manager
  /// provided they satisfy the basic API requirements. When this pass is
  /// created, these methods can be instantiated to satisfy whatever the
  /// context requires.
  template <typename IRUnitT>
  PreservedAnalyses run(IRUnitT &Arg, AnalysisManager &AM) {
    (void)AM.template getResult<AnalysisT>(Arg);

    return PreservedAnalyses::all();
  }
};

/// \brief A template utility pass to force an analysis result to be
/// invalidated.
///
/// This is a no-op pass which simply forces a specific analysis result to be
/// invalidated when it is run.
template <typename AnalysisT>
struct InvalidateAnalysisPass
    : PassInfoMixin<InvalidateAnalysisPass<AnalysisT>> {
  /// \brief Run this pass over some unit of IR.
  ///
  /// This pass can be run over any unit of IR and use any analysis manager
  /// provided they satisfy the basic API requirements. When this pass is
  /// created, these methods can be instantiated to satisfy whatever the
  /// context requires.
  template <typename IRUnitT>
  PreservedAnalyses run(IRUnitT &Arg, AnalysisManager &AM) {
    // We have to directly invalidate the analysis result as we can't
    // enumerate all other analyses and use the preserved set to control it.
    AM.template invalidate<AnalysisT>(Arg);

    return PreservedAnalyses::all();
  }
};

/// \brief A utility pass that does nothing but preserves no analyses.
///
/// As a consequence fo not preserving any analyses, this pass will force all
/// analysis passes to be re-run to produce fresh results if any are needed.
struct InvalidateAllAnalysesPass : PassInfoMixin<InvalidateAllAnalysesPass> {
  /// \brief Run this pass over some unit of IR.
  template <typename IRUnitT>
  PreservedAnalyses run(IRUnitT &, AnalysisManager &) {
    return PreservedAnalyses::none();
  }
};

/// A utility pass template that simply runs another pass multiple times.
///
/// This can be useful when debugging or testing passes. It also serves as an
/// example of how to extend the pass manager in ways beyond composition.
template <typename PassT>
class RepeatedPass : public PassInfoMixin<RepeatedPass<PassT>> {
public:
  RepeatedPass(int Count, PassT P) : Count(Count), P(std::move(P)) {}
  // We have to explicitly define all the special member functions because MSVC
  // refuses to generate them.
  RepeatedPass(const RepeatedPass &Arg) : Count(Arg.Count), P(Arg.P) {}
  RepeatedPass(RepeatedPass &&Arg) : Count(Arg.Count), P(std::move(Arg.P)) {}
  friend void swap(RepeatedPass &LHS, RepeatedPass &RHS) {
    using std::swap;
    swap(LHS.Count, RHS.Count);
    swap(LHS.P, RHS.P);
  }
  RepeatedPass &operator=(RepeatedPass RHS) {
    swap(*this, RHS);
    return *this;
  }

  template <typename IRUnitT, typename... Ts>
  PreservedAnalyses run(IRUnitT &Arg, AnalysisManager &AM, Ts... Args) {
    auto PA = PreservedAnalyses::all();
    for (int i = 0; i < Count; ++i)
      PA.intersect(P.run(Arg, AM, Args...));
    return PA;
  }

private:
  int Count;
  PassT P;
};

template <typename PassT>
RepeatedPass<PassT> createRepeatedPass(int Count, PassT P) {
  return RepeatedPass<PassT>(Count, std::move(P));
}

}

#endif
