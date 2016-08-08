; RUN: opt '-passes=require<aa>,invalidate<basic-aa>' -aa-pipeline=basic-aa \
; RUN:     -debug-pass-manager -disable-output < %s 2>&1 | FileCheck %s


; CHECK:      Running pass: InvalidateAnalysisPass<llvm::BasicAA>
; CHECK-NEXT: Invalidating analysis: BasicAA
; CHECK-NEXT: Invalidating analysis: AAManager


target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define void @foo() {
entry:
  ret void
}
