; RUN: llc -march=amdgcn -mcpu=SI -verify-machineinstrs < %s | FileCheck -check-prefix=SI -check-prefix=GCN -check-prefix=SI-NOHSA -check-prefix=GCN-NOHSA -check-prefix=FUNC %s
; RUN: llc -march=amdgcn -mcpu=tonga -verify-machineinstrs < %s | FileCheck -check-prefix=VI  -check-prefix=VI-NOHSA -check-prefix=GCN -check-prefix=GCN-NOHSA -check-prefix=FUNC %s
; RUN: llc -march=r600 -mcpu=redwood < %s | FileCheck -check-prefix=EG -check-prefix=FUNC %s


; FUNC-LABEL: {{^}}ngroups_x:
; EG: MEM_RAT_CACHELESS STORE_RAW [[VAL:T[0-9]+\.X]]
; EG: MOV {{\*? *}}[[VAL]], KC0[0].X

; GCN-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0
; GCN-NOHSA: v_mov_b32_e32 [[VVAL:v[0-9]+]], [[VAL]]
; GCN-NOHSA: buffer_store_dword [[VVAL]]

define void @ngroups_x (i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.ngroups.x() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; FUNC-LABEL: {{^}}ngroups_y:
; EG: MEM_RAT_CACHELESS STORE_RAW [[VAL:T[0-9]+\.X]]
; EG: MOV {{\*? *}}[[VAL]], KC0[0].Y

; SI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0x1
; VI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0x4
; GCN-NOHSA: v_mov_b32_e32 [[VVAL:v[0-9]+]], [[VAL]]
; GCN-NOHSA: buffer_store_dword [[VVAL]]
define void @ngroups_y (i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.ngroups.y() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; FUNC-LABEL: {{^}}ngroups_z:
; EG: MEM_RAT_CACHELESS STORE_RAW [[VAL:T[0-9]+\.X]]
; EG: MOV {{\*? *}}[[VAL]], KC0[0].Z

; SI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0x2
; VI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0x8
; GCN-NOHSA: v_mov_b32_e32 [[VVAL:v[0-9]+]], [[VAL]]
; GCN-NOHSA: buffer_store_dword [[VVAL]]
define void @ngroups_z (i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.ngroups.z() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; FUNC-LABEL: {{^}}global_size_x:
; EG: MEM_RAT_CACHELESS STORE_RAW [[VAL:T[0-9]+\.X]]
; EG: MOV {{\*? *}}[[VAL]], KC0[0].W

; SI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0x3
; VI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0xc
; GCN-NOHSA: v_mov_b32_e32 [[VVAL:v[0-9]+]], [[VAL]]
; GCN-NOHSA: buffer_store_dword [[VVAL]]
define void @global_size_x (i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.global.size.x() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; FUNC-LABEL: {{^}}global_size_y:
; EG: MEM_RAT_CACHELESS STORE_RAW [[VAL:T[0-9]+\.X]]
; EG: MOV {{\*? *}}[[VAL]], KC0[1].X

; SI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0x4
; VI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0x10
; GCN-NOHSA: v_mov_b32_e32 [[VVAL:v[0-9]+]], [[VAL]]
; GCN-NOHSA: buffer_store_dword [[VVAL]]
define void @global_size_y (i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.global.size.y() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; FUNC-LABEL: {{^}}global_size_z:
; EG: MEM_RAT_CACHELESS STORE_RAW [[VAL:T[0-9]+\.X]]
; EG: MOV {{\*? *}}[[VAL]], KC0[1].Y

; SI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0x5
; VI-NOHSA: s_load_dword [[VAL:s[0-9]+]], s[0:1], 0x14
; GCN-NOHSA: v_mov_b32_e32 [[VVAL:v[0-9]+]], [[VAL]]
; GCN-NOHSA: buffer_store_dword [[VVAL]]
define void @global_size_z (i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.global.size.z() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; The tgid values are stored in sgprs offset by the number of user
; sgprs.

; FUNC-LABEL: {{^}}tgid_x:
; GCN-NOHSA: v_mov_b32_e32 [[VVAL:v[0-9]+]], s2{{$}}
; GCN-NOHSA: buffer_store_dword [[VVAL]]

; GCN-NOHSA: COMPUTE_PGM_RSRC2:USER_SGPR: 2
; GCN: COMPUTE_PGM_RSRC2:TGID_X_EN: 1
; GCN: COMPUTE_PGM_RSRC2:TGID_Y_EN: 0
; GCN: COMPUTE_PGM_RSRC2:TGID_Z_EN: 0
; GCN: COMPUTE_PGM_RSRC2:TIDIG_COMP_CNT: 0
define void @tgid_x(i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.tgid.x() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; FUNC-LABEL: {{^}}tgid_y:
; GCN-NOHSA: v_mov_b32_e32 [[VVAL:v[0-9]+]], s3
; GCN-NOHSA: buffer_store_dword [[VVAL]]

; GCN-NOHSA: COMPUTE_PGM_RSRC2:USER_SGPR: 2
define void @tgid_y(i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.tgid.y() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; FUNC-LABEL: {{^}}tgid_z:
; GCN-NOHSA: v_mov_b32_e32 [[VVAL:v[0-9]+]], s3{{$}}
; GCN-NOHSA: buffer_store_dword [[VVAL]]

; GCN-NOHSA: COMPUTE_PGM_RSRC2:USER_SGPR: 2
; GCN: COMPUTE_PGM_RSRC2:TGID_X_EN: 1
; GCN: COMPUTE_PGM_RSRC2:TGID_Y_EN: 0
; GCN: COMPUTE_PGM_RSRC2:TGID_Z_EN: 1
; GCN: COMPUTE_PGM_RSRC2:TIDIG_COMP_CNT: 0
define void @tgid_z(i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.tgid.z() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; GCN-NOHSA: .section .AMDGPU.config
; GCN-NOHSA: .long 47180
; GCN-NOHSA-NEXT: .long 132{{$}}

; FUNC-LABEL: {{^}}tidig_x:
; GCN-NOHSA: buffer_store_dword v0
define void @tidig_x(i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.tidig.x() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; GCN-NOHSA: .section .AMDGPU.config
; GCN-NOHSA: .long 47180
; GCN-NOHSA-NEXT: .long 2180{{$}}

; FUNC-LABEL: {{^}}tidig_y:

; GCN-NOHSA: buffer_store_dword v1
define void @tidig_y(i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.tidig.y() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

; GCN-NOHSA: .section .AMDGPU.config
; GCN-NOHSA: .long 47180
; GCN-NOHSA-NEXT: .long 4228{{$}}

; FUNC-LABEL: {{^}}tidig_z:
; GCN-NOHSA: buffer_store_dword v2
define void @tidig_z(i32 addrspace(1)* %out) {
entry:
  %0 = call i32 @llvm.r600.read.tidig.z() #0
  store i32 %0, i32 addrspace(1)* %out
  ret void
}

declare i32 @llvm.r600.read.ngroups.x() #0
declare i32 @llvm.r600.read.ngroups.y() #0
declare i32 @llvm.r600.read.ngroups.z() #0

declare i32 @llvm.r600.read.global.size.x() #0
declare i32 @llvm.r600.read.global.size.y() #0
declare i32 @llvm.r600.read.global.size.z() #0

declare i32 @llvm.r600.read.tgid.x() #0
declare i32 @llvm.r600.read.tgid.y() #0
declare i32 @llvm.r600.read.tgid.z() #0

declare i32 @llvm.r600.read.tidig.x() #0
declare i32 @llvm.r600.read.tidig.y() #0
declare i32 @llvm.r600.read.tidig.z() #0

declare i32 @llvm.AMDGPU.read.workdim() #0

attributes #0 = { readnone }
