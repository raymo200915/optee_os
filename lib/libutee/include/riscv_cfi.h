/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 NXP
 * Copyright (c) 2026, RISCStar Solutions Corporation
 */

#ifndef __RISCV_CFI_H
#define __RISCV_CFI_H

/*
 * LLVM 22 emits LPAD instructions for -fcf-protection, but does not emit the
 * RISC-V FEATURE_1_AND note for C or C++ objects. The linker ANDs this
 * property across all its input objects, so emit it explicitly in every
 * protected TA and ldelf C/C++ compilation unit.
 */
#include <elf_common.h>

#if defined(CFG_TA_ZICFILP)
#define RISCV_CFI_FEATURE_LP GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_UNLABELED
#else
#define RISCV_CFI_FEATURE_LP 0
#endif

#if defined(CFG_TA_ZICFISS)
#define RISCV_CFI_FEATURE_SS GNU_PROPERTY_RISCV_FEATURE_1_CFI_SS
#else
#define RISCV_CFI_FEATURE_SS 0
#endif

#define RISCV_CFI_FEATURE_AND (RISCV_CFI_FEATURE_LP | RISCV_CFI_FEATURE_SS)

#define __riscv_cfi_stringify_1(x) #x
#define __riscv_cfi_stringify(x) __riscv_cfi_stringify_1(x)

#if __riscv_xlen == 32
#define RISCV_CFI_NOTE_P2ALIGN "2"
#else
#define RISCV_CFI_NOTE_P2ALIGN "3"
#endif

__asm__(
	".pushsection .note.gnu.property, \"a\"\n"
	".p2align " RISCV_CFI_NOTE_P2ALIGN "\n"
	".long 2f - 1f\n"
	".long 6f - 3f\n"
	".long " __riscv_cfi_stringify(NT_GNU_PROPERTY_TYPE_0) "\n"
	"1: .string \"GNU\"\n"
	"2:\n"
	".p2align " RISCV_CFI_NOTE_P2ALIGN "\n"
	"3: .long " __riscv_cfi_stringify(GNU_PROPERTY_RISCV_FEATURE_1_AND) "\n"
	".long 5f - 4f\n"
	"4: .long " __riscv_cfi_stringify(RISCV_CFI_FEATURE_AND) "\n"
	"5:\n"
	".p2align " RISCV_CFI_NOTE_P2ALIGN "\n"
	"6:\n"
	".popsection\n");

#endif /* __RISCV_CFI_H */
