/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 *
 * AES SubWord implemented with the RISC-V Vector AES instructions.
 */

#include <asm.S>

.text
.option arch, +zvkned

/*
 * uint32_t aes_riscv_zvkng_subword(uint32_t word)
 *
 * Replicate word into each AES state column.  This makes ShiftRows a no-op,
 * therefore vaesef.vs with an all-zero round key performs SubBytes(word).
 */
FUNC aes_riscv_zvkng_subword , :
	vsetivli	zero, 4, e32, m1, ta, ma
	vmv.v.x	v1, a0
	vmv.v.i	v2, 0
	vaesef.vs	v1, v2
	vmv.x.s	a0, v1
	ret
