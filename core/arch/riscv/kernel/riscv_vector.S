/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <riscv.h>
#include <riscv_macros.S>
#include <riscv_vector.h>

#if defined(CFG_WITH_VFP)

/*
 * size_t riscv_vector_state_size(void)
 * Formula: sizeof(struct riscv_vector_state) + (32 * CSR_VLENB)
 */

FUNC riscv_vector_state_size , :
	/* 1. Read the active xstatus and preserve it */
	csrr    t1, CSR_XSTATUS

        /* 2. Temporarily enable the Vector extension (Set VS to 01) */
	li      t2, ~CSR_XSTATUS_VS_MASK
        and     t2, t1, t2               /* Clear existing VS bits */
	li      t3, (CSR_XSTATUS_VS_INITIAL << CSR_XSTATUS_VS_BIT)
        or      t2, t2, t3               /* Set VS to 01 (Initial) */
	csrw    CSR_XSTATUS, t2

        /* 3. Safe to read CSR_VLENB now without a panic */
        csrr    a0, CSR_VLENB            /* Fetch vector length in bytes */

        /* 4. Restore original sstatus to lock down vector state */
	csrw    CSR_XSTATUS, t1

	/* 5. Calculate structure size: (32 * vlenb) + fixed fields */
        li      t0, 32
        mul     a0, a0, t0               /* a0 = 32 * vlenb */
	addi    a0, a0, (RISCV_XLEN_BYTES * 5)
        ret
END_FUNC riscv_vector_state_size


/*
 * void riscv_vector_save(struct riscv_vector_state *dst)
 * Layout offsets are expressed in XLEN-sized units, matching
 * struct riscv_vector_state.
 */
FUNC riscv_vector_save , :
	beqz a0, 1f /* Early exit if dst == NULL */

	/* Step 1: Save original status register and enable VS. */
	csrr t1, CSR_XSTATUS /* t1 = current status */
	srli t0, t1, CSR_XSTATUS_VS_BIT
	andi t0, t0, 3
	STR t0, 0(a0)
	li t0, CSR_XSTATUS_VS_MASK /* vector state bitmask flag */
	csrs CSR_XSTATUS, t0 /* Enable Vector Unit */

	/* Step 2: Save Control Registers */
	csrr t0, CSR_VCSR
	STR t0, RISCV_XLEN_BYTES(a0)
	csrr t0, CSR_VSTART
	STR t0, (RISCV_XLEN_BYTES * 2)(a0)
	csrr t0, CSR_VL
	STR t0, (RISCV_XLEN_BYTES * 3)(a0)
	csrr t0, CSR_VTYPE
	STR t0, (RISCV_XLEN_BYTES * 4)(a0)

	/* Step 3: Save Vector Data Registers via Unrolled Macro */
	csrr t2, CSR_VLENB /* t2 = vlenb */
	addi a1, a0, (RISCV_XLEN_BYTES * 5)
	do_all_vreg_chunks vs8r.v, a1, t2

	/* Step 4: Restore original status context cleanly */
	csrw CSR_XSTATUS, t1
1:
	ret
END_FUNC riscv_vector_save


/*
 * void riscv_vector_restore(const struct riscv_vector_state *src)
 */
FUNC riscv_vector_restore , :
	beqz a0, 1f /* Early exit if src == NULL */

	/* Step 1: Save original status register and enable execution
	 *  tracking safety flags
	 */
	csrr t1, CSR_XSTATUS /* t1 = current status */
	li t0, CSR_XSTATUS_VS_MASK /* vector state bitmask flag */
	csrs CSR_XSTATUS, t0 /* Enable Vector Unit */

	/* Step 2: Restore the vector configuration and registers. */
	LDR t4, (RISCV_XLEN_BYTES * 3)(a0)
	LDR t5, (RISCV_XLEN_BYTES * 4)(a0)
	vsetvl zero, t4, t5
	csrr t2, CSR_VLENB
	addi a1, a0, (RISCV_XLEN_BYTES * 5)
	do_all_vreg_chunks vl8r.v, a1, t2

	/* Step 3: Restore CSR registers */
	LDR t0, RISCV_XLEN_BYTES(a0)
	csrw CSR_VCSR, t0
	LDR t0, (RISCV_XLEN_BYTES * 2)(a0)
	csrw CSR_VSTART, t0

	/* Step 4: Restore original status context cleanly */
	csrw CSR_XSTATUS, t1
1:
	ret
END_FUNC riscv_vector_restore

#endif /* CFG_WITH_VFP */
