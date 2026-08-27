// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <crypto/crypto_accel.h>
#if defined(CFG_RISCV_TEST_SHA2_KAT)
#include "riscv_zvkng_test.h"
#else
#include <kernel/thread.h>
#endif

void sha256_transform_zvknha_or_zvknhb_zvkb(uint32_t state[8],
					    const void *src,
					    unsigned int block_count);

void crypto_accel_sha256_compress(uint32_t state[8], const void *src,
				  unsigned int block_count)
{
#if defined(CFG_RISCV_TEST_SHA2_KAT)
	unsigned long xstatus = riscv_zvkng_test_vector_enable();

	sha256_transform_zvknha_or_zvknhb_zvkb(state, src, block_count);
	riscv_zvkng_test_vector_disable(xstatus);
#else
	uint32_t vfp_state = thread_kernel_enable_vfp();

	sha256_transform_zvknha_or_zvknhb_zvkb(state, src, block_count);
	thread_kernel_disable_vfp(vfp_state);
#endif
}
