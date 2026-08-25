// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <crypto/crypto_accel.h>
#include <kernel/thread.h>

void sha512_riscv_zvkng_transform(uint64_t state[8], const void *src,
				  unsigned int block_count);

void crypto_accel_sha512_compress(uint64_t state[8], const void *src,
				  unsigned int block_count)
{
	uint32_t vfp_state = thread_kernel_enable_vfp();

	sha512_riscv_zvkng_transform(state, src, block_count);
	thread_kernel_disable_vfp(vfp_state);
}
