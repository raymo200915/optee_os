// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <crypto/crypto_accel.h>
#include <initcall.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

static TEE_Result sha256_kat(void)
{
	static const uint8_t block[64] = {
		0x61, 0x62, 0x63, 0x80,
		[63] = 0x18,
	};
	static const uint32_t initial_state[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};
	static const uint32_t expected_state[8] = {
		0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
		0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
	};
	uint32_t state[ARRAY_SIZE(initial_state)] = { };

	memcpy(state, initial_state, sizeof(state));
	crypto_accel_sha256_compress(state, block, 1);

	if (memcmp(state, expected_state, sizeof(state)))
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}

static TEE_Result sha512_kat(void)
{
	static const uint8_t block[128] = {
		0x61, 0x62, 0x63, 0x80,
		[127] = 0x18,
	};
	static const uint64_t initial_state[8] = {
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	};
	static const uint64_t expected_state[8] = {
		0xddaf35a193617aba, 0xcc417349ae204131,
		0x12e6fa4e89a97ea2, 0x0a9eeee64b55d39a,
		0x2192992a274fc1a8, 0x36ba3c23a3feebbd,
		0x454d4423643ce80e, 0x2a9ac94fa54ca49f,
	};
	uint64_t state[ARRAY_SIZE(initial_state)] = { };

	memcpy(state, initial_state, sizeof(state));
	crypto_accel_sha512_compress(state, block, 1);

	if (memcmp(state, expected_state, sizeof(state)))
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}

static TEE_Result sha2_riscv_zvkng_kat_init(void)
{
	TEE_Result res = sha256_kat();

	if (!res)
		res = sha512_kat();
	if (res)
		EMSG("RISC-V vector SHA-2 KAT failed: %#" PRIx32, res);
	else
		IMSG("RISC-V vector SHA-2 KAT passed");

	return res;
}
service_init_crypto(sha2_riscv_zvkng_kat_init);
