// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <crypto/crypto_accel.h>
#include <kernel/thread.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

struct aes_block {
	uint8_t b[TEE_AES_BLOCK_SIZE];
};

uint32_t aes_riscv_zvkng_subword(uint32_t word);

static uint32_t ror32(uint32_t val, unsigned int shift)
{
	return (val >> shift) | (val << (32 - shift));
}

#ifdef CFG_RISCV_ZVKNG
TEE_Result crypto_riscv_zvkng_aes_expand_keys_kat(void);

static TEE_Result test_aes_expand_key(const uint8_t *key, size_t key_len,
				      const uint8_t *last_round_key)
{
	struct aes_block enc[15] = { };
	struct aes_block dec[15] = { };
	unsigned int rounds = 0;
	TEE_Result res = TEE_SUCCESS;

	res = crypto_accel_aes_expand_keys(key, key_len, enc, dec, sizeof(enc),
					  &rounds);
	if (res)
		return res;
	if (memcmp(enc[rounds].b, last_round_key, TEE_AES_BLOCK_SIZE) ||
	    memcmp(dec[0].b, last_round_key, TEE_AES_BLOCK_SIZE) ||
	    memcmp(dec[rounds].b, key, TEE_AES_BLOCK_SIZE))
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}

TEE_Result crypto_riscv_zvkng_aes_expand_keys_kat(void)
{
	static const uint8_t key_128[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	static const uint8_t key_192[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	};
	static const uint8_t key_256[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	static const uint8_t last_128[] = {
		0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17,
		0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5,
	};
	static const uint8_t last_192[] = {
		0xa4, 0x97, 0x0a, 0x33, 0x1a, 0x78, 0xdc, 0x09,
		0xc4, 0x18, 0xc2, 0x71, 0xe3, 0xa4, 0x1d, 0x5d,
	};
	static const uint8_t last_256[] = {
		0x24, 0xfc, 0x79, 0xcc, 0xbf, 0x09, 0x79, 0xe9,
		0x37, 0x1a, 0xc2, 0x3c, 0x6d, 0x68, 0xde, 0x36,
	};
	TEE_Result res = TEE_SUCCESS;

	res = test_aes_expand_key(key_128, sizeof(key_128), last_128);
	if (!res)
		res = test_aes_expand_key(key_192, sizeof(key_192), last_192);
	if (!res)
		res = test_aes_expand_key(key_256, sizeof(key_256), last_256);
	if (res)
		EMSG("AES key expansion KAT failed: %#" PRIx32, res);
	else
		IMSG("AES key expansion KAT passed");

	return res;
}
#endif

static void expand_enc_key(uint32_t *enc_key, size_t key_len)
{
	static const uint8_t rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
	};
	unsigned int kwords = key_len / sizeof(uint32_t);
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(rcon); i++) {
		uint32_t *rki = enc_key + i * kwords;
		uint32_t *rko = rki + kwords;

		rko[0] = ror32(aes_riscv_zvkng_subword(rki[kwords - 1]), 8) ^
			 rcon[i] ^ rki[0];
		rko[1] = rko[0] ^ rki[1];
		rko[2] = rko[1] ^ rki[2];
		rko[3] = rko[2] ^ rki[3];

		if (key_len == 24) {
			if (i >= 7)
				break;
			rko[4] = rko[3] ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
		} else if (key_len == 32) {
			if (i >= 6)
				break;
			rko[4] = aes_riscv_zvkng_subword(rko[3]) ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
			rko[6] = rko[5] ^ rki[6];
			rko[7] = rko[6] ^ rki[7];
		}
	}
}

static void make_dec_key(unsigned int round_count,
			 const struct aes_block *key_enc,
			 struct aes_block *key_dec)
{
	unsigned int i = 0;

	/*
	 * vaesdm.vs incorporates InvMixColumns itself, so it uses the normal
	 * encryption round keys in reverse order.
	 */
	for (i = 0; i <= round_count; i++)
		key_dec[i] = key_enc[round_count - i];
}

TEE_Result crypto_accel_aes_expand_keys(const void *key, size_t key_len,
					void *enc_key, void *dec_key,
					size_t expanded_key_len,
					unsigned int *round_count)
{
	unsigned int num_rounds = 0;
	uint32_t vfp_state = 0;

	if (!key || !enc_key || !round_count)
		return TEE_ERROR_BAD_PARAMETERS;
	if (key_len != 16 && key_len != 24 && key_len != 32)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!IS_ALIGNED_WITH_TYPE(enc_key, struct aes_block) ||
	    (dec_key && !IS_ALIGNED_WITH_TYPE(dec_key, struct aes_block)))
		return TEE_ERROR_BAD_PARAMETERS;

	num_rounds = 10 + ((key_len / 8) - 2) * 2;
	if (expanded_key_len < (num_rounds + 1) * sizeof(struct aes_block))
		return TEE_ERROR_BAD_PARAMETERS;

	*round_count = num_rounds;
	memset(enc_key, 0, expanded_key_len);
	memcpy(enc_key, key, key_len);

	vfp_state = thread_kernel_enable_vfp();
	expand_enc_key(enc_key, key_len);
	if (dec_key)
		make_dec_key(num_rounds, enc_key, dec_key);
	thread_kernel_disable_vfp(vfp_state);

	return TEE_SUCCESS;
}
