// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <crypto/crypto_accel.h>
#include <kernel/thread.h>
#include <string.h>
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
