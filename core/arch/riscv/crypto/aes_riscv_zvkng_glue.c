// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include <assert.h>
#include <stdbool.h>
#include "aes_riscv_zvkng.h"
#include <crypto/crypto_accel.h>
#include <kernel/thread.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

#define AES_EXPANDED_KEY_SIZE	(15 * TEE_AES_BLOCK_SIZE)

/*
 * LibTomCrypt stores the encryption and decryption schedules separately, so
 * the mode wrappers build the Linux vector AES ABI adapter on the stack.
 */

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
	uint8_t product = 0;

	while (b) {
		if (b & 1)
			product ^= a;
		a = (a << 1) ^ ((a >> 7) * 0x1b);
		b >>= 1;
	}

	return product;
}

static uint8_t aes_sbox(uint8_t x)
{
	uint8_t inverse = 1;
	uint8_t power = x;
	uint8_t result = 0;
	unsigned int i = 0;

	if (!x)
		return 0x63;

	/* x^-1 = x^254 in GF(2^8). */
	for (i = 0; i < 8; i++) {
		if ((254 >> i) & 1)
			inverse = gf_mul(inverse, power);
		power = gf_mul(power, power);
	}

	for (i = 0; i < 8; i++)
		result ^= (((inverse >> i) ^ (inverse >> ((i + 4) & 7)) ^
			    (inverse >> ((i + 5) & 7)) ^
			    (inverse >> ((i + 6) & 7)) ^
			    (inverse >> ((i + 7) & 7))) & 1) << i;

	return result ^ 0x63;
}

static uint32_t subword(uint32_t word)
{
	uint32_t result = 0;
	unsigned int i = 0;

	for (i = 0; i < sizeof(word); i++)
		result |= (uint32_t)aes_sbox(word >> (i * 8)) << (i * 8);

	return result;
}

static uint32_t ror32(uint32_t value, unsigned int shift)
{
	return (value >> shift) | (value << (32 - shift));
}

static void expand_enc_key(uint32_t *enc_key, size_t key_len)
{
	static const uint8_t rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
	};
	unsigned int key_words = key_len / sizeof(*enc_key);
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(rcon); i++) {
		uint32_t *input = enc_key + i * key_words;
		uint32_t *output = input + key_words;

		output[0] = ror32(subword(input[key_words - 1]), 8) ^
			    rcon[i] ^ input[0];
		output[1] = output[0] ^ input[1];
		output[2] = output[1] ^ input[2];
		output[3] = output[2] ^ input[3];

		if (key_len == 24) {
			if (i >= 7)
				break;
			output[4] = output[3] ^ input[4];
			output[5] = output[4] ^ input[5];
		} else if (key_len == 32) {
			if (i >= 6)
				break;
			output[4] = subword(output[3]) ^ input[4];
			output[5] = output[4] ^ input[5];
			output[6] = output[5] ^ input[6];
			output[7] = output[6] ^ input[7];
		}
	}
}

TEE_Result crypto_accel_aes_expand_keys(const void *key, size_t key_len,
					void *enc_key, void *dec_key,
					size_t expanded_key_len,
					unsigned int *round_count)
{
	unsigned int rounds = 0;

	if (!key || !enc_key || !round_count)
		return TEE_ERROR_BAD_PARAMETERS;
	if (key_len != 16 && key_len != 24 && key_len != 32)
		return TEE_ERROR_BAD_PARAMETERS;
	if (expanded_key_len < AES_EXPANDED_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	rounds = 10 + ((key_len / 8) - 2) * 2;
	memset(enc_key, 0, expanded_key_len);
	memcpy(enc_key, key, key_len);
	expand_enc_key(enc_key, key_len);
	if (dec_key)
		memcpy(dec_key, enc_key, expanded_key_len);
	*round_count = rounds;

	return TEE_SUCCESS;
}

static unsigned int key_len_from_round_count(unsigned int round_count)
{
	switch (round_count) {
	case 10:
		return 16;
	case 12:
		return 24;
	case 14:
		return 32;
	default:
		return 0;
	}
}

static void make_linux_key(struct riscv_aes_key *dst, const void *src,
			   unsigned int round_count)
{
	memset(dst, 0, sizeof(*dst));
	memcpy(dst->enc_key, src, sizeof(dst->enc_key));
	dst->key_len = key_len_from_round_count(round_count);
}

static void aes_xts_crypt(void *out, const void *in, const void *key1,
			  unsigned int round_count, unsigned int block_count,
			  const void *key2, void *tweak, bool decrypt)
{
	struct riscv_aes_key data_key = { };
	struct riscv_aes_key tweak_key = { };
	const struct riscv_aes_key *key = &data_key;
	size_t len = block_count * TEE_AES_BLOCK_SIZE;
	uint32_t vfp_state = 0;

	assert(out && in && key1 && key2 && tweak);
	assert(block_count);
	make_linux_key(&data_key, key1, round_count);
	make_linux_key(&tweak_key, key2, round_count);
	assert(data_key.key_len);

	vfp_state = thread_kernel_enable_vfp();
	aes_ecb_encrypt_zvkned(&tweak_key, tweak, tweak, TEE_AES_BLOCK_SIZE);
	if (decrypt)
		aes_xts_decrypt_zvkned_zvbb_zvkg(key, in, out, len, tweak);
	else
		aes_xts_encrypt_zvkned_zvbb_zvkg(key, in, out, len, tweak);
	thread_kernel_disable_vfp(vfp_state);
}

void crypto_accel_aes_xts_enc(void *out, const void *in, const void *key1,
			      unsigned int round_count,
			      unsigned int block_count,
			      const void *key2, void *tweak)
{
	aes_xts_crypt(out, in, key1, round_count, block_count, key2, tweak,
		      false);
}

void crypto_accel_aes_xts_dec(void *out, const void *in, const void *key1,
			      unsigned int round_count,
			      unsigned int block_count,
			      const void *key2, void *tweak)
{
	aes_xts_crypt(out, in, key1, round_count, block_count, key2, tweak,
		      true);
}

#ifdef CFG_RISCV_ZVKNG
TEE_Result crypto_riscv_zvkng_aes_kat(void);

static TEE_Result test_aes_expand_key(const uint8_t *key, size_t key_len,
				      const uint8_t *last_round_key)
{
	uint8_t enc_key[15][TEE_AES_BLOCK_SIZE] = { };
	uint8_t dec_key[15][TEE_AES_BLOCK_SIZE] = { };
	unsigned int rounds = 0;
	TEE_Result res = TEE_SUCCESS;

	res = crypto_accel_aes_expand_keys(key, key_len, enc_key, dec_key,
					   sizeof(enc_key), &rounds);
	if (res)
		return res;
	if (memcmp(enc_key[rounds], last_round_key, TEE_AES_BLOCK_SIZE) ||
	    memcmp(dec_key[rounds], last_round_key, TEE_AES_BLOCK_SIZE) ||
	    memcmp(dec_key[0], key, TEE_AES_BLOCK_SIZE))
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}

static TEE_Result test_aes_xts(void)
{
	static const uint8_t key[TEE_AES_BLOCK_SIZE] = { };
	static const uint8_t expected_ct[2 * TEE_AES_BLOCK_SIZE] = {
		0x91, 0x7c, 0xf6, 0x9e, 0xbd, 0x68, 0xb2, 0xec,
		0x9b, 0x9f, 0xe9, 0xa3, 0xea, 0xdd, 0xa6, 0x92,
		0xcd, 0x43, 0xd2, 0xf5, 0x95, 0x98, 0xed, 0x85,
		0x8c, 0x02, 0xc2, 0x65, 0x2f, 0xbf, 0x92, 0x2e,
	};
	static const uint8_t expected_tweak[TEE_AES_BLOCK_SIZE] = {
		0x98, 0xa5, 0x2f, 0x51, 0xbf, 0x2b, 0xb2, 0xec,
		0x20, 0x32, 0xe9, 0x67, 0x29, 0xd3, 0xac, 0xb8,
	};
	uint8_t enc_key1[15][TEE_AES_BLOCK_SIZE] = { };
	uint8_t dec_key1[15][TEE_AES_BLOCK_SIZE] = { };
	uint8_t enc_key2[15][TEE_AES_BLOCK_SIZE] = { };
	uint8_t plaintext[sizeof(expected_ct)] = { };
	uint8_t ciphertext[sizeof(expected_ct)] = { };
	uint8_t output[sizeof(expected_ct)] = { };
	uint8_t tweak[TEE_AES_BLOCK_SIZE] = { };
	unsigned int rounds = 0;
	TEE_Result res = TEE_SUCCESS;

	res = crypto_accel_aes_expand_keys(key, sizeof(key), enc_key1, dec_key1,
					   sizeof(enc_key1), &rounds);
	if (res)
		return res;
	res = crypto_accel_aes_expand_keys(key, sizeof(key), enc_key2, NULL,
					   sizeof(enc_key2), &rounds);
	if (res)
		return res;

	crypto_accel_aes_xts_enc(ciphertext, plaintext, enc_key1, rounds, 2,
			 enc_key2, tweak);
	if (memcmp(ciphertext, expected_ct, sizeof(ciphertext)) ||
	    memcmp(tweak, expected_tweak, sizeof(tweak)))
		return TEE_ERROR_SECURITY;

	memset(tweak, 0, sizeof(tweak));
	crypto_accel_aes_xts_dec(output, ciphertext, dec_key1, rounds, 2,
			 enc_key2, tweak);
	if (memcmp(output, plaintext, sizeof(output)) ||
	    memcmp(tweak, expected_tweak, sizeof(tweak)))
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}

TEE_Result crypto_riscv_zvkng_aes_kat(void)
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
	if (!res)
		res = test_aes_xts();
	if (res)
		EMSG("AES key expansion/XTS KAT failed: %#" PRIx32, res);
	else
		IMSG("AES key expansion/XTS KAT passed");

	return res;
}
#endif
