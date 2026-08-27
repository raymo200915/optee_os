# SPDX-License-Identifier: BSD-2-Clause
#
# RISC-V crypto_drv implementations are added here as they become available.
#
# The generic crypto library selects these only via CFG_CORE_CRYPTO_*_ACCEL.
# Keep the source selection per algorithm, so a disabled accelerator continues
# to use the libtomcrypt software implementation.
#
srcs-$(call cfg-one-enabled,CFG_CORE_CRYPTO_SHA256_ACCEL CFG_RISCV_TEST_SHA2_KAT) += sha256_riscv_zvkng_glue.c
srcs-$(call cfg-one-enabled,CFG_CORE_CRYPTO_SHA256_ACCEL CFG_RISCV_TEST_SHA2_KAT) += sha256-riscv64-zvknha_or_zvknhb-zvkb.S
srcs-$(call cfg-one-enabled,CFG_CORE_CRYPTO_SHA512_ACCEL CFG_RISCV_TEST_SHA2_KAT) += sha512_riscv_zvkng_glue.c
srcs-$(call cfg-one-enabled,CFG_CORE_CRYPTO_SHA512_ACCEL CFG_RISCV_TEST_SHA2_KAT) += sha512-riscv64-zvknhb-zvkb.S
srcs-$(CFG_RISCV_TEST_SHA2_KAT) += riscv_zvkng_test.c
srcs-$(CFG_RISCV_TEST_SHA2_KAT) += sha2_riscv_zvkng_kat.c

# The generic crypto library selects the AES implementation via this option.
# The temporary AES KAT selects it explicitly until CFG_CORE_CRYPTO_AES_ACCEL
# provides every libtomcrypt AES entry point.
srcs-$(call cfg-one-enabled,CFG_CORE_CRYPTO_AES_ACCEL CFG_RISCV_TEST_AES_KAT) += aes_riscv_zvkng_glue.c
srcs-$(call cfg-one-enabled,CFG_CORE_CRYPTO_AES_ACCEL CFG_RISCV_TEST_AES_KAT) += aes-riscv64-zvkned.S
srcs-$(call cfg-one-enabled,CFG_CORE_CRYPTO_AES_ACCEL CFG_RISCV_TEST_AES_KAT) += aes-riscv64-zvkned-zvkb.S
srcs-$(call cfg-one-enabled,CFG_CORE_CRYPTO_AES_ACCEL CFG_RISCV_TEST_AES_KAT) += aes-riscv64-zvkned-zvbb-zvkg.S
