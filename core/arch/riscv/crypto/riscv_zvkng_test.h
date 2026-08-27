/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#ifndef __RISCV_ZVKNG_TEST_H
#define __RISCV_ZVKNG_TEST_H

#include <types_ext.h>

unsigned long riscv_zvkng_test_vector_enable(void);
void riscv_zvkng_test_vector_disable(unsigned long xstatus);

#endif /* __RISCV_ZVKNG_TEST_H */
