// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCstar Solutions Corporation
 */

#include "riscv_zvkng_test.h"

#include <riscv.h>

unsigned long riscv_zvkng_test_vector_enable(void)
{
	unsigned long xstatus = read_csr(CSR_XSTATUS);
	unsigned long new_xstatus = xstatus & ~CSR_XSTATUS_VS_MASK;

	new_xstatus |= CSR_XSTATUS_VS_INITIAL << CSR_XSTATUS_VS_BIT;
	write_csr(CSR_XSTATUS, new_xstatus);

	return xstatus;
}

void riscv_zvkng_test_vector_disable(unsigned long xstatus)
{
	write_csr(CSR_XSTATUS, xstatus);
}
