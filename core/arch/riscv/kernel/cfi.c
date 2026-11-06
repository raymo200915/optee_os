// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 NXP
 */

#include <config.h>
#include <encoding.h>
#include <kernel/cfi.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <riscv.h>
#include <sbi.h>
#include <trace.h>

/* Set by the primary hart, every secondary must agree */
static bool lp_available;
static bool ss_available;

/*
 * FWFT LANDING_PAD controls menvcfg.LPE for the calling S-mode domain.
 * It enables landing-pad enforcement in S-mode and makes senvcfg.LPE
 * writable for the per-user-context policy. It is hart-local, so this
 * runs on every OP-TEE hart during boot.
 */
static bool enable_landing_pads(void)
{
	bool available = false;
	unsigned long value = 0;
	int rc = SBI_SUCCESS;

	/* menvcfg.LPE enforces S-mode too, so the core must be protected. */
	if (!IS_ENABLED(CFG_CORE_ZICFILP))
		return false;

	rc = sbi_fwft_set(SBI_FWFT_LANDING_PAD, 1, 0);
	if (rc) {
		if (rc != SBI_ERR_NOT_SUPPORTED)
			EMSG("SBI FWFT landing-pad enable failed: %d", rc);
		return false;
	}

	rc = sbi_fwft_get(SBI_FWFT_LANDING_PAD, &value);
	if (rc || value != 1) {
		if (rc)
			EMSG("SBI FWFT landing-pad query failed: %d", rc);
		return false;
	}

	if (IS_ENABLED(CFG_TA_ZICFILP)) {
		set_csr(CSR_SENVCFG, CSR_SENVCFG_LPE);
		available = read_csr(CSR_SENVCFG) & CSR_SENVCFG_LPE;
		clear_csr(CSR_SENVCFG, CSR_SENVCFG_LPE);
	} else {
		available = true;
	}

	return available;
}

/*
 * senvcfg.SSE is read-only zero and the ssp CSR traps from S-mode until
 * the M-mode firmware sets menvcfg.SSE. SBI FWFT is the ratified way to
 * ask for it, per hart. Confirm through senvcfg that the request took
 * effect rather than trusting the return code alone.
 */
static bool enable_shadow_stacks(void)
{
	bool available = false;
	int rc = SBI_SUCCESS;

	if (!IS_ENABLED(CFG_TA_ZICFISS))
		return false;

	rc = sbi_fwft_set(SBI_FWFT_SHADOW_STACK, 1, 0);
	if (rc) {
		if (rc != SBI_ERR_NOT_SUPPORTED)
			EMSG("SBI FWFT shadow stack enable failed: %d", rc);
		return false;
	}

	set_csr(CSR_SENVCFG, CSR_SENVCFG_SSE);
	available = read_csr(CSR_SENVCFG) & CSR_SENVCFG_SSE;
	clear_csr(CSR_SENVCFG, CSR_SENVCFG_SSE);

	return available;
}

#ifdef CFG_TA_ZICFISS
bool cfi_shadow_stack_enabled(void)
{
	return ss_available;
}
#endif

void cfi_init_hart(void)
{
	bool lp = enable_landing_pads();
	bool ss = enable_shadow_stacks();

	if (get_core_pos() == 0) {
		lp_available = lp;
		ss_available = ss;
		if (IS_ENABLED(CFG_CORE_ZICFILP) || IS_ENABLED(CFG_TA_ZICFILP))
			IMSG("Zicfilp landing pads: %s",
			     lp ? "enabled" : "not available");
		if (IS_ENABLED(CFG_TA_ZICFISS))
			IMSG("Zicfiss shadow stacks for user mode: %s",
			     ss ? "enabled" : "not available");
	} else if (lp != lp_available || ss != ss_available) {
		EMSG("CFI extension availability differs between harts");
		panic();
	}

	if (IS_ENABLED(CFG_CORE_ZICFILP) && !lp)
		panic();
}
