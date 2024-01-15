/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) Anlogic Corporation or its affiliates.
 *
 */

#include <libfdt.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_io.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_const.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_math.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_timer.h>
#include <dr1v90_uart.h>
#include <sbi_utils/fdt/fdt_fixup.h>
#include <sbi_utils/irqchip/plic.h>
#include <sbi_utils/sys/clint.h>

#include <board_cfg.h>
#include "hardware.h"

/* clang-format off */

#define DR1V90_HART_COUNT		1

/* dr1v90 timer base address */
#define DR1V90_DR1V90_TIMER_ADDR  0x68030000
#define DR1V90_DR1V90_TIMER_MSFTRST_OFS	0xFF0
#define DR1V90_DR1V90_TIMER_CTL_OFS	0xFF8
#define DR1V90_DR1V90_TIMER_MSFTRST_KEY	0x80000A5F
/* The clint compatiable timer offset is 0x1000 against dr1v90 timer */
#define DR1V90_CLINT_TIMER_ADDR		(DR1V90_DR1V90_TIMER_ADDR + 0x1000)

#define DR1V90_PLIC_ADDR	0x6c000000    /*	0x8000000*/
#define DR1V90_PLIC_NUM_SOURCES		0x35
#define DR1V90_PLIC_NUM_PRIORITIES	7


#ifndef __RISCV_XLEN
  /** \brief Refer to the width of an integer register in bits(either 32 or 64) */
  #ifndef __riscv_xlen
    #define __RISCV_XLEN    32
  #else
    #define __RISCV_XLEN    __riscv_xlen
  #endif
#endif /* __RISCV_XLEN */

/** \brief Type of Control and Status Register(CSR), depends on the XLEN defined in RISC-V */
#if __RISCV_XLEN == 32
  typedef uint32_t rv_csr_t;
#elif __RISCV_XLEN == 64
  typedef uint64_t rv_csr_t;
#else
  typedef uint32_t rv_csr_t;
#endif

#ifndef   __ASM
  #define __ASM                                  __asm
#endif


#define __RV_CSR_CLEAR(csr, val)                                \
    ({                                                          \
        register rv_csr_t __v = (rv_csr_t)(val);                \
        __ASM volatile("csrc " STRINGIFY(csr) ", %0"            \
                     :                                          \
                     : "rK"(__v)                                \
                     : "memory");                               \
    })


#define CSR_MNOCB		0x7F5
#define CSR_MNOCM		0x7F6
#define CSR_MCACHE_CTL		0x7CA
#define CSR_CCM_SUEN		0x7CE
#define CSR_MMISC_CTL           0x7D0

#define CCM_SUEN_ENABLE		0x03030303
#define CSR_CACHE_ENABLE	0x100C1

#define AL_EXT_FPGA		(SBI_EXT_VENDOR_START+0)
#define AL_EXT_NCACHE		(SBI_EXT_VENDOR_START+1)
#define AL_EXT_NCACHE_SET	0
#define AL_EXT_NCACHE_CLR	1

#define ROOT_FW_REGION		0
#define ROOT_DDR_REGION		1
#define ROOT_ALL_REGION		2
#define ROOT_END_REGION		3
static struct sbi_domain_memregion root_memregs[ROOT_END_REGION + 1] = { 0 };

/* clang-format on */

static struct plic_data plic = {
	.addr = DR1V90_PLIC_ADDR,
	.num_src = DR1V90_PLIC_NUM_SOURCES,
};

static struct clint_data clint = {
	.addr = DR1V90_CLINT_TIMER_ADDR,
	.first_hartid = 0,
	.hart_count = DR1V90_HART_COUNT,
	.has_64bit_mmio = TRUE,
};

unsigned long fw_platform_init(unsigned long arg0, unsigned long arg1,
				unsigned long arg2, unsigned long arg3,
				unsigned long arg4)
{
	void *mtimectl = (void *)(DR1V90_DR1V90_TIMER_ADDR+DR1V90_DR1V90_TIMER_CTL_OFS);
	u32 value;
	value = readl(mtimectl);
	writel(value | 0x4, mtimectl);
	csr_write(CSR_MCACHE_CTL, CSR_CACHE_ENABLE);
	//Enable S/U mode CCM operation
	csr_write(CSR_CCM_SUEN, CCM_SUEN_ENABLE);
	return arg1;
}

static int dr1v90_early_init(bool cold_boot)
{
	dr1v90_uart_init(DR1V90_UART, uart_clock, uart_baud, UART_BIT_LENGTH_8);
	dr1v90_uart_config_stopbit(DR1V90_UART,DR1V90_UART_STOP_BIT_1);
	dr1v90_uart_fifo_enable(DR1V90_UART);

	return 0;
}

static void dr1v90_modify_dt(void *fdt)
{
	fdt_fixups(fdt);
}

static int dr1v90_final_init(bool cold_boot)
{
	void *fdt;

	if (!cold_boot)
		return 0;

	fdt = sbi_scratch_thishart_arg1_ptr();
	dr1v90_modify_dt(fdt);

	// Enable U-Mode to access all regions by setting spmpcfg0 and spmpaddr0
	csr_write(0x1a0, 0x1f);  //sbi_trap_error
	csr_write(0x1b0, 0xffffffff);
	csr_write(0x7ce, 0xffffffff);
	sbi_printf("micfg_info                : 0x%lx\r\n", csr_read(0xfc0));
	sbi_printf("mdcfg_info                : 0x%lx\r\n", csr_read(0xfc1));
	sbi_printf("mcfg_info                 : 0x%lx\r\n", csr_read(0xfc2));
	sbi_printf("misa                      : 0x%lx\r\n", csr_read(0x301));

	return 0;
}

static int dr1v90_console_init(void)
{
	return dr1v90_uart_init(DR1V90_UART, uart_clock, uart_baud, UART_BIT_LENGTH_8);
}

static void dr1v90_console_write(char val)
{
	dr1v90_uart_write(DR1V90_UART, val);
}

static int dr1v90_console_read(void)
{
	return dr1v90_uart_read(DR1V90_UART);
}

static int dr1v90_irqchip_init(bool cold_boot)
{
	int rc;
	u32 hartid = current_hartid();

	if (cold_boot) {
		rc = plic_cold_irqchip_init(&plic);
		if (rc)
			return rc;
	}

	return plic_warm_irqchip_init(&plic, 2 * hartid, 2 * hartid + 1);
}

static int dr1v90_ipi_init(bool cold_boot)
{
	int rc;

	if (cold_boot) {
		rc = clint_cold_ipi_init(&clint);
		if (rc)
			return rc;
	}

	return clint_warm_ipi_init();
}

static int dr1v90_timer_init(bool cold_boot)
{
	int rc;

	if (cold_boot) {
		rc = clint_cold_timer_init(&clint, NULL);
		if (rc)
			return rc;
	}

	return clint_warm_timer_init();
}

static int dr1v90_system_reset_check(u32 type, u32 reason)
{
	if (type == SBI_SRST_RESET_TYPE_COLD_REBOOT ||
	    type == SBI_SRST_RESET_TYPE_WARM_REBOOT)
		return 1;
	else
		return 0;
}

static void dr1v90_system_reset(u32 type, u32 reason)
{
	/* Reset system using MSFTRST register in Dr1v90 Timer. */
	//writel(DR1V90_DR1V90_TIMER_MSFTRST_KEY, (void *)(DR1V90_DR1V90_TIMER_ADDR
	//				+ DR1V90_DR1V90_TIMER_MSFTRST_OFS));
	u32 reg_val;
	if (type == SBI_SRST_RESET_TYPE_COLD_REBOOT ||
	    type == SBI_SRST_RESET_TYPE_WARM_REBOOT) {
		reg_val = readl((void*)SYSCTRL_S_GLOBAL_SRSTN);
		reg_val &= (u32)~SYSCTRL_S_GLOBAL_SRSTN_MSK_GLB_SRST;
		writel((u32)reg_val, (void*)SYSCTRL_S_GLOBAL_SRSTN);
	} else {
		sbi_printf("sbi: not supported reset type\n");
	}
	while(1)
		wfi();
}

void platform_udelay(unsigned long usec)
{
	u64 tmp;
	tmp = sbi_timer_value() + ((usec * TIMER_CLOCK_RATE)/1000000);
	while (sbi_timer_value() < (tmp+1))
		;
}

extern int dr1v90_fpga_prog(long funcid,
		   const struct sbi_trap_regs *regs,
		   unsigned long *out_value,
		   struct sbi_trap_info *out_trap);
static int dr1v90_ext_provider(long extid, long funcid,
			   const struct sbi_trap_regs *regs,
			   unsigned long *out_value,
			   struct sbi_trap_info *out_trap)
{
	if (extid == AL_EXT_FPGA) {
		return dr1v90_fpga_prog(funcid, regs, out_value, out_trap);
	} else if (extid == AL_EXT_NCACHE) {
		if (funcid == AL_EXT_NCACHE_SET) {
			csr_write(CSR_MNOCB, 0);
			csr_write(CSR_MNOCM, regs->a1&0xFFFFFFFC);
			csr_write(CSR_MNOCB, (regs->a0&0xFFFFFFFC)|1);
			return 0;
		} else if (funcid == AL_EXT_NCACHE_CLR) {
			csr_write(CSR_MNOCB, 0);
			csr_write(CSR_MNOCM, 0);
			return 0;
		}
	}
	return SBI_ENOTSUPP;
}

static struct sbi_domain_memregion *dr1v90_root_regions(void)
{
	u32 hartid = current_hartid();
	struct sbi_scratch *scratch = sbi_hartid_to_scratch(hartid);

	if (!scratch)
		return NULL;

	/* Root domain firmware memory region */
	root_memregs[ROOT_FW_REGION].order = log2roundup(scratch->fw_size);
	root_memregs[ROOT_FW_REGION].base = scratch->fw_start &
				~((1UL << root_memregs[0].order) - 1UL);
	root_memregs[ROOT_FW_REGION].flags = 0;

	/* Root domain ddr region */
	root_memregs[ROOT_DDR_REGION].order = log2roundup(DDR_SIZE);
	root_memregs[ROOT_DDR_REGION].base = DDR_BASE;
	root_memregs[ROOT_DDR_REGION].flags = (SBI_DOMAIN_MEMREGION_READABLE |
						SBI_DOMAIN_MEMREGION_WRITEABLE |
						SBI_DOMAIN_MEMREGION_EXECUTABLE |
						SBI_DOMAIN_MEMREGION_MMODE);

	/* Root domain allow everything memory region */
	root_memregs[ROOT_ALL_REGION].order = __riscv_xlen;
	root_memregs[ROOT_ALL_REGION].base = 0;
	root_memregs[ROOT_ALL_REGION].flags = (SBI_DOMAIN_MEMREGION_READABLE |
						SBI_DOMAIN_MEMREGION_WRITEABLE |
						SBI_DOMAIN_MEMREGION_MMODE);

	/* Root domain memory region end */
	root_memregs[ROOT_END_REGION].order = 0;

	return root_memregs;
}

const struct sbi_platform_operations platform_ops = {
	.early_init		= dr1v90_early_init,
	.final_init		= dr1v90_final_init,
	.console_putc		= dr1v90_console_write,
	.console_getc		= dr1v90_console_read,
	.console_init		= dr1v90_console_init,
	.irqchip_init		= dr1v90_irqchip_init,
	.ipi_send		= clint_ipi_send,
	.ipi_clear		= clint_ipi_clear,
	.ipi_init		= dr1v90_ipi_init,
	.timer_value		= clint_timer_value,
	.timer_event_stop	= clint_timer_event_stop,
	.timer_event_start	= clint_timer_event_start,
	.timer_init		= dr1v90_timer_init,
	.system_reset_check	= dr1v90_system_reset_check,
	.system_reset		= dr1v90_system_reset,
	.vendor_ext_provider	= dr1v90_ext_provider,
	.domains_root_regions	= dr1v90_root_regions,
};

const struct sbi_platform platform = {
	.opensbi_version	= OPENSBI_VERSION,
	.platform_version	= SBI_PLATFORM_VERSION(0x0U, 0x01U),
	.name			= "Anlogic DR1V90",
	.features		= SBI_PLATFORM_DEFAULT_FEATURES,
	.hart_count		= DR1V90_HART_COUNT,
	.hart_stack_size	= SBI_PLATFORM_DEFAULT_HART_STACK_SIZE,
	.platform_ops_addr	= (unsigned long)&platform_ops
};
