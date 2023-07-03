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
#include <dr1v90_uart.h>
#include <sbi_utils/fdt/fdt_fixup.h>
#include <sbi_utils/irqchip/plic.h>
#include <sbi_utils/timer/core_feature_timer.h>

#include <sbi_utils/sys/clint.h>

/* clang-format off */

#define DR1V90_HART_COUNT		1
#define DR1V90_TIMER_FREQ		50000000/*32768 ian fang*/

/* dr1v90 timer base address */
#define DR1V90_DR1V90_TIMER_ADDR  0x68030000	/*0x2000000 ian fang*/
#define DR1V90_DR1V90_TIMER_MSFTRST_OFS	0xFF0
#define DR1V90_DR1V90_TIMER_MSFTRST_KEY	0x80000A5F
/* The clint compatiable timer offset is 0x1000 against dr1v90 timer */
#define DR1V90_CLINT_TIMER_ADDR		(DR1V90_DR1V90_TIMER_ADDR + 0x1000)

#define DR1V90_PLIC_ADDR	0x6c000000    /*	0x8000000*/
#define DR1V90_PLIC_NUM_SOURCES		0x35
#define DR1V90_PLIC_NUM_PRIORITIES	7

#define DR1V90_UART0_ADDR	  0xF8400000  /*	0x10013000 ianfang*/
#define DR1V90_UART1_ADDR		0xF8401000    /*0x10023000*/


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


/* clang-format on */
static u32 dr1v90_clk_freq = 2500000 ; /*16000000; ian fang */

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

static int dr1v90_early_init(bool cold_boot)
{
	dr1v90_clk_freq =50000000;

	*(uint32_t *)(0xf8803068u) =0x3;    //uart0  MIO26/27
	*(uint32_t *)(0xf880306cu) =0x3;
	*(uint32_t *)(0xf8803410u) =0x1;

	*(uint32_t *)(0xf8803070u) =0xe;     //rgmii1 mio 28-39
	*(uint32_t *)(0xf8803074u) =0xe;
	*(uint32_t *)(0xf8803078u) =0xe;
	*(uint32_t *)(0xf880307cu) =0xe;
	*(uint32_t *)(0xf8803080u) =0xe;
	*(uint32_t *)(0xf8803084u) =0xe;
	*(uint32_t *)(0xf8803088u) =0xe;
	*(uint32_t *)(0xf880308cu) =0xe;
	*(uint32_t *)(0xf8803090u) =0xe;
	*(uint32_t *)(0xf8803094u) =0xe;
	*(uint32_t *)(0xf8803098u) =0xe;
	*(uint32_t *)(0xf880309cu) =0xe;
	*(uint32_t *)(0xf88030d0u) =0xf;      //mdc1   MIO52-53
	*(uint32_t *)(0xf88030d4u) =0xf;      //mdio1
	*(uint32_t *)(0xf8803438u) =0x1;      //emio_sel

	dr1v90_uart_init(DR1V90_UART0,115200,UART_BIT_LENGTH_8);
	dr1v90_uart_config_stopbit(DR1V90_UART0,DR1V90_UART_STOP_BIT_1);
	dr1v90_uart_fifo_enable(DR1V90_UART0);

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
	sbi_printf("modify dt before 1  %p %d\n",(unsigned long *)fdt,dr1v90_clk_freq);
	dr1v90_modify_dt(fdt);
	// Enable U-Mode to access all regions by setting spmpcfg0 and spmpaddr0
	csr_write(0x1a0, 0x1f);  //   ian fang20220125 sbi_trap_error
	csr_write(0x1b0, 0xffffffff);
	csr_write(0x7ce, 0xffffffff);
	sbi_printf("micfg_info : 0x%lx\r\n", csr_read(0xfc0));
	sbi_printf("mdcfg_info : 0x%lx\r\n", csr_read(0xfc1));
	sbi_printf("mcfg_info : 0x%lx\r\n", csr_read(0xfc2));
	sbi_printf("misa : 0x%lx\r\n", csr_read(0x301));

	return 0;
}

static int dr1v90_console_init(void)
{
	return dr1v90_uart_init(DR1V90_UART0,115200,UART_BIT_LENGTH_8);
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
	return 1;
}

static void dr1v90_system_reset(u32 type, u32 reason)
{
	/* Reset system using MSFTRST register in Dr1v90 Timer. */
	writel(DR1V90_DR1V90_TIMER_MSFTRST_KEY, (void *)(DR1V90_DR1V90_TIMER_ADDR
					+ DR1V90_DR1V90_TIMER_MSFTRST_OFS));
	while(1);
}

const struct sbi_platform_operations platform_ops = {
	.early_init		= dr1v90_early_init,
	.final_init		= dr1v90_final_init,
	.console_putc		= dr1v90_uart_write,
	.console_getc		= dr1v90_uart_read,
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
	.system_reset		= dr1v90_system_reset
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
