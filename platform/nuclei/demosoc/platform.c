/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) Nuclei Corporation or its affiliates.
 *
 * Authors:
 *   lujun <lujun@nucleisys.com>
 *   hqfang <hqfang@nucleisys.com>
 */

#include <libfdt.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_io.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_const.h>
#include <sbi/sbi_platform.h>
#include <sbi_utils/fdt/fdt_fixup.h>
#include <sbi_utils/irqchip/plic.h>
/*#include <sbi_utils/serial/sifive-uart.h>*/
#include <sbi_utils/serial/al9000_uart.h>
/*#include <sbi_utils/serial/demosoc.h>*/
#include <sbi_utils/timer/core_feature_timer.h>

#include <sbi_utils/sys/clint.h>

/* clang-format off */

#define NUCLEI_HART_COUNT		1
#define NUCLEI_TIMER_FREQ		50000000/*32768 ian fang*/

/* Nuclei timer base address */
#define NUCLEI_NUCLEI_TIMER_ADDR  0x68030000	/*0x2000000 ian fang*/
#define NUCLEI_NUCLEI_TIMER_MSFTRST_OFS	0xFF0
#define NUCLEI_NUCLEI_TIMER_MSFTRST_KEY	0x80000A5F
/* The clint compatiable timer offset is 0x1000 against nuclei timer */
#define NUCLEI_CLINT_TIMER_ADDR		(NUCLEI_NUCLEI_TIMER_ADDR + 0x1000)

#define NUCLEI_PLIC_ADDR	0x6c000000    /*	0x8000000*/
#define NUCLEI_PLIC_NUM_SOURCES		0x35
#define NUCLEI_PLIC_NUM_PRIORITIES	7

#define NUCLEI_UART0_ADDR	  0xF8400000  /*	0x10013000 ianfang*/
#define NUCLEI_UART1_ADDR		0xF8401000    /*0x10023000*/

#define NUCLEI_DEBUG_UART		NUCLEI_UART0_ADDR

#ifndef NUCLEI_UART_BAUDRATE
#define NUCLEI_UART_BAUDRATE		115200
#endif

#define NUCLEI_GPIO_ADDR	     0xF8411000   /*	0x10012000*/
#define NUCLEI_GPIO_INPUT_EN_OFS	0x4
#define NUCLEI_GPIO_OUTPUT_EN_OFS	0x8
#define NUCLEI_GPIO_IOF_EN_OFS		0x38
#define NUCLEI_GPIO_IOF_SEL_OFS		0x3C

#define NUCLEI_GPIO_IOF_UART0_MASK	0x00030000
#define NUCLEI_GPIO_IOF_UART1_MASK	0x03000000
#define NUCLEI_GPIO_IOF_QSPI2_MASK	0xFC000000

#define NUCLEI_GPIO_INPUT_EN_UART0_MASK	0x00010000
#define NUCLEI_GPIO_INPUT_EN_UART1_MASK	0x01000000
#define NUCLEI_GPIO_INPUT_EN_QSPI2_MASK	0x10000000

#define NUCLEI_GPIO_OUTPUT_EN_UART0_MASK	0x00020000
#define NUCLEI_GPIO_OUTPUT_EN_UART1_MASK	0x02000000
#define NUCLEI_GPIO_OUTPUT_EN_QSPI2_MASK	0xEC000000

/* UART0, UART1, QSPI2 pinmux selected */
#define NUCLEI_GPIO_IOF_MASK		(NUCLEI_GPIO_IOF_UART0_MASK | \
	NUCLEI_GPIO_IOF_UART1_MASK | NUCLEI_GPIO_IOF_QSPI2_MASK)

#define NUCLEI_GPIO_INPUT_EN_MASK	(NUCLEI_GPIO_INPUT_EN_UART0_MASK | \
	NUCLEI_GPIO_INPUT_EN_UART1_MASK | NUCLEI_GPIO_INPUT_EN_QSPI2_MASK)

#define NUCLEI_GPIO_OUTPUT_EN_MASK	(NUCLEI_GPIO_OUTPUT_EN_UART0_MASK | \
	NUCLEI_GPIO_OUTPUT_EN_UART1_MASK | NUCLEI_GPIO_OUTPUT_EN_QSPI2_MASK)

#define NUCLEI_TIMER_VALUE()		readl((void *)NUCLEI_NUCLEI_TIMER_ADDR)
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
static u32 nuclei_clk_freq = 2500000 ; /*16000000; ian fang */

static struct plic_data plic = {
	.addr = NUCLEI_PLIC_ADDR,
	.num_src = NUCLEI_PLIC_NUM_SOURCES,
};

static struct clint_data clint = {
	.addr = NUCLEI_CLINT_TIMER_ADDR,
	.first_hartid = 0,
	.hart_count = NUCLEI_HART_COUNT,
	.has_64bit_mmio = TRUE,
};

//static u32 measure_cpu_freq(u32 n)
//{
//	u32 start_mtime, delta_mtime;
//	u32 mtime_freq = NUCLEI_TIMER_FREQ;
//	u32 tmp = (u32)NUCLEI_TIMER_VALUE();
//	u32 start_mcycle, delta_mcycle, freq;

	/* Don't start measuring until we see an mtime tick */
//	do {
//		start_mtime = (u32)NUCLEI_TIMER_VALUE();
//	} while (start_mtime == tmp);

//	start_mcycle = csr_read(mcycle);

//	do {
//		delta_mtime = (u32)NUCLEI_TIMER_VALUE() - start_mtime;
//	} while (delta_mtime < n);

//	delta_mcycle = csr_read(mcycle) - start_mcycle;

//	freq = (delta_mcycle / delta_mtime) * mtime_freq
//		+ ((delta_mcycle % delta_mtime) * mtime_freq) / delta_mtime;

//	return freq;
//}

//static u32 nuclei_get_clk_freq(void)
//{
//	u32 cpu_freq;

	/* warm up */
//	measure_cpu_freq(1);
	/* measure for real */
//	cpu_freq = measure_cpu_freq(100);

//	return cpu_freq;
//}
//extern void SysTimer_clk_sel(void);
static int nuclei_early_init(bool cold_boot)
{
	/*u32 regval;*/
  /*---------------ian fang------------------------------*/
  //SysTimer_clk_sel();


  //__RV_CSR_CLEAR(0x7D0,(1<<3));

	/* Measure CPU frequency using timer */
	nuclei_clk_freq =50000000;//nuclei_get_clk_freq();

  /*uart initial*/
 /* __RV_CSR_CLEAR(0x7D0,(1<<3));*/


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



        AL9000_uart_init(AL9000_UART0,115200,UART_BIT_LENGTH_8);
	AL9000_uart_config_stopbit(AL9000_UART0,AL9000_UART_STOP_BIT_1);
	AL9000_uart_fifo_enable(AL9000_UART0);


	/* Init GPIO pinmux set by NUCLEI_GPIO_IOF_MASK */
/*ianfang	regval = readl((void *)(NUCLEI_GPIO_ADDR + NUCLEI_GPIO_IOF_SEL_OFS)) &
		~NUCLEI_GPIO_IOF_MASK;
	writel(regval, (void *)(NUCLEI_GPIO_ADDR + NUCLEI_GPIO_IOF_SEL_OFS));
	regval = readl((void *)(NUCLEI_GPIO_ADDR + NUCLEI_GPIO_IOF_EN_OFS)) |
		NUCLEI_GPIO_IOF_MASK;
	writel(regval, (void *)(NUCLEI_GPIO_ADDR + NUCLEI_GPIO_IOF_EN_OFS));
*/
	/*
	 * Init GPIO input/output direction by
	 * NUCLEI_GPIO_INPUT_EN_MASK and NUCLEI_GPIO_OUTPUT_EN_MASK
	 */
/*ianfang	regval = readl((void *)(NUCLEI_GPIO_ADDR + NUCLEI_GPIO_INPUT_EN_OFS)) |
		NUCLEI_GPIO_INPUT_EN_MASK;
	writel(regval, (void *)(NUCLEI_GPIO_ADDR + NUCLEI_GPIO_INPUT_EN_OFS));
	regval = readl((void *)(NUCLEI_GPIO_ADDR + NUCLEI_GPIO_OUTPUT_EN_OFS)) |
		NUCLEI_GPIO_OUTPUT_EN_MASK;
	writel(regval, (void *)(NUCLEI_GPIO_ADDR + NUCLEI_GPIO_OUTPUT_EN_OFS));
*/
	return 0;
}

static void nuclei_modify_dt(void *fdt)
{
	fdt_fixups(fdt);
}

static int nuclei_final_init(bool cold_boot)
{
	void *fdt;

	if (!cold_boot)
		return 0;

	fdt = sbi_scratch_thishart_arg1_ptr();
	sbi_printf("modify dt before 1  %p %d\n",(unsigned long *)fdt,nuclei_clk_freq);
  nuclei_modify_dt(fdt);
   // Enable U-Mode to access all regions by setting spmpcfg0 and spmpaddr0
    csr_write(0x1a0, 0x1f);  //   ian fang20220125 sbi_trap_error
    csr_write(0x1b0, 0xffffffff);
	csr_write(0x7ce, 0xffffffff);
	sbi_printf("micfg_info : 0x%lx\r\n", csr_read(0xfc0));
	sbi_printf("mdcfg_info : 0x%lx\r\n", csr_read(0xfc1));
	sbi_printf("mcfg_info : 0x%lx\r\n", csr_read(0xfc2));
	sbi_printf("misa : 0x%lx\r\n", csr_read(0x301));

//	sbi_printf("modify dt later \n");

	return 0;
}

static int nuclei_console_init(void)
{
/*	return sifive_uart_init(NUCLEI_DEBUG_UART, nuclei_clk_freq,
				NUCLEI_UART_BAUDRATE);*/
    return AL9000_uart_init(AL9000_UART0,115200,UART_BIT_LENGTH_8);








}

static int nuclei_irqchip_init(bool cold_boot)
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

static int nuclei_ipi_init(bool cold_boot)
{
	int rc;

	if (cold_boot) {
		rc = clint_cold_ipi_init(&clint);
		if (rc)
			return rc;
	}

	return clint_warm_ipi_init();
}

static int nuclei_timer_init(bool cold_boot)
{
	int rc;

	if (cold_boot) {
		rc = clint_cold_timer_init(&clint, NULL);
		if (rc)
			return rc;
	}

	return clint_warm_timer_init();
}

static int nuclei_system_reset_check(u32 type, u32 reason)
{
	return 1;
}

static void nuclei_system_reset(u32 type, u32 reason)
{
	/* Reset system using MSFTRST register in Nuclei Timer. */
	writel(NUCLEI_NUCLEI_TIMER_MSFTRST_KEY, (void *)(NUCLEI_NUCLEI_TIMER_ADDR
					+ NUCLEI_NUCLEI_TIMER_MSFTRST_OFS));
	while(1);
}

const struct sbi_platform_operations platform_ops = {
	.early_init		= nuclei_early_init,
	.final_init		= nuclei_final_init,
	.console_putc		=  uart_write, /*sifive_uart_putc,  ian fang*/
	.console_getc		=  uart_read, /*sifive_uart_getc, ian fang*/
	.console_init		= nuclei_console_init,
	.irqchip_init		= nuclei_irqchip_init,
	.ipi_send		= clint_ipi_send,
	.ipi_clear		= clint_ipi_clear,
	.ipi_init		= nuclei_ipi_init,
	.timer_value		= clint_timer_value,
	.timer_event_stop	= clint_timer_event_stop,
	.timer_event_start	= clint_timer_event_start,
	.timer_init		= nuclei_timer_init,
	.system_reset_check	= nuclei_system_reset_check,
	.system_reset		= nuclei_system_reset
};

const struct sbi_platform platform = {
	.opensbi_version	= OPENSBI_VERSION,
	.platform_version	= SBI_PLATFORM_VERSION(0x0U, 0x01U),
	.name			= "Nuclei Demo SoC",
	.features		= SBI_PLATFORM_DEFAULT_FEATURES,
	.hart_count		= NUCLEI_HART_COUNT,
	.hart_stack_size	= SBI_PLATFORM_DEFAULT_HART_STACK_SIZE,
	.platform_ops_addr	= (unsigned long)&platform_ops
};
