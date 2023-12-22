#include <sbi/riscv_asm.h>
#include <sbi/riscv_io.h>
#include <sbi/sbi_const.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include "hardware.h"

#define ALSIP_FPGA_PROG_START	0
#define ALSIP_FPGA_PROG_LOAD	1
#define ALSIP_FPGA_PROG_DONE	2
#define ALSIP_FPGA_PLCLK_RST	3

#define fpga_readl(c)		readl((void*)(c))
#define fpga_writel(v, c)	writel((v), (void*)(c))

extern void platform_udelay(unsigned long usec);
int fpga_prog_start(void)
{
	int i;
	u32 val;

	// disable acp
	val = fpga_readl(APU_AINACTS);
	fpga_writel(val|0x1, APU_AINACTS);
	val = fpga_readl(CRP_SRST_CTRL0);
	fpga_writel(val&~0x100, CRP_SRST_CTRL0);

	// disable gp and fahb
	val = fpga_readl(SYSCTRL_NS_PLS_PROT);
	fpga_writel(val|0x3, SYSCTRL_NS_PLS_PROT);

	// reset pl
	val = fpga_readl(SYSCTRL_S_GLOBAL_SRSTN);
	fpga_writel(val&~SYSCTRL_S_GLOBAL_SRSTN_MSK_GLB_PL_SRST, SYSCTRL_S_GLOBAL_SRSTN);
	platform_udelay(50);
	fpga_writel(val|SYSCTRL_S_GLOBAL_SRSTN_MSK_GLB_PL_SRST, SYSCTRL_S_GLOBAL_SRSTN);
	platform_udelay(50);

	// reset gp and hp
	val = fpga_readl(CRP_SRST_CTRL2);
	fpga_writel(val&~0x30, CRP_SRST_CTRL2);
	val = fpga_readl(CRP_SRST_CTRL2);
	fpga_writel(val&~0x3, CRP_SRST_CTRL2);

	// reset pcap
	fpga_writel(0, CSU_PCAP_RESET);
	fpga_writel(1, CSU_PCAP_RESET);

	// enable pcap
	fpga_writel(0, CSU_PCAP_ENABLE);
	fpga_writel(1, CSU_PCAP_ENABLE);

	for (i=0; i<10000; i++) {
		platform_udelay(50);
		val = fpga_readl(CRP_CFG_STATE);
		if (val & CRP_CFG_STATE_MSK_PL2PS_INITN)
			return 0;
	}

	return SBI_EFAIL;
}

int fpga_prog_load(void *p, u64 len)
{
	u32 *addr, cnt, i;

	if (len & 0x3)
		return SBI_EFAIL;

	addr = (u32 *)p;
	cnt = (u32)(len/sizeof(u32));
	for (i=0; i<cnt; i++) {
		fpga_writel(addr[i], CSU_PCAP_WR_STREAM);
	}

	return 0;
}

int fpga_check_prog_done(void)
{
	int i;
	u32 val;

	for (i=0; i<100; i++) {
		val = fpga_readl(CRP_CFG_STATE);
		if ((val & 0x7) == 7)
			return 1;
	}

	return 0;
}

int fpga_prog_done(u32 done)
{
	int i, ret;
	u32 val;

	ret = 0;

	if (done && !fpga_check_prog_done()) {
		ret = SBI_EFAIL;
		//prog done
		fpga_writel(0x90300002, CSU_PCAP_WR_STREAM);
		fpga_writel(0x00000005, CSU_PCAP_WR_STREAM);
		fpga_writel(0x1655e833, CSU_PCAP_WR_STREAM);
		//bit stream noop
		for (i = 0; i < 2048; i++)
			fpga_writel(0x80000000, CSU_PCAP_WR_STREAM);

		if (fpga_check_prog_done())
			ret = 0;
	}

	// disable pcap
	fpga_writel(0, CSU_PCAP_ENABLE);

	// release gp and hp
	val = fpga_readl(CRP_SRST_CTRL2);
	fpga_writel(val|0x3, CRP_SRST_CTRL2);
	val = fpga_readl(CRP_SRST_CTRL2);
	fpga_writel(val|0x30, CRP_SRST_CTRL2);

	// enable gp and fahb
	val = fpga_readl(SYSCTRL_NS_PLS_PROT);
	fpga_writel(val&~0x3, SYSCTRL_NS_PLS_PROT);

	// enable acp
	val = fpga_readl(CRP_SRST_CTRL0);
	fpga_writel(val|0x100, CRP_SRST_CTRL0);
	val = fpga_readl(APU_AINACTS);
	fpga_writel(val&~0x1, APU_AINACTS);

	return ret;
}

int fpga_plclk_reset(u32 reset)
{
	u32 val;

	val = fpga_readl(SYSCTRL_S_GLOBAL_SRSTN);
	if (reset < 2) {
		val &= ~SYSCTRL_S_GLOBAL_SRSTN_MSK_FCLK_DOMAIN_SRST;
		val |= (reset<<4);
		fpga_writel(val, SYSCTRL_S_GLOBAL_SRSTN);
	}

	return (val&SYSCTRL_S_GLOBAL_SRSTN_MSK_FCLK_DOMAIN_SRST)?1:0;
}

int dr1v90_fpga_prog(long funcid,
		   const struct sbi_trap_regs *regs,
		   unsigned long *out_value,
		   struct sbi_trap_info *out_trap)
{
	if (funcid == ALSIP_FPGA_PROG_START)
		return fpga_prog_start();
	else if (funcid == ALSIP_FPGA_PROG_LOAD)
		return fpga_prog_load((void *)regs->a0, (u64)regs->a1);
	else if (funcid == ALSIP_FPGA_PROG_DONE)
		return fpga_prog_done((u32)regs->a0);
	else if (funcid == ALSIP_FPGA_PLCLK_RST)
		return fpga_plclk_reset((u32)regs->a0);
	else
		return SBI_ENOTSUPP;
}
