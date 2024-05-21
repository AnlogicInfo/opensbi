/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) Anlogic Corporation or its affiliates.
 *
 */

#include <sbi/riscv_asm.h>
#include <sbi/riscv_io.h>
#include <sbi/sbi_const.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_bitops.h>
#include "hardware.h"
#include "fpga_prog.h"
#include "crypto.h"

#define ALSIP_FPGA_PROG_START	0
#define ALSIP_FPGA_PROG_LOAD	1
#define ALSIP_FPGA_PROG_DONE	2
#define ALSIP_FPGA_PLCLK_RST	3
#define ALSIP_FPGA_PROG_INIT	4

#define fpga_readl(c)		readl((void*)(c))
#define fpga_writel(v, c)	writel((v), (void*)(c))

extern void platform_udelay(unsigned long usec);
static int fpga_prog_start(void);
static int fpga_prog_load(void *p, u64 len);
static int fpga_prog_done(u32 done);

#define cost_data(csz)						\
	do {							\
		typeof(csz) ___tmp = csz;			\
		fpgamod.imgoff += ___tmp;			\
		len -= ___tmp;					\
		buf += ___tmp;					\
	} while (0)

#define save_data(type)						\
	do {							\
		tmp = fpgamod.imgoff - fpgamod.bit##type##start;\
		sz = sizeof(fpgamod.type) - tmp;		\
		if (sz > len)					\
			sz = len;				\
		cpy_mem(fpgamod.type + tmp, buf, sz);		\
		cost_data(sz);					\
	} while (0)

#define FM_STP_UNINIT				0
#define FM_STP_INITED				1
#define FM_STP_STARTED				2
#define FM_STP_LOADING				3

#define FM_FLG_BOOTIMG				0x01UL
#define FM_FLG_FAILED				0x02UL
#define FM_FLG_PCAPST				0x04UL
#define FM_FLG_PTAC				0x08UL
#define FM_FLG_PTHASH				0x10UL
#define FM_FLG_HASHOUT				0x20UL
#define FM_FLG_START_CLR	(FM_FLG_BOOTIMG | FM_FLG_FAILED |	\
				 FM_FLG_PTAC | FM_FLG_PTHASH |		\
				 FM_FLG_HASHOUT)
#define FM_CHK_ERR()		(fpgamod.flag & FM_FLG_FAILED)
#define FM_SET_ERR()		fpgamod.flag |= FM_FLG_FAILED

#define BLOCK_MIN_SIZE				(64U)

#define PPK_BYTE_LENGTH				(64U)
#define SPK_BYTE_LENGTH				(64U)

#define HASH_BYTE_LENGTH			(32U)

#define ALIH_MIN_PARTITIONS			(1U)
#define ALIH_MAX_PARTITIONS			(6U)

#define ALIH_BH_SIZE				(0x300U)
#define ALIH_IHT_SIZE				(0x40U)

#define ALIH_PH_SIZE				(64U)
#define ALIH_HASH_SIZE				(64U)

#define ALIH_BH_ATTRB_OFFSET			(0x8C)
#define ALIH_BH_ATTRB_HD_AUTH_ONLY_MASK		(0x03 << 4)
#define ALIH_BH_ATTRB_HD_HASH_SEL_MASK		(0x03 << 8)
#define ALIH_BH_ATTRB_CPU_SEL_MASK		(0x03 << 10)

#define ALIH_BH_ATTRB_HD_AC_SEL_MASK		(0x03 << 12)
#define ALIH_BH_ATTRB_HD_AC_SEL_NONE		(0x00 << 12)
#define ALIH_BH_ATTRB_HD_AC_SEL_SM2		(0x01 << 12)
#define ALIH_BH_ATTRB_HD_AC_SEL_ECC256		(0x02 << 12)

#define ALIH_BH_ATTRB_HD_PPK_HASH_MASK		(0x03 << 14)

#define ALIH_BH_QSPI_WIDTH_SEL_OFFSET		(0x60)
#define ALIH_BH_IMAGE_ID_OFFSET			(0x64)
#define ALIH_BH_ENC_STATUS_OFFSET		(0x68)
#define ALIH_BH_AC_OFFSET			(0x90)
#define ALIH_BH_FIRST_PARTIADDR_OFFSET		(0x94)
#define ALIH_BH_PARTINUM_OFFSET			(0x98)
#define ALIH_BH_CHECKSUM_OFFSET			(0x9C)

#define ALIH_BH_ENC_KEY_OFFSET			(0xA0)
#define ALIH_BH_ENC_KEY_LENGTH			(0x20)

#define ALIH_BH_IV_OFFSET			(0xC0)
#define ALIH_BH_IV_LENGTH			(0x20)

#define ALIH_PH_ATTRIB_PART_OWNER_MASK		(0x07 << 16)
#define ALIH_PH_ATTRIB_PART_OWNER_FSBL		(0x00 << 16)
#define ALIH_PH_ATTRIB_PART_OWNER_UBOOT		(0x01 << 16)

#define ALIH_PH_ATTRIB_AUTH_TYPE_MASK		(0x03 << 14)
#define ALIH_PH_ATTRIB_AUTH_TYPE_NONE		(0x00 << 14)
#define ALIH_PH_ATTRIB_AUTH_TYPE_SM2		(0x01 << 14)
#define ALIH_PH_ATTRIB_AUTH_TYPE_ECC256		(0x02 << 14)
#define ALIH_PH_ATTRIB_AUTH_TYPE_MAXVAL		(0x02 << 14)

#define ALIH_PH_ATTRIB_ENC_TYPE_MASK		(0x03 << 12)
#define ALIH_PH_ATTRIB_ENC_TYPE_NONE		(0x00 << 12)
#define ALIH_PH_ATTRIB_ENC_TYPE_SM4		(0x01 << 12)
#define ALIH_PH_ATTRIB_ENC_TYPE_AES256		(0x02 << 12)
#define ALIH_PH_ATTRIB_ENC_TYPE_MAXVAL		(0x02 << 12)

#define ALIH_PH_ATTRIB_HASH_TYPE_MASK		(0x03 << 10)
#define ALIH_PH_ATTRIB_HASH_TYPE_NONE		(0x00 << 10)
#define ALIH_PH_ATTRIB_HASH_TYPE_SM3		(0x01 << 10)
#define ALIH_PH_ATTRIB_HASH_TYPE_SHA256		(0x02 << 10)
#define ALIH_PH_ATTRIB_HASH_TYPE_MAXVAL		(0x02 << 10)

#define ALIH_PH_ATTRIB_DEST_DEV_MASK		(0x07 <<  7)
#define ALIH_PH_ATTRIB_DEST_DEV_PS		(0x00 <<  7)
#define ALIH_PH_ATTRIB_DEST_DEV_PL		(0x01 <<  7)

#define ALIH_PH_ATTRIB_DEST_CPU_MASK		(0x03 <<  5)
#define ALIH_PH_ATTRIB_DEST_CPU_RPU		(0x00 <<  5)
#define ALIH_PH_ATTRIB_DEST_CPU_APU0		(0x01 <<  5)
#define ALIH_PH_ATTRIB_DEST_CPU_APU1		(0x02 <<  5)

#define ALAC_HD_ACSEL_NONE			0x000
#define ALAC_HD_ACSEL_SM2			0x001
#define ALAC_HD_ACSEL_ECC256			0x002

#define ALAC_ACHEADER_OFFSET			0x000
#define ALAC_SPKID_OFFSET			0x004
#define ALAC_CUSTOMIZED_OFFSET			0x008

#define ALAC_PPK_OFFSET				0x040
#define ALAC_PPK_X_OFFSET			0x040
#define ALAC_PPK_Y_OFFSET			0x060

#define ALAC_SPK_OFFSET				0x080
#define ALAC_SPK_X_OFFSET			0x080
#define ALAC_SPK_Y_OFFSET			0x0A0

#define ALAC_SPK_SIGNATURE_OFFSET		0x0C0
#define ALAC_BTHDR_SIGNATURE_OFFSET		0x100
#define ALAC_PART_SIGNATURE_OFFSET		0x140
#define ALAC_LENGTH				0x180

struct boot_header {
	u32 vector_tbl[24];		// 0x00~0x5c,   vector table in xip mode, not used
	u32 qspi_width_sel;		// 0x60,        qspi bit width select,
					//              0x55aa: x1 mode only,
					//              other: auto detect
	u32 image_id;			// 0x64,        header signature
	u32 enc_stat;			// 0x68,        encryption encrypt key source
	u32 fsbl_info[8];		// 0x6c~0x88,   fsbl information,
	u32 bh_attr;			// 0x8c,        bootheader attribute
	u32 bh_ac_off;			// 0x90,        bootheader ac offset
	u32 first_ph_off;		// 0x94,        1st partition header offset
	u32 part_num;			// 0x98,        count of partition headers
	u32 bh_chksum;			// 0x9c,        boot header checksum
	u8  enc_key[32];		// 0xa0~0xbc,   encryption key
	u8  sec_hdr_iv[32];		// 0xc0~0xdc,   secure header iv
	u8  rsv_e0[32];			// 0xe0~0xfc,   reserved
	u32 reg_init_val[128];		// 0x100~0x2fc, register initialization data
} __packed;

struct partition_header {
	u32 part_len;			/// 0x00 Partition Byte Length, including padding
	u32 exact_part_len;		/// 0x04 Partition Byte Length, not including padding
	u32 tot_part_len;		/// 0x08 Partition Total Byte Length,
					///      including padding and AC (if exists)
	u32 next_ph_off;		/// 0x0c Next partition header address offset
	u64 dst_exec_addr;		/// 0x10 partition execution address (64 bit)
	u64 dst_load_addr;		/// 0x18 partition load address (64 bit)
	u32 part_off;			/// 0x20 Actual partition address byte offset
	u32 part_attr;			/// 0x24 Partition attribute
	u32 rsv_28;			/// 0x28 Reserved 0x28
	u32 hash_data_off;		/// 0x2c partition checksum address byte offset
	u32 rsv_30;			/// 0x30 Reserved 0x30
	u32 ac_off;			/// 0x34 Authentication Certificate byte Offset
	u32 rsv_38;			/// 0x38 Reserved 0x38
	u32 ph_chksum;			/// 0x3c Partition header checksum
} __packed;

struct fpga_mod {
	u32 flag;
	u16 step;
	u16 partidx;
	u32 bitstart;
	u32 bittotend;
	u32 bitend;
	u32 bitoff;
	u32 bithashstart;
	u32 bithashend;
	u32 bitacstart;
	u32 bitacend;
	u32 imgoff;
	u32 efusectl;
	u16 blklen;
	u16 blkdata;
	u8  *blkbuf;
	u8  hashtype;
	u8  authtype;
	u8  enctype;
	u8  reserved1;
	u8  hashout[HASH_LEN];
	struct boot_header bh;
	struct partition_header ph[ALIH_MAX_PARTITIONS];
	u8	ac[ALAC_LENGTH];
	u8	hash[HASH_LEN];
};

static struct fpga_mod fpgamod;

int fpga_mod_start(void)
{
	if (fpgamod.step != FM_STP_INITED)
		return -ERR_START(EER_NOTINITED);

	fpgamod.flag &= ~FM_FLG_START_CLR;
	fpgamod.partidx = (u16)-1;
	fpgamod.bitstart = 0;
	fpgamod.bittotend = 0;
	fpgamod.bitend = 0;
	fpgamod.bitoff = 0;
	fpgamod.bithashstart = 0;
	fpgamod.bithashend = 0;
	fpgamod.bitacstart = 0;
	fpgamod.bitacend = 0;
	fpgamod.imgoff = 0;
	fpgamod.blkdata = 0;
	fpgamod.authtype = CRPT_OP_AUTH_NONE;
	fpgamod.hashtype = CRPT_OP_HASH_NONE;
	fpgamod.enctype = CRPT_OP_ENCRYPT_NONE;

	fpgamod.efusectl = fpga_readl(EFUSE_SEC_CTRL);

	fpgamod.step = FM_STP_STARTED;
	return 0;
}

static int fpga_mod_ac_verify(u8 *ac)
{
	u32 efusectl, tmp;
	u8  hashtype;
	u8  authtype;
	struct crypto_hash_param hashpara;
	u8 *p2;
	int ret;

	efusectl = (fpgamod.efusectl & EFUSE_PPK_HASH_TYPE_MASK);
	tmp = (fpgamod.bh.bh_attr & ALIH_BH_ATTRB_HD_PPK_HASH_MASK);
	if (efusectl == EFUSE_PPK_HASH_TYPE_SM3) {
		hashtype = CRPT_OP_HASH_SM3;
	} else if (efusectl == EFUSE_PPK_HASH_TYPE_SHA256) {
		hashtype = CRPT_OP_HASH_SHA256;
	} else if (efusectl == EFUSE_PPK_HASH_TYPE_HEADER_SET) {
		if (tmp == ALIH_BH_ATTRB_HD_PPK_HASH_MASK)
			goto verify_spk;
		tmp = (*(u32 *)ac) & 0x3;
		if (tmp == ALAC_HD_ACSEL_SM2)
			hashtype = CRPT_OP_HASH_SM3;
		else if (tmp == ALAC_HD_ACSEL_ECC256)
			hashtype = CRPT_OP_HASH_SHA256;
		else if (tmp == ALAC_HD_ACSEL_NONE)
			goto verify_spk;
		else
			return -ERR_ACVERI(EOP_PPKVERI, EER_HASHSEL);

	} else {
		return -ERR_ACVERI(EOP_PPKVERI, EER_HASHSEL);
	}

	if ((fpgamod.efusectl & EFUSE_PPK0_INVALID_MASK) != EFUSE_PPK0_INVALID_MASK)
		p2 = (u8 *)(SYSCTRL_S_EFUSE_GLB00);
	else if ((fpgamod.efusectl & EFUSE_PPK1_INVALID_MASK) != EFUSE_PPK1_INVALID_MASK)
		p2 = (u8 *)(SYSCTRL_S_EFUSE_GLB08);
	else
		goto verify_spk;

	hashpara.hash_type = hashtype;
	cpy_mem(fpgamod.blkbuf, ac + ALAC_PPK_OFFSET, PPK_BYTE_LENGTH);
	ret = crypto_hash((ulong)fpgamod.blkbuf, PPK_BYTE_LENGTH,
			  CRPT_BLOCK_WHOLE, &hashpara);
	if (ret < 0)
		return -ERR_ACVERI(EOP_PPKHASH, -ret);

	if (cmp_mem(hashpara.hash_output, p2, sizeof(hashpara.hash_output)))
		return -ERR_ACVERI(EOP_PPKVERI, EER_HASHCMP);

verify_spk:
	efusectl = (fpgamod.efusectl & EFUSE_AUTH_TYPE_MASK);
	tmp = (*(u32 *)fpgamod.ac) & 0x3;
	if (tmp == ALAC_HD_ACSEL_NONE) {
		if (efusectl != EFUSE_AUTH_TYPE_HEADER_SET)
			return -ERR_ACVERI(EOP_SPKVERI, EER_ACSEL);
		authtype = CRPT_OP_AUTH_NONE;
		hashtype = CRPT_OP_HASH_NONE;
		goto suc_exit;
	} else if (tmp == ALAC_HD_ACSEL_ECC256) {
		if (efusectl != EFUSE_AUTH_TYPE_ECC256 &&
		    efusectl != EFUSE_AUTH_TYPE_HEADER_SET)
			return -ERR_ACVERI(EOP_SPKVERI, EER_ACSEL);
		authtype = CRPT_OP_AUTH_ECC256;
		hashtype = CRPT_OP_HASH_SHA256;
	} else if (tmp == ALAC_HD_ACSEL_SM2) {
		if (efusectl != EFUSE_AUTH_TYPE_SM2 &&
		    efusectl != EFUSE_AUTH_TYPE_HEADER_SET)
			return -ERR_ACVERI(EOP_SPKVERI, EER_ACSEL);
		authtype = CRPT_OP_AUTH_SM2;
		hashtype = CRPT_OP_HASH_SM3;
	} else {
		return -ERR_ACVERI(EOP_SPKVERI, EER_ACSEL);
	}

	if (!((*(u32 *)fpgamod.ac) & 0x100))
		goto suc_exit;

	cpy_mem(fpgamod.blkbuf, ac + ALAC_SPK_OFFSET, SPK_BYTE_LENGTH);
	ret = crypto_auth2((ulong)fpgamod.blkbuf, SPK_BYTE_LENGTH,
			   hashtype, authtype,
			ac + ALAC_PPK_OFFSET,
			ac + ALAC_SPK_SIGNATURE_OFFSET);
	if (ret < 0)
		return -ERR_ACVERI(EOP_SPKAUTH, -ret);

suc_exit:
	return 0;
}

static int fpga_mod_imghdr_auth(u8 *p, u64 len)
{
	u32 efusectl, tmp;
	u8  hashtype;
	u8  authtype;
	struct boot_header *bh = (struct boot_header *)p;
	u8 *ac = p + bh->bh_ac_off;
	int ret;

	ret = fpga_mod_ac_verify(ac);
	if (ret < 0)
		return ret;

	efusectl = (fpgamod.efusectl & EFUSE_AUTH_TYPE_MASK);
	tmp = (bh->bh_attr & ALIH_BH_ATTRB_HD_AC_SEL_MASK);
	if (tmp == ALIH_BH_ATTRB_HD_AC_SEL_NONE) {
		if (efusectl != EFUSE_AUTH_TYPE_HEADER_SET)
			return -ERR_IMGHDR(EOP_IHVERI, EER_ACSEL);
		return 0;
	} else if (tmp == ALIH_BH_ATTRB_HD_AC_SEL_ECC256) {
		if (efusectl != EFUSE_AUTH_TYPE_ECC256 &&
		    efusectl != EFUSE_AUTH_TYPE_HEADER_SET)
			return -ERR_IMGHDR(EOP_IHVERI, EER_ACSEL);
		authtype = CRPT_OP_AUTH_ECC256;
		hashtype = CRPT_OP_HASH_SHA256;
	} else if (tmp == ALIH_BH_ATTRB_HD_AC_SEL_SM2) {
		if (efusectl != EFUSE_AUTH_TYPE_SM2 &&
		    efusectl != EFUSE_AUTH_TYPE_HEADER_SET)
			return -ERR_IMGHDR(EOP_IHVERI, EER_ACSEL);
		authtype = CRPT_OP_AUTH_SM2;
		hashtype = CRPT_OP_HASH_SM3;
	} else {
		return -ERR_IMGHDR(EOP_IHVERI, EER_ACSEL);
	}

	ret = crypto_auth2((ulong)p,
			   ALIH_BH_SIZE + ALIH_PH_SIZE * fpgamod.bh.part_num,
			   hashtype, authtype,
			   ac + ALAC_SPK_OFFSET,
			   ac + ALAC_BTHDR_SIGNATURE_OFFSET);
	if (ret < 0)
		return -ERR_IMGHDR(EOP_IHAUTH, -ret);

	return 0;
}

static int fpga_mod_pthdr_auth(u8 *p, u64 len, u32 off)
{
	struct partition_header *ph = (struct partition_header *)(p + off);

	if (crypto_calc_crc32(ph, 0x3c) != ph->ph_chksum)
		return -1;

	return 0;
}

static int fpga_mod_part_auth(void)
{
	struct crypto_auth_param authpara;
	u32 tmp;
	int ret = -1;

	if (fpgamod.authtype != CRPT_OP_AUTH_NONE) {
		if (!(fpgamod.flag & FM_FLG_HASHOUT)) {
			ret = -ERR_PARTAUTH(0, EER_NOHASH);
			goto fail;
		}
		if (!(fpgamod.flag & FM_FLG_PTAC)) {
			ret = -ERR_PARTAUTH(0, EER_NOAC);
			goto fail;
		}
		ret = fpga_mod_ac_verify(fpgamod.ac);
		if (ret < 0)
			goto fail;
		authpara.auth_type = fpgamod.authtype;
		cpy_mem(authpara.hash, fpgamod.hashout, sizeof(authpara.hash));
		if ((*(u32 *)fpgamod.ac) & 0x100)
			tmp = ALAC_SPK_OFFSET;
		else
			tmp = ALAC_PPK_OFFSET;
		cpy_mem(authpara.spk, fpgamod.ac + tmp,
			sizeof(authpara.spk));
		cpy_mem(authpara.sig, fpgamod.ac + ALAC_PART_SIGNATURE_OFFSET,
			sizeof(authpara.sig));

		ret = crypto_auth(&authpara);
		if (ret) {
			ret = -ERR_PARTAUTH(EOP_PARTAUTH, -ret);
			goto fail;
		}
	} else if (fpgamod.hashtype != CRPT_OP_HASH_NONE) {
		if (!(fpgamod.flag & FM_FLG_HASHOUT)) {
			ret = -ERR_PARTAUTH(0, EER_NOHASH);
			goto fail;
		}
		if (!(fpgamod.flag & FM_FLG_PTHASH)) {
			ret = -ERR_PARTAUTH(0, EER_NOHASH);
			goto fail;
		}
		if (cmp_mem(fpgamod.hashout, fpgamod.hash, sizeof(fpgamod.hashout))) {
			ret = -ERR_PARTAUTH(0, EER_HASHCMP);
			goto fail;
		}
	}

	return 0;
fail:
	return ret;
}

static int fpga_mod_parse_ptattr(u32 ptattr)
{
	u32 efusectl, tmp;

	efusectl = (fpgamod.efusectl & EFUSE_AUTH_TYPE_MASK);
	tmp = (ptattr & ALIH_PH_ATTRIB_AUTH_TYPE_MASK);
	if (tmp == ALIH_PH_ATTRIB_AUTH_TYPE_NONE) {
		if (efusectl != EFUSE_AUTH_TYPE_HEADER_SET)
			return -ERR_PHDR(EOP_PHATTR, EER_ACSEL);
		fpgamod.authtype = CRPT_OP_AUTH_NONE;
		tmp = (ptattr & ALIH_PH_ATTRIB_HASH_TYPE_MASK);
		if (tmp == ALIH_PH_ATTRIB_HASH_TYPE_SHA256)
			fpgamod.hashtype = CRPT_OP_HASH_SHA256;
		else if (tmp == ALIH_PH_ATTRIB_HASH_TYPE_SM3)
			fpgamod.hashtype = CRPT_OP_HASH_SM3;
		else if (tmp == ALIH_PH_ATTRIB_HASH_TYPE_NONE)
			fpgamod.hashtype = CRPT_OP_HASH_NONE;
		else
			return -ERR_PHDR(EOP_PHATTR, EER_HASHSEL);
	} else if (tmp == ALIH_PH_ATTRIB_AUTH_TYPE_ECC256) {
		if (efusectl != EFUSE_AUTH_TYPE_ECC256 &&
		    efusectl != EFUSE_AUTH_TYPE_HEADER_SET)
			return -ERR_PHDR(EOP_PHATTR, EER_ACSEL);
		fpgamod.authtype = CRPT_OP_AUTH_ECC256;
		fpgamod.hashtype = CRPT_OP_HASH_SHA256;
	} else if (tmp == ALIH_PH_ATTRIB_AUTH_TYPE_SM2) {
		if (efusectl != EFUSE_AUTH_TYPE_SM2 &&
		    efusectl != EFUSE_AUTH_TYPE_HEADER_SET)
			return -ERR_PHDR(EOP_PHATTR, EER_ACSEL);
		fpgamod.authtype = CRPT_OP_AUTH_SM2;
		fpgamod.hashtype = CRPT_OP_HASH_SM3;
	} else {
		return -ERR_PHDR(EOP_PHATTR, EER_ACSEL);
	}

	efusectl = (fpgamod.efusectl & EFUSE_ENC_TYPE_MASK);
	tmp = (ptattr & ALIH_PH_ATTRIB_ENC_TYPE_MASK);
	if (tmp == ALIH_PH_ATTRIB_ENC_TYPE_NONE) {
		if (efusectl != EFUSE_ENC_TYPE_HEADER_SET)
			return -ERR_PHDR(EOP_PHATTR, EER_ENCSEL);
		fpgamod.enctype = CRPT_OP_ENCRYPT_NONE;
	} else if (tmp == ALIH_PH_ATTRIB_ENC_TYPE_AES256) {
		if (efusectl != EFUSE_ENC_TYPE_AES256 &&
		    efusectl != EFUSE_ENC_TYPE_HEADER_SET)
			return -ERR_PHDR(EOP_PHATTR, EER_ENCSEL);
		if (fpgamod.hashtype != CRPT_OP_HASH_SHA256 &&
		    fpgamod.hashtype != CRPT_OP_HASH_NONE)
			return -ERR_PHDR(EOP_PHATTR, EER_ENCSEL);
		fpgamod.enctype = CRPT_OP_ENCRYPT_AES256;
	} else if (tmp == ALIH_PH_ATTRIB_ENC_TYPE_SM4) {
		if (efusectl != EFUSE_ENC_TYPE_SM4 &&
		    efusectl != EFUSE_ENC_TYPE_HEADER_SET)
			return -ERR_PHDR(EOP_PHATTR, EER_ENCSEL);
		if (fpgamod.hashtype != CRPT_OP_HASH_SM3 &&
		    fpgamod.hashtype != CRPT_OP_HASH_NONE)
			return -ERR_PHDR(EOP_PHATTR, EER_ENCSEL);
		fpgamod.enctype = CRPT_OP_ENCRYPT_SM4;
	} else {
		return -ERR_PHDR(EOP_PHATTR, EER_ENCSEL);
	}

	return 0;
}

static int fpga_mod_load_data(u8 *p, u64 len)
{
	int ret;
	u8 *buf;
	u64 sz, csz;
	enum crypto_block_mode blk_mode;
	struct crypto_hash_param hash_para, *hashp;
	struct crypto_dec_param dec_para;
	u32 imgoff = fpgamod.imgoff;

	if (len & 0x3)
		return -ERR_LOAD(0, EER_INVDATALEN);

	if (fpgamod.enctype == CRPT_OP_ENCRYPT_NONE &&
	    fpgamod.hashtype == CRPT_OP_HASH_NONE) {
		return fpga_prog_load(p, len);
	}

	while (len) {
		if (fpgamod.blkdata) {
			imgoff -= fpgamod.blkdata;
			csz = BLOCK_MIN_SIZE - fpgamod.blkdata;
			if (csz <= len) {
				cpy_mem(fpgamod.blkbuf + fpgamod.blkdata, p, csz);
				buf = fpgamod.blkbuf;
				sz = BLOCK_MIN_SIZE;
				fpgamod.blkdata = 0;
			} else {
				csz = len;
				cpy_mem(fpgamod.blkbuf + fpgamod.blkdata, p, csz);
				fpgamod.blkdata += csz;
				break;
			}
		} else {
			if (len >= BLOCK_MIN_SIZE) {
				sz = len / BLOCK_MIN_SIZE * BLOCK_MIN_SIZE;
				csz = sz;
				buf = p;
			} else {
				cpy_mem(fpgamod.blkbuf, p, len);
				fpgamod.blkdata = len;
				break;
			}
		}

		if ((sz + imgoff) >= fpgamod.bitend) {
			blk_mode = (imgoff == fpgamod.bitstart)
				   ? CRPT_BLOCK_WHOLE
				   : CRPT_BLOCK_LAST;
		} else {
			blk_mode = (imgoff == fpgamod.bitstart)
				   ? CRPT_BLOCK_FIRST
				   : CRPT_BLOCK_MID;
		}

		dec_para.enc_type = fpgamod.enctype;
		dec_para.key_mode = CRPT_KM_BHDR_KEY;
		hash_para.hash_type = fpgamod.hashtype;
		if (fpgamod.enctype != CRPT_OP_ENCRYPT_NONE) {
			hashp = &hash_para;
			dec_para.decode = 1;
			clr_mem(dec_para.iv, sizeof(dec_para.iv));
		} else {
			hashp = NULL;
			ret = crypto_hash((unsigned long)buf, sz, blk_mode,
					  &hash_para);
			if (ret < 0) {
				ret = -ERR_LOAD(EOP_PARTHASH, -ret);
				return ret;
			}
		}

		ret = crypto_dma((unsigned long)buf, sz, blk_mode,
				 CRPT_ADDR_SRC_INCR,
				 &dec_para, hashp,
				 CSU_PCAP_WR_STREAM);
		if (ret < 0) {
			ret = -ERR_LOAD(EOP_PARTENC, -ret);
			return ret;
		}

		len -= csz;
		p += csz;
		imgoff += sz;

		if (imgoff >= fpgamod.bitend &&
		    fpgamod.hashtype != CRPT_OP_HASH_NONE) {
			cpy_mem(fpgamod.hashout, hash_para.hash_output,
				sizeof(fpgamod.hashout));
			fpgamod.flag |= FM_FLG_HASHOUT;
		}
	}

	return 0;
}

static int fpga_mod_handle_imghdr(u8 *p, u64 len)
{
	struct boot_header *bh;
	struct partition_header *ph;
	u32 off, tmp, i;
	int ret;

	bh = (struct boot_header *)p;
	if (len < sizeof(struct boot_header)) {
		ret = -ERR_IMGHDR(EOP_BOOTHDR, EER_INVDATALEN);
		goto invalid_bi;
	}

	if (bh->image_id != 0x43474c41)
		goto not_bi;

	if (crypto_calc_crc32(&bh->qspi_width_sel, 0x3c) != bh->bh_chksum)
		goto not_bi;

	bh = &fpgamod.bh;
	cpy_mem(bh, p, sizeof(struct boot_header));
	off = bh->first_ph_off;
	tmp = sizeof(struct partition_header) * bh->part_num;
	if (len < (off + tmp)) {
		ret = -ERR_IMGHDR(EOP_BOOTHDR, EER_INVDATALEN);
		goto invalid_bi;
	}

	ph = fpgamod.ph;
	cpy_mem(ph, p + off, tmp);

	if ((fpgamod.efusectl & EFUSE_AUTH_TYPE_MASK) ||
	    (bh->bh_attr & ALIH_BH_ATTRB_HD_AC_SEL_MASK)) {
		off = bh->bh_ac_off;
		if (len < off + ALAC_LENGTH) {
			ret = -ERR_IMGHDR(EOP_BOOTHDR, EER_INVDATALEN);
			goto invalid_bi;
		}

		ret = fpga_mod_imghdr_auth(p, len);
		if (ret)
			goto invalid_bi;
	}

	for (i = 0; i < bh->part_num; i++) {
		tmp = (ph[i].part_attr & ALIH_PH_ATTRIB_DEST_DEV_MASK);
		if (tmp != ALIH_PH_ATTRIB_DEST_DEV_PL)
			continue;

		if (ph[i].part_len % 64) {
			ret = -ERR_PHDR(0, EER_INVDATALEN);
			goto invalid_bi;
		}

		off = bh->first_ph_off + ALIH_PH_SIZE * i;
		ret = fpga_mod_pthdr_auth(p, len, off);
		if (ret) {
			ret = -ERR_PHDR(0, EER_INVDATA);
			goto invalid_bi;
		}

		ret = fpga_mod_parse_ptattr(ph[i].part_attr);
		if (ret)
			goto invalid_bi;

		fpgamod.partidx = i;
		fpgamod.bitstart = ph[i].part_off;
		fpgamod.bitend = fpgamod.bitstart + ph[i].part_len;
		fpgamod.bittotend = fpgamod.bitstart + ph[i].tot_part_len;
		tmp = fpgamod.bitend;
		if (ph[i].hash_data_off) {
			if (ph[i].hash_data_off < tmp) {
				ret = -ERR_PHDR(0, EER_INVDATA);
				goto invalid_bi;
			}

			fpgamod.bithashstart = ph[i].hash_data_off;
			fpgamod.bithashend = fpgamod.bithashstart + HASH_LEN;
			tmp = fpgamod.bithashend;
		}
		if ((ph[i].part_attr & ALIH_PH_ATTRIB_AUTH_TYPE_MASK)
		    != ALIH_PH_ATTRIB_AUTH_TYPE_NONE) {
			if (ph[i].ac_off < tmp) {
				ret = -ERR_PHDR(0, EER_INVDATA);
				goto invalid_bi;
			}

			fpgamod.bitacstart = ph[i].ac_off;
			fpgamod.bitacend = fpgamod.bitacstart + ALAC_LENGTH;
		}

		goto suc_bi;
	}

	ret = -ERR_PHDR(0, EER_BITNOTFOUND);

invalid_bi:
	FM_SET_ERR();
	return ret;

not_bi:
	if (fpgamod.efusectl &
	    (EFUSE_AUTH_TYPE_MASK | EFUSE_ENC_TYPE_MASK))
		return -ERR_IMGHDR(EOP_BITDATA, EER_NOTACCEPT);
	return 0;

suc_bi:
	fpgamod.flag |= FM_FLG_BOOTIMG;
	return 1;
}

int fpga_mod_load(void *buf, u64 len)
{
	u64 sz;
	u32 tmp;
	int ret = 0;

	if (FM_CHK_ERR())
		return -ERR_LOAD(0, EER_INERR);

	if (fpgamod.step == FM_STP_STARTED) {
		ret = fpga_mod_handle_imghdr(buf, len);
		if (ret < 0)
			goto fail;
		tmp = ret;

		fpgamod.flag |= FM_FLG_PCAPST;
		ret = fpga_prog_start();
		if (ret < 0)
			goto fail;

		fpgamod.step = FM_STP_LOADING;
		if (tmp > 0) {
			if (fpgamod.bitstart >= len) {
				fpgamod.imgoff = len;
				return 0;
			}
			fpgamod.imgoff = fpgamod.bitstart;
			buf = buf + fpgamod.imgoff;
			len = len - fpgamod.imgoff;
		} else {
			fpgamod.bitstart = 0;
			fpgamod.bitend = -1;
			fpgamod.imgoff = 0;
		}
	} else if (fpgamod.step != FM_STP_LOADING) {
		ret = -ERR_LOAD(0, EER_NOTSTARTED);
		goto fail;
	}

	ret = 0;
	while (len > 0) {
		if (!(fpgamod.flag & FM_FLG_BOOTIMG)) {
			sz = len;
			ret = fpga_mod_load_data(buf, sz);
			cost_data(sz);
			break;
		}

		if (fpgamod.imgoff < fpgamod.bitstart) {
			tmp = fpgamod.bitstart - fpgamod.imgoff;
			sz = (len > tmp) ? tmp : len;
			cost_data(sz);
			continue;
		}

		if (fpgamod.imgoff < fpgamod.bitend) {
			tmp = fpgamod.bitend - fpgamod.imgoff;
			sz = (len > tmp) ? tmp : len;
			ret = fpga_mod_load_data(buf, sz);
			cost_data(sz);
			if (ret < 0)
				break;
			continue;
		}

		if (fpgamod.imgoff < fpgamod.bithashstart) {
			tmp = fpgamod.bithashstart - fpgamod.imgoff;
			sz = (len > tmp) ? tmp : len;
			cost_data(sz);
			continue;
		}

		if (fpgamod.imgoff < fpgamod.bithashend) {
			save_data(hash);
			if (fpgamod.imgoff == fpgamod.bithashend)
				fpgamod.flag |= FM_FLG_PTHASH;
			continue;
		}

		if (fpgamod.imgoff < fpgamod.bitacstart) {
			tmp = fpgamod.bitacstart - fpgamod.imgoff;
			sz = (len > tmp) ? tmp : len;
			cost_data(sz);
			continue;
		}

		if (fpgamod.imgoff < fpgamod.bitacend) {
			save_data(ac);
			if (fpgamod.imgoff == fpgamod.bitacend)
				fpgamod.flag |= FM_FLG_PTAC;
			continue;
		}

		sz = len;
		cost_data(sz);
	}

fail:
	if (ret < 0)
		FM_SET_ERR();
	return ret;
}

int fpga_mod_done(u32 done)
{
	int ret = 0, tmp;

	if (fpgamod.step == FM_STP_UNINIT)
		return -ERR_DONE(0, EER_NOTSTARTED);

	if (FM_CHK_ERR())
		done = 0;

	if (fpgamod.step == FM_STP_LOADING) {
		if (done && fpgamod.flag & FM_FLG_BOOTIMG) {
			if (fpgamod.bitend > fpgamod.imgoff) {
				done = 0;
				FM_SET_ERR();
				ret = -ERR_DONE(0, EER_UNCOMPLETEDATA);
			} else {
				ret = fpga_mod_part_auth();
				if (ret < 0) {
					FM_SET_ERR();
					done = 0;
				}
			}
		}
	}

	if (fpgamod.flag & FM_FLG_PCAPST) {
		tmp = fpga_prog_done(done);
		fpgamod.flag &= ~FM_FLG_PCAPST;
		if (!ret)
			ret = tmp;
	}

	fpgamod.step = FM_STP_INITED;
	return ret;
}

int fpga_mod_init(void *buf, u32 len)
{
	if (len < BLOCK_MIN_SIZE)
		return -ERR_INIT(EER_NOBUF);

	fpgamod.blkbuf = buf;
	fpgamod.blklen = BLOCK_MIN_SIZE;

	if (crypto_mod_init(buf + BLOCK_MIN_SIZE, len - BLOCK_MIN_SIZE) < 0)
		return -ERR_INIT(EER_CRYPTINIT);

	fpgamod.step = FM_STP_INITED;
	return 0;
}

static int fpga_prog_start(void)
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

	return -ERR_START(EER_INITPCAP);
}

static int fpga_prog_load(void *p, u64 len)
{
	u32 *addr, cnt, i;

	if (len & 0x3)
		return -ERR_LOAD(0, EER_INVDATALEN);

	addr = (u32 *)p;
	cnt = (u32)(len/sizeof(u32));
	for (i=0; i<cnt; i++) {
		fpga_writel(addr[i], CSU_PCAP_WR_STREAM);
	}

	return 0;
}

static int fpga_check_prog_done(void)
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

static int fpga_prog_done(u32 done)
{
	int i, ret;
	u32 val;

	ret = 0;

	if (!done) {
		// reset pl
		val = fpga_readl(SYSCTRL_S_GLOBAL_SRSTN);
		fpga_writel(val&~SYSCTRL_S_GLOBAL_SRSTN_MSK_GLB_PL_SRST, SYSCTRL_S_GLOBAL_SRSTN);
		platform_udelay(50);
		fpga_writel(val|SYSCTRL_S_GLOBAL_SRSTN_MSK_GLB_PL_SRST, SYSCTRL_S_GLOBAL_SRSTN);
		platform_udelay(50);
	} else if (!fpga_check_prog_done()) {
		ret = -ERR_DONE(0, EER_PCAPSTAT);
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

static int fpga_plclk_reset(u32 reset)
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
	int ret;

	if (funcid == ALSIP_FPGA_PROG_START)
		ret = fpga_mod_start();
	else if (funcid == ALSIP_FPGA_PROG_LOAD)
		ret = fpga_mod_load((void *)regs->a0, (u64)regs->a1);
	else if (funcid == ALSIP_FPGA_PROG_DONE)
		ret = fpga_mod_done((u32)regs->a0);
	else if (funcid == ALSIP_FPGA_PROG_INIT)
		ret = fpga_mod_init((void *)regs->a0, (u64)regs->a1);
	else if (funcid == ALSIP_FPGA_PLCLK_RST)
		ret = fpga_plclk_reset((u32)regs->a0);
	else
		return SBI_ENOTSUPP;

	*out_value = ret;
	return SBI_SUCCESS;
}
