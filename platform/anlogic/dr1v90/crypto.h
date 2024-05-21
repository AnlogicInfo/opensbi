/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2024 Anlogic, Inc.
 */
#ifndef _AN_CRYPTO_H_
#define _AN_CRYPTO_H_

#define CRYPTO_ERR_INVALID_PARAM           0x02U
#define CRYPTO_ERR_INVALID_CSU_ACK         0x03U
#define CRYPTO_ERR_CHECKSUM_ERROR          0x04U
#define CRYPTO_ERR_HASH_FAIL               0x05U
#define CRYPTO_ERR_NOT_INIT                0x06U
#define CRYPTO_ERR_ACK_TIMEOUT             0x07U
#define CRYPTO_ERR_AUTH_FAIL               0x6AU
#define CRYPTO_ERR_CMD_ERROR               0xE1U
#define CRYPTO_ERR_CRYPTO_ERR              0xE2U
#define CRYPTO_ERR_CSU_TIMEOUT             0xE3U
#define CRYPTO_ERR_CSU_SELECT_KEY_ERROR    0xE4U
#define CRYPTO_ERR_DMA_ERROR               0xE5U

#define PTR2U32(p)	((uint32_t)(long)(p))

#define HASH_LEN			32U
#define SPK_LEN				64U
#define KEY_LEN				32U
#define IV_LEN				16U
#define SIG_LEN				64U

static inline void dump_mem(void *buf, long sz)
{
	long i;
	unsigned char *p = buf;

	for (i = 0; i < sz; i++) {
		sbi_printf("%02x ", p[i]);
		if (i % 16 == 15)
			sbi_printf("\n");
	}
	sbi_printf("\n");
}

static inline void clr_mem(void *buf, long sz)
{
	unsigned char *p = buf;

	while (sz > 0) {
		*p++ = 0;
		sz--;
	}
}

static inline void cpy_mem(void *buf, void *buf1, long sz)
{
	unsigned char *p = buf;
	unsigned char *p1 = buf1;

	while (sz > 0) {
		*p++ = *p1++;
		sz--;
	}
}

static inline int cmp_mem(void *buf, void *buf1, long sz)
{
	unsigned char *p = buf;
	unsigned char *p1 = buf1;

	while (sz > 0) {
		if (*p > *p1)
			return 1;
		else if (*p < *p1)
			return -1;
		p++;
		p1++;
		sz--;
	}
	return 0;
}

enum crypto_op_auth {
	CRPT_OP_AUTH_NONE = 0x00,
	CRPT_OP_AUTH_ECC256 = 0x61,
	CRPT_OP_AUTH_SM2 = 0x62,
};

static inline int crypto_verify_op_auth(enum crypto_op_auth op)
{
	if (op != CRPT_OP_AUTH_NONE &&
	    op != CRPT_OP_AUTH_ECC256 &&
	    op != CRPT_OP_AUTH_SM2)
		return -1;

	return 0;
}

enum crypto_op_encrypt {
	CRPT_OP_ENCRYPT_AES256 = 0x63,
	CRPT_OP_ENCRYPT_SM4 = 0x64,
	CRPT_OP_ENCRYPT_NONE = 0x65,
};

static inline int crypto_verify_op_encrypt(enum crypto_op_encrypt op)
{
	if (op != CRPT_OP_ENCRYPT_AES256 &&
	    op != CRPT_OP_ENCRYPT_SM4 &&
	    op != CRPT_OP_ENCRYPT_NONE)
		return -1;

	return 0;
}

enum crypto_op_hash {
	CRPT_OP_HASH_SHA256 = 0b10,
	CRPT_OP_HASH_SM3 = 0b11,
	CRPT_OP_HASH_NONE = 0b00,
};

static inline int crypto_verify_op_hash(enum crypto_op_hash op)
{
	if (op != CRPT_OP_HASH_SHA256 &&
	    op != CRPT_OP_HASH_SM3 &&
	    op != CRPT_OP_HASH_NONE)
		return -1;

	return 0;
}

enum crypto_key_mode {
	CRPT_KM_BHDR_KEY = 0x6E,
	CRPT_KM_USER_KEY = 0x6F,
};

static inline int crypto_verify_key_mode(enum crypto_key_mode mode)
{
	if (mode != CRPT_KM_BHDR_KEY &&
	    mode != CRPT_KM_USER_KEY)
		return -1;

	return 0;
}

enum crypto_addr_incr {
	CRPT_ADDR_BOTH_INCR = 0,
	CRPT_ADDR_DST_INCR = 1,
	CRPT_ADDR_SRC_INCR = 2,
	CRPT_ADDR_NONE_INCR = 3,
};

static inline int crypto_verify_addr_incr(enum crypto_addr_incr incr)
{
	if (incr != CRPT_ADDR_BOTH_INCR &&
	    incr != CRPT_ADDR_DST_INCR &&
	    incr != CRPT_ADDR_SRC_INCR &&
	    incr != CRPT_ADDR_NONE_INCR)
		return -1;

	return 0;
}

enum crypto_block_mode {
	CRPT_BLOCK_WHOLE = 0,
	CRPT_BLOCK_FIRST = 1,
	CRPT_BLOCK_LAST = 2,
	CRPT_BLOCK_MID = 3,
};

static inline int crypto_verify_block_mode(enum crypto_block_mode mode)
{
	if (mode != CRPT_BLOCK_WHOLE &&
	    mode != CRPT_BLOCK_FIRST &&
	    mode != CRPT_BLOCK_LAST &&
	    mode != CRPT_BLOCK_MID)
		return -1;

	return 0;
}

struct crypto_hash_param {
	enum crypto_op_hash hash_type;
	u8 hash_output[HASH_LEN];
};

struct crypto_dec_param {
	enum crypto_op_encrypt enc_type;
	enum crypto_key_mode key_mode;
	int decode;
	u8 iv[IV_LEN];
	u8 key[KEY_LEN];
};

struct crypto_auth_param {
	enum crypto_op_auth auth_type;
	u8 spk[SPK_LEN];
	u8 hash[HASH_LEN];
	u8 sig[SIG_LEN];
};

static inline int crypto_verify_buf(unsigned long addr, u32 len)
{
	if (addr > ((uint32_t)-1) || (addr + len) > ((uint32_t)-1))
		return -1;
	return 0;
}

uint32_t crypto_calc_crc32(void *buf, u32 len);
int crypto_hash(unsigned long data, u32 len, enum crypto_block_mode blk_mode,
		struct crypto_hash_param *hash_para);
int crypto_auth(struct crypto_auth_param *auth_para);
int crypto_auth2(unsigned long data, u32 len,
		 u8 hashtype, u8 authtype,
		 u8 *key, u8 *sig);
int crypto_dma(unsigned long data, u32 len,
	       enum crypto_block_mode blk_mode,
	       enum crypto_addr_incr addrincr,
	       struct crypto_dec_param *dec_para,
	       struct crypto_hash_param *hash_para,
	       unsigned long output);
int crypto_mod_init(void *buf, u32 len);
void crypto_mod_deinit(void);
#endif
