// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Anlogic, Inc. All rights reserved.
 */

#include <sbi/riscv_asm.h>
#include <sbi/riscv_io.h>
#include <sbi/sbi_const.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_console.h>
#include <hardware.h>
#include <crypto.h>

// bit[0]:     0--ECB, 1--CBC
#define SYM_ECB (0x00)
#define SYM_CBC (0x01)

// bit[3]:     0--enc, 1--dec
#define SYM_ENCRYPT  (0x00)
#define SYM_DECRYPT  (0x08)

// bit[6:4]:   001--128, 010--192, 100--256
#define SYM_128BIT  (0x10)
#define SYM_192BIT  (0x20)
#define SYM_256BIT  (0x40)

#define CRPT_HASH_TIMEOUT(len) ((((len) / 1024) + 1) * 300)
#define CRPT_DMA_TIMEOUT(len) ((((len) / 1024) + 1) * 300)
#define CRPT_AUTH_TIMEOUT()	10000

enum csu_msg_cmd {
	CSU_CMD_AUTH = 0xCD01,
	CSU_CMD_DMA = 0xCD02,
	CSU_CMD_ENCRYPT = 0xCD03,
	CSU_CMD_HASH = 0xCD04,
	CSU_CMD_SIGN = 0xCD05,
	CSU_CMD_GENKEY = 0xCD06,
	CSU_CMD_GETZ = 0xCD07,
	CSU_CMD_ACK = 0xAC01,
};

enum csu_ack_option {
	CSU_ACK_AUTH_PASS = 0x69,
	CSU_ACK_AUTH_FAIL = 0x6A,
	CSU_ACK_DMA_DONE = 0x6B,
	CSU_ACK_ENCRYPT_DONE = 0x6C,
	CSU_ACK_HASH_DONE = 0x6D,
	CSU_ACK_SIGN_DONE = 0x6E,
	CSU_ACK_GENKEY_DONE = 0x6F,
	CSU_ACK_GETZ_DONE = 0x71,
	CSU_ACK_CMD_ERROR = 0xE1,
	CSU_ACK_CSU_ERROR = 0xE2,
	CSU_ACK_CSU_TIMEOUT = 0xE3,
	CSU_ACK_CSU_SELECT_KEY_ERROR = 0xE4,
	CSU_ACK_DMA_ERROR = 0xE5,
};

struct msg_opt_def {
	u32 opt0_low:8;
	u32 opt0_high:8;
	u32 opt1_low:8;
	u32 opt1_high:8;
};

union dma_op_mode_def {
	struct {
		u32 ecb_cbc   :  1;
		u32 reserved0 :  2;
		u32 enc_dec   :  1;
		u32 aes_len   :  3;
		u32 reserved1 : 25;
	};
	u32 bits;
};

struct dma_param_def {
	union dma_op_mode_def op_mode;
	u32  key_addr;
	u32  iv_addr;
	u32  input_addr;
	u32  total_length;
	u32  output_addr;
	u32  hash_out_addr;
};

struct auth_param_def {
	u32 pub_key_addr;
	u32 digest_addr;
	u32 signature_addr;
};

struct hash_param_def {
	u32 input_addr;
	u32 total_length;
	u32 hash_out_addr;
};

struct signature_param_def {
	u32 pri_key_addr;
	u32 digest_addr;
	u32 signature_addr;
};

struct key_pair_gen_param_def {
	u32 pub_key_addr;
	u32 pri_key_addr;
};

struct sec_msg_def {
	u32 cmd;
	struct msg_opt_def option;
	union {
		struct auth_param_def       auth_param;
		struct hash_param_def       hash_param;
		struct dma_param_def        dma_param;
		struct signature_param_def  signature_param;
		struct key_pair_gen_param_def key_pair_gen_param;
		u32           data[7];
	};
};

struct ack_def {
	u32  cmd;
	struct msg_opt_def option;
};

struct work_buf {
	u8 hash[HASH_LEN];
	u8 iv[IV_LEN];
	u8 key[KEY_LEN];
	u8 spk[SPK_LEN];
	u8 sig[SIG_LEN];
};

struct crypto_mod {
	struct work_buf *wbuf;
	u32 wbuf_len;
};

extern void platform_udelay(unsigned long usec);

static struct crypto_mod crypto;

int crypto_send_msg_and_wait(struct sec_msg_def *msg,
			     unsigned long timeout /*us*/)
{
	struct sec_msg_def volatile *csu_msg = (void *)CSU_MSG_RAM;
	struct ack_def volatile *csu_ack = (void *)(CSU_MSG_RAM + 64);
	unsigned long i;
	int status;
	u32 ack;

	csu_msg->cmd = msg->cmd;
	csu_msg->option = msg->option;
	for (i = 0; i < 7; i++)
		csu_msg->data[i] = msg->data[i];
	csu_ack->cmd = 0;

	// trigger csu
	writel(1, (void *)RPU2CSU_REQ_ADDR);
	writel(0, (void *)RPU2CSU_REQ_ADDR);

	timeout = (timeout + 49) / 50;
	while (timeout && readl(&csu_ack->cmd) != CSU_CMD_ACK) {
		platform_udelay(50);
		timeout--;
	}

	if (readl(&csu_ack->cmd) != CSU_CMD_ACK) {
		status = -CRYPTO_ERR_ACK_TIMEOUT;
		goto ack_ret;
	}

	ack = (readl(&csu_ack->option) & 0xFF);

	if (ack == CSU_ACK_DMA_DONE ||
	    ack == CSU_ACK_ENCRYPT_DONE ||
	    ack == CSU_ACK_HASH_DONE ||
	    ack == CSU_ACK_SIGN_DONE ||
	    ack == CSU_ACK_GENKEY_DONE ||
	    ack == CSU_ACK_GETZ_DONE ||
	    ack == CSU_ACK_AUTH_PASS) {
		status = 0;
	} else {
		status = -ack;
		goto ack_ret;
	}

	status = 0;
ack_ret:
	return status;
}

int crypto_hash(unsigned long data, u32 len,
			 enum crypto_block_mode blk_mode,
			 struct crypto_hash_param *hash_para)
{
	struct sec_msg_def msg;
	int ret;

	if (!crypto.wbuf)
		return -CRYPTO_ERR_NOT_INIT;

	if (!hash_para || crypto_verify_op_hash(hash_para->hash_type) ||
	    crypto_verify_block_mode(blk_mode))
		return -CRYPTO_ERR_INVALID_PARAM;

	if (hash_para->hash_type == CRPT_OP_HASH_NONE)
		return 0;

	if (crypto_verify_buf(data, len))
		return -CRYPTO_ERR_INVALID_PARAM;

	clr_mem(&msg, sizeof(msg));
	msg.cmd = CSU_CMD_HASH;
	msg.option.opt0_low = hash_para->hash_type;
	msg.option.opt1_high = (blk_mode << 2);
	msg.hash_param.input_addr = (u32)data;
	msg.hash_param.total_length = len;
	msg.hash_param.hash_out_addr = PTR2U32(&crypto.wbuf->hash);
	if (blk_mode == CRPT_BLOCK_WHOLE ||
	    blk_mode == CRPT_BLOCK_FIRST)
		clr_mem(crypto.wbuf->hash, sizeof(crypto.wbuf->hash));

	ret = crypto_send_msg_and_wait(&msg, CRPT_HASH_TIMEOUT(len));
	if (ret)
		return ret;

	if (blk_mode == CRPT_BLOCK_WHOLE ||
	    blk_mode == CRPT_BLOCK_LAST)
		cpy_mem(hash_para->hash_output, crypto.wbuf->hash,
			sizeof(crypto.wbuf->hash));
	return 0;
}

int crypto_auth(struct crypto_auth_param *auth_para)
{
	struct sec_msg_def msg;
	int ret;

	if (!crypto.wbuf)
		return -CRYPTO_ERR_NOT_INIT;

	if (!auth_para || crypto_verify_op_auth(auth_para->auth_type))
		return -CRYPTO_ERR_INVALID_PARAM;

	if (auth_para->auth_type == CRPT_OP_AUTH_NONE)
		return 0;

	clr_mem(&msg, sizeof(msg));
	msg.cmd = CSU_CMD_AUTH;
	msg.option.opt0_low = auth_para->auth_type;
	cpy_mem(crypto.wbuf->spk, auth_para->spk, sizeof(crypto.wbuf->spk));
	cpy_mem(crypto.wbuf->sig, auth_para->sig, sizeof(crypto.wbuf->sig));
	cpy_mem(crypto.wbuf->hash, auth_para->hash, sizeof(crypto.wbuf->hash));
	msg.auth_param.pub_key_addr = PTR2U32(crypto.wbuf->spk);
	msg.auth_param.digest_addr = PTR2U32(crypto.wbuf->hash);
	msg.auth_param.signature_addr = PTR2U32(crypto.wbuf->sig);

	ret = crypto_send_msg_and_wait(&msg, CRPT_AUTH_TIMEOUT());
	if (ret)
		return ret;

	return 0;
}

int crypto_auth2(unsigned long data, u32 len,
			  u8 hashtype, u8 authtype,
			  u8 *key, u8 *sig)
{
	struct crypto_hash_param hashpara;
	struct crypto_auth_param authpara;
	int ret;

	hashpara.hash_type = hashtype;
	ret = crypto_hash(data, len, CRPT_BLOCK_WHOLE, &hashpara);
	if (ret < 0)
		return ret;

	authpara.auth_type = authtype;
	cpy_mem(authpara.hash, hashpara.hash_output, sizeof(authpara.hash));
	cpy_mem(authpara.spk, key, sizeof(authpara.spk));
	cpy_mem(authpara.sig, sig, sizeof(authpara.sig));
	ret = crypto_auth(&authpara);
	if (ret < 0)
		return ret;
	return 0;
}

int crypto_dma(unsigned long data, u32 len,
	       enum crypto_block_mode blk_mode,
	       enum crypto_addr_incr addrincr,
	       struct crypto_dec_param *dec_para,
	       struct crypto_hash_param *hash_para,
	       unsigned long output)
{
	struct sec_msg_def msg;
	int ret;

	if (!crypto.wbuf)
		return -CRYPTO_ERR_NOT_INIT;

	if (dec_para &&
	    (crypto_verify_op_encrypt(dec_para->enc_type) ||
	     crypto_verify_key_mode(dec_para->key_mode))
	   )
		return -CRYPTO_ERR_INVALID_PARAM;

	if ((hash_para && crypto_verify_op_hash(hash_para->hash_type)) ||
	    crypto_verify_block_mode(blk_mode))
		return -CRYPTO_ERR_INVALID_PARAM;

	if (dec_para->enc_type == CRPT_OP_ENCRYPT_NONE &&
	    hash_para->hash_type != CRPT_OP_HASH_NONE)
		return -CRYPTO_ERR_INVALID_PARAM;

	if (crypto_verify_buf(data, len))
		return -CRYPTO_ERR_INVALID_PARAM;

	clr_mem(&msg, sizeof(msg));
	msg.cmd = CSU_CMD_DMA;
	msg.dma_param.input_addr = data;
	msg.dma_param.total_length = len;
	msg.dma_param.output_addr = output;

	msg.dma_param.key_addr = 0;
	msg.dma_param.iv_addr = 0;
	msg.dma_param.hash_out_addr = 0;

	msg.option.opt0_low = CRPT_OP_ENCRYPT_NONE;
	msg.option.opt0_high = CRPT_OP_HASH_NONE;
	msg.option.opt1_low = CRPT_KM_BHDR_KEY;
	msg.option.opt1_high = ((blk_mode << 2) | addrincr);

	msg.dma_param.op_mode.bits = SYM_256BIT | SYM_ECB;

	if (dec_para && dec_para->enc_type != CRPT_OP_ENCRYPT_NONE) {
		cpy_mem(crypto.wbuf->iv, dec_para->iv, sizeof(crypto.wbuf->iv));
		cpy_mem(crypto.wbuf->key, dec_para->key, sizeof(crypto.wbuf->key));
		msg.dma_param.key_addr = PTR2U32(&crypto.wbuf->key);
		msg.dma_param.iv_addr = PTR2U32(&crypto.wbuf->iv);
		if (dec_para->decode)
			msg.dma_param.op_mode.bits |= SYM_DECRYPT;
		msg.option.opt0_low = dec_para->enc_type;
		msg.option.opt1_low = dec_para->key_mode;
	}

	if (hash_para && hash_para->hash_type != CRPT_OP_HASH_NONE) {
		if (blk_mode == CRPT_BLOCK_WHOLE ||
		    blk_mode == CRPT_BLOCK_FIRST)
			clr_mem(crypto.wbuf->hash, sizeof(crypto.wbuf->hash));
		msg.dma_param.hash_out_addr = PTR2U32(&crypto.wbuf->hash);
		msg.option.opt0_high = hash_para->hash_type;
	}

	ret = crypto_send_msg_and_wait(&msg, CRPT_DMA_TIMEOUT(len));
	if (ret)
		return ret;

	if (hash_para && hash_para->hash_type != CRPT_OP_HASH_NONE) {
		if (blk_mode == CRPT_BLOCK_WHOLE ||
		    blk_mode == CRPT_BLOCK_LAST)
			cpy_mem(hash_para->hash_output, crypto.wbuf->hash,
				sizeof(crypto.wbuf->hash));
	}
	return 0;
}

u32 crypto_calc_crc32(void *buf, u32 len)
{
	u8 *p = buf;
	u8 i;
	u32 crc = 0xffffffff;

	while (len--) {
		crc ^= *p++;
		for (i = 0; i < 8; i++) {
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc = (crc >> 1);
		}
	}

	return (~crc);
}

int crypto_mod_init(void *buf, u32 len)
{
	if (crypto_verify_buf((unsigned long)buf, len))
		return -1;

	if (len < sizeof(struct work_buf))
		return -1;

	crypto.wbuf = buf;
	crypto.wbuf_len = len;
	return 0;
}

void crypto_mod_deinit(void)
{
	crypto.wbuf = NULL;
	crypto.wbuf_len = 0;
}
