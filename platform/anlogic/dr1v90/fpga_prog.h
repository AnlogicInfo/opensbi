/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Anlogic Inc.
 */
#ifndef _FPGA_PROG_H_
#define _FPGA_PROG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_CODE(step, op, err) \
	((((u32)(step) & 0xFF) << 16) | (((u32)(op) & 0xFF) << 8) | ((u32)(err) & 0xFF))

#define ERR_UNCLS(err)			ERR_CODE(0, 0, err)
#define ERR_INIT(err)			ERR_CODE(1, 0, err)
#define ERR_START(err)			ERR_CODE(2, 0, err)
#define ERR_LOAD(op, err)		ERR_CODE(3, 0, err)
#define ERR_IMGHDR(op, err)		ERR_CODE(4, 0, err)
#define ERR_ACVERI(op, err)		ERR_CODE(5, 0, err)
#define ERR_PHDR(op, err)		ERR_CODE(6, 0, err)
#define ERR_PARTAUTH(op, err)		ERR_CODE(7, 0, err)
#define ERR_DONE(op, err)		ERR_CODE(8, 0, err)

#define EOP_PPKVERI			0x01
#define EOP_PPKHASH			0x02
#define EOP_SPKVERI			0x03
#define EOP_SPKAUTH			0x04
#define EOP_BOOTHDR			0x05
#define EOP_PARTAUTH			0x06
#define EOP_BITDATA			0x07
#define EOP_IHVERI			0x08
#define EOP_IHAUTH			0x09
#define EOP_PHATTR			0x0a
#define EOP_PARTHASH			0x0b
#define EOP_PARTENC			0x0c

#define EER_TIMEOUT			0x02
#define EER_NOTSTARTED			0x03
#define EER_NOTINITED			0x04
#define EER_NOBUF			0x05
#define EER_CRYPTINIT			0x06
#define EER_INVDATALEN			0x07
#define EER_INERR			0x08
#define EER_HASH			0x09
#define EER_HASHSEL			0x0a
#define EER_HASHCMP			0x0b
#define EER_ACSEL			0x0c
#define EER_INVDATA			0x0d
#define EER_NOTACCEPT			0x0e
#define EER_ENCSEL			0x0f
#define EER_NOAC			0x10
#define EER_NOHASH			0x11
#define EER_UNCOMPLETEDATA		0x12
#define EER_INITPCAP			0x13
#define EER_PCAPSTAT			0x14
#define EER_BITNOTFOUND			0x15

int fpga_mod_init(void *buf, u32 len);
int fpga_mod_start(void);
int fpga_mod_load(void *buf, u64 len);
int fpga_mod_done(u32 done);

#ifdef __cplusplus
}
#endif

#endif
