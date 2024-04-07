/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) Anlogic Corporation or its affiliates.
 *
 * DR1V90_UART.H
 *
 * Created on: 2021年9月17日
 * Author: wei.pang
 */

/**
 ****************************************************************************************
 * @defgroup UART
 * @ingroup DRIVERS
 * @brief UART Drivers.
 *        Functions specified for UART.
 *
 * @{
 ****************************************************************************************
 */

#ifndef _DR1V90_UART_H
#define _DR1V90_UART_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sbi/sbi_types.h>

/* Register offsets */
#define UART_REG_RBR		0x00
#define UART_REG_THR		0x00
#define UART_REG_DLL		0x00
#define UART_REG_DLH		0x04
#define UART_REG_IER		0x04
#define UART_REG_IIR		0x08
#define UART_REG_FCR		0x08
#define UART_REG_LCR		0x0C
#define UART_REG_MCR		0x10
#define UART_REG_LSR		0x14
#define UART_REG_MSR		0x18
#define UART_REG_SCR		0x1c
#define UART_REG_FAR		0x70
#define UART_REG_TFR		0x74
#define UART_REG_RFW		0x78
#define UART_REG_USR		0x7C
#define UART_REG_TFL		0x80
#define UART_REG_RFL		0x84
#define UART_REG_CPR		0xF4

#define __IOM volatile

typedef struct{
	__IOM uint32_t RBR_THR_DLL;		// 0x00
	__IOM uint32_t DLH_IER;			// 0x04
	__IOM uint32_t IIR_FCR;			// 0x08
	__IOM uint32_t LCR;			// 0x0c
	__IOM uint32_t MCR;			// 0x10
	__IOM uint32_t LSR;			// 0X14
	__IOM uint32_t MSR;			// 0X18	
	__IOM uint32_t SCR;			// 0x1c
	__IOM uint32_t reserved_reg1[20];	// 0x20-0x70
	__IOM uint32_t FAR;			// 0x70
	__IOM uint32_t TFR;			// 0x74
	__IOM uint32_t RFW;			// 0x78
	__IOM uint32_t USR;			// 0x7c
	__IOM uint32_t TFL;			// 0x80
	__IOM uint32_t RFL;			// 0x84
}UART_DR1V90_TypeDef;

/*******************  Bit definition for UART_REG_IER register  ********************/
/*
	Enable Received Data Available Interrupt. 
 */
#define UART_REG_IER_ERBFI   (0)
#define UART_REG_IER_ERBFI_MASK  (0x1 << UART_REG_IER_ERBFI)

/*
	Enable Transmit Holding Register Empty Interrupt. 
 */ 
#define UART_REG_IER_ETBEI   (1)
#define UART_REG_IER_ETBEI_MASK  (0x1 << UART_REG_IER_ETBEI)

/*
	Enable Receiver Line Status Interrupt. 
 */ 
#define UART_REG_IER_ELSI   (2)
#define UART_REG_IER_ELSI_MASK  (0x1 << UART_REG_IER_ELSI)

/*
	Enable Modem Status Interrupt. 
 */ 
#define UART_REG_IER_EDSSI   (3)
#define UART_REG_IER_EDSSI_MASK  (0x1 << UART_REG_IER_EDSSI)
/*
	Programmable THRE Interrupt Mode Enable.
 */
#define UART_REG_IER_PTIME   (7)
#define UART_REG_IER_PTIME_MASK  (0x1 << UART_REG_IER_PTIME)
 
 
/*******************  Bit definition for UART_REG_IIR register  ********************/
/*
	Interrupt ID 
 */
#define UART_REG_IIR_IID_MASK  ((uint8_t) 0x07)

/*
	FIFOs Enabled. 
 */
#define UART_REG_IIR_FIFOSE   (0)   
#define UART_REG_IIR_FIFOSE_MASK   

/*******************  Bit definition for UART_REG_FCR register  ********************/
/*
	FIFO Enable. 
 */
#define UART_REG_FCR_FIFOE   (0)
#define UART_REG_FCR_FIFOE_MASK  (0x1 << UART_REG_FCR_FIFOE)

/*
	RCVR FIFO Reset. 
 */ 
#define UART_REG_FCR_RFIFOR   (1)
#define UART_REG_FCR_RFIFOR_MASK  (0x1 << UART_REG_FCR_RFIFOR)

/*
	XMIT FIFO Reset. 
 */ 
#define UART_REG_FCR_XFIFOR   (2)
#define UART_REG_FCR_XFIFOR_MASK  (0x1 << UART_REG_FCR_XFIFOR)

/*
	DMA Mode.
 */ 
#define UART_REG_FCR_DMAM   (3)
#define UART_REG_FCR_DMAM_MASK  (0x1 << UART_REG_FCR_DMAM)

/*
	TX Empty Trigger.  
 */
#define UART_REG_FCR_TET   (4)
#define UART_REG_FCR_TET_MASK  (0x3 << UART_REG_FCR_TET)

/*
	RCVR Trigger. 
 */
#define UART_REG_FCR_RCVR   (6)
#define UART_REG_FCR_RCVR_MASK  (0x3 << UART_REG_FCR_RCVR)
 
/*******************  Bit definition for UART_REG_LCR register  ********************/
/*
	Data Length Select.  
 */
#define UART_REG_LCR_DLS_5BITS  				((uint8_t)0x00)
#define UART_REG_LCR_DLS_6BITS  				((uint8_t)0x01)
#define UART_REG_LCR_DLS_7BITS  				((uint8_t)0x02)
#define UART_REG_LCR_DLS_8BITS  				((uint8_t)0x03)

/*
	Number of stop bits.
 */ 
#define UART_REG_LCR_STOP_1BITS  ((uint8_t)0x00);
#define UART_REG_LCR_STOP_2BITS  ((uint8_t)0x04)

/*
	Parity Enable.
 */ 
#define UART_REG_LCR_PEN   (3)
#define UART_REG_LCR_PEN_MASK  (0x1 << UART_REG_LCR_PEN)

/*
	Even Parity Select. 
 */ 
#define UART_REG_LCR_EPS   (4)
#define UART_REG_LCR_EPS_MASK  (0x1 << UART_REG_LCR_EPS)

/*
	Stick Parity.  
 */
#define UART_REG_LCR_STICK_PARITY   (5)
#define UART_REG_LCR_STICK_PARITY_MASK  (0x1 << UART_REG_LCR_STICK_PARITY)

/*
	Break Control Bit. 
 */
#define UART_REG_LCR_BREAK   (6)
#define UART_REG_LCR_BREAK_MASK  (0x1 << UART_REG_LCR_BREAK)

/*
	Divisor Latch Access Bit.
 */ 
#define UART_REG_LCR_DLAB   (7)
#define UART_REG_LCR_DLAB_MASK  (0x1 << UART_REG_LCR_DLAB)
 
/*******************  Bit definition for UART_REG_MCR register  ********************/
/*
	Data Terminal Ready. 
 */
#define UART_REG_MCR_DTR   (0)
#define UART_REG_MCR_DTR_MASK  (0x1 << UART_REG_MCR_DTR)

/*
	Request to Send. 
 */ 
#define UART_REG_MCR_RTS   (1)
#define UART_REG_MCR_RTS_MASK  (0x1 << UART_REG_MCR_RTS)

/*
	out1. 
 */ 
#define UART_REG_MCR_OUT1   (2)
#define UART_REG_MCR_OUT1_MASK  (0x1 << UART_REG_MCR_OUT1)

/*
	out2. 
 */ 
#define UART_REG_MCR_OUT2   (3)
#define UART_REG_MCR_OUT2_MASK  (0x1 << UART_REG_MCR_OUT2)

/*
	LoopBack Bit.  
 */
#define UART_REG_MCR_LoopBack   (4)
#define UART_REG_MCR_LoopBack_MASK  (0x1 << UART_REG_MCR_LoopBack)

/*
	Auto Flow Control Enable. 
 */
#define UART_REG_MCR_ACFE   (5)
#define UART_REG_MCR_ACFE_MASK  (0x1 << UART_REG_MCR_ACFE)

/*
	SIR Mode Enable. 
 */ 
#define UART_REG_MCR_SIRE   (6)
#define UART_REG_MCR_SIRE_MASK  (0x1 << UART_REG_MCR_SIRE)

/*******************  Bit definition for UART_REG_LSR register  ********************/
/*
	Data Ready bit.  
 */
#define UART_REG_LSR_DR   (0)
#define UART_REG_LSR_DR_MASK  (0x1 << UART_REG_LSR_DR)

/*
	Overrun error bit. 
*/ 
#define UART_REG_LSR_OE   (1)
#define UART_REG_LSR_OE_MASK  (0x1 << UART_REG_LSR_OE)

/*
	Parity Error bit.
*/ 
#define UART_REG_LSR_PE   (2)
#define UART_REG_LSR_PE_MASK  (0x1 << UART_REG_LSR_PE)

/*
	Framing Error bit.
*/ 
#define UART_REG_LSR_FE   (3)
#define UART_REG_LSR_FE_MASK  (0x1 << UART_REG_LSR_FE)

/*
	Break Interrupt bit.
*/
#define UART_REG_LSR_BI   (4)
#define UART_REG_LSR_BI_MASK  (0x1 << UART_REG_LSR_BI)

/*
	Transmit Holding Register Empty bit.
*/
#define UART_REG_LSR_THRE   (5)
#define UART_REG_LSR_THRE_MASK  (0x1 << UART_REG_LSR_THRE)
#define UART_REG_LSR_THRE_offset_MASK  (0x0 << UART_REG_LSR_THRE)

/*
	Transmitter Empty bit.
*/ 
#define UART_REG_LSR_TEMT   (6)
#define UART_REG_LSR_TEMT_MASK  (0x1 << UART_REG_LSR_TEMT)

/*
	Receiver FIFO Error bit.
*/ 
#define UART_REG_LSR_RFE   (7)
#define UART_REG_LSR_RFE_MASK  (0x1 << UART_REG_LSR_RFE)

/*******************  Bit definition for UART_REG_MSR register  ********************/
/*******************  Bit definition for UART_REG_SCR register  ********************/
/*******************  Bit definition for UART_REG_FAR register  ********************/
#define UART_REG_FAR_FIFOAR   (0)
#define UART_REG_FAR_FIFOAR_MASK  (0x1 << UART_REG_FAR_FIFOAR) 
/*******************  Bit definition for UART_REG_TFR register  ********************/
/*******************  Bit definition for UART_REG_RFW register  ********************/
/*******************  Bit definition for UART_REG_USR register  ********************/
/*
	Framing Error bit.
 */ 
#define UART_REG_USR_BUSY   (16)
#define UART_REG_USR_BUSY_MASK  (0x7 << UART_REG_USR_BUSY)

/*
	Break Interrupt bit.
 */
#define UART_REG_USR_TFNF   (16)
#define UART_REG_USR_TFNF_MASK  (0x7 << UART_REG_USR_TFNF)

/*
	Transmit Holding Register Empty bit.
 */
#define UART_REG_USR_TFE   (16)
#define UART_REG_USR_TFE_MASK  (0x7 << UART_REG_USR_TFE)

/*
	Transmitter Empty bit.
 */ 
#define UART_REG_USR_RFNE   (16)
#define UART_REG_USR_RFNE_MASK  (0x7 << UART_REG_USR_RFNE)

/*
	Receiver FIFO Error bit.
 */ 
#define UART_REG_USR_RFF   (16)
#define UART_REG_USR_RFF_MASK  (0x7 << UART_REG_USR_RFF)

/*******************  Bit definition for UART_REG_TFL register  ********************/
/*******************  Bit definition for UART_REG_RFL register  ********************/
/*******************  Bit definition for UART_REG_CPR register  ********************/
 
typedef enum DR1V90_uart_stop_bit {
	DR1V90_UART_STOP_BIT_1 = 0,
	DR1V90_UART_STOP_BIT_1p5 = 1,
	DR1V90_UART_STOP_BIT_2 = 2
} DR1V90_UART_STOP_BIT;

typedef enum DR1V90_uart_pariy_bit {
	UART_EVEN_BIT = 0,
	UART_ODD_BIT = 1,
} DR1V90_UART_PARITY_BIT;


typedef enum DR1V90_uart_bit_length {
	UART_BIT_LENGTH_5 = 0 ,
	UART_BIT_LENGTH_6 = 1 ,
	UART_BIT_LENGTH_7 = 2 ,
	UART_BIT_LENGTH_8 = 3 ,
} DR1V90_UART_BIT_LENGTH;

/*!
    \brief  uart initialize
    \param  uart: uart parameter stuct
    \param  uart_clock: uart clock
    \param  baudrate: uart buadrate
    \param  bit_length: bit length (5/6/7/8/9)
    \retval 0,if uart!=null; otherwise -1;
*/
int32_t dr1v90_uart_init(UART_DR1V90_TypeDef *uart, uint32_t uart_clock,
	       uint32_t baudrate, DR1V90_UART_BIT_LENGTH bit_length);
/*!
    \brief  uart stop bit config
    \param  uart: uart parameter stuct
    \param  stopbit: stop bit (1/2/0.5/1.5)
    \retval 0,if uart!=null; otherwise -1;
*/
int32_t dr1v90_uart_config_stopbit(UART_DR1V90_TypeDef *uart, DR1V90_UART_STOP_BIT stopbit);
/*!
    \brief  uart TXFIFO transmitte
    \param  uart: uart parameter stuct
    \param  val: value of TXFIFO
    \retval 0,if uart!=null; otherwise -1;
*/
void dr1v90_uart_write(UART_DR1V90_TypeDef *uart, char val);
/*!
    \brief  uart FIFOF enable
    \param  uart: uart parameter stuct
    \retval FCR:  value
*/
uint8_t dr1v90_uart_fifo_enable(UART_DR1V90_TypeDef *uart);
/*!
    \brief  uart RXFIFO receive
    \param  uart: uart parameter stuct
    \retval RXFIFO value
*/
int dr1v90_uart_read(UART_DR1V90_TypeDef *uart);

#ifndef __RARELY
  #define __RARELY(exp)  __builtin_expect((exp), 0)
#endif

#ifdef __cplusplus
}
#endif
#endif /* _HBIRD_UART_H */


