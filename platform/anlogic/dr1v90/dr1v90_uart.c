/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) Anlogic Corporation or its affiliates.
 *
 * DR1V90_UART.C
 *
 * Created on: 2021年9月17日
 * Author: wei.pang
 */

#include "dr1v90_uart.h"

/*!
    \brief  uart initialize
    \param  uart: uart parameter stuct
    \param  uart_clock: uart clock
    \param  baudrate: uart buadrate
    \param  bit_length: bit length (5/6/7/8)
    \retval 0,if uart!=null; otherwise -1;
*/
int32_t dr1v90_uart_init(UART_DR1V90_TypeDef *uart, uint32_t uart_clock,
		uint32_t baudrate, DR1V90_UART_BIT_LENGTH bit_length)
{
    if (__RARELY(uart == NULL)) {
        return -1;
    }

    uart->LCR 		 |= UART_REG_LCR_DLAB_MASK ;
    uart->DLH_IER 	  = ((uint16_t)(uart_clock / (baudrate*16))) >> 8 ;
    uart->RBR_THR_DLL = ((uint8_t)(uart_clock / (baudrate*16))) ;
    uart->MCR 		 |= UART_REG_MCR_DTR_MASK;
    uart->MCR 		 |= UART_REG_MCR_RTS_MASK;
    uart->LCR 		 &= (uint8_t)(0x7f);
    switch (bit_length)
    {
    case 0:
    	uart->LCR |= UART_REG_LCR_DLS_5BITS;//(bit_length<<UART_REG_LCR_DLS) & UART_REG_LCR_DLS_MASK;
    	break;
    case 1:
    	uart->LCR |= UART_REG_LCR_DLS_6BITS;//(bit_length<<UART_REG_LCR_DLS) & UART_REG_LCR_DLS_MASK;
    	break;
    case 2:
        uart->LCR |= UART_REG_LCR_DLS_7BITS;//(bit_length<<UART_REG_LCR_DLS) & UART_REG_LCR_DLS_MASK;
        break;
    default:
    	uart->LCR |= UART_REG_LCR_DLS_8BITS;
    	break;
    }

    return 0;
}

/*!
    \brief  uart stop bit config
    \param  uart: uart parameter stuct
    \param  stopbit: stop bit (1/2/0.5/1.5)
    \retval 0,if uart!=null; otherwise -1;
*/
int32_t dr1v90_uart_config_stopbit(UART_DR1V90_TypeDef *uart, DR1V90_UART_STOP_BIT stopbit)
{
   if (__RARELY(uart == NULL)) {
        return -1;
    }
   switch(stopbit)
   {
   case 0:
	   uart->LCR |=  UART_REG_LCR_STOP_1BITS;
	   break;
   case 1:
	   uart->LCR &= ~UART_REG_LCR_DLS_5BITS;
	   uart->LCR |=  UART_REG_LCR_STOP_2BITS;
	   break;
   default:
	   uart->LCR |=  UART_REG_LCR_STOP_2BITS;
	   break;
   }
   // uart->DLH_IER  |= UART_REG_IER_PTIME_MASK ;  pangwei
    return 0;
}
/*!
    \brief  uart FIFOF enable
    \param  uart: uart parameter stuct
    \retval FCR:  value
*/
uint8_t dr1v90_uart_fifo_enable(UART_DR1V90_TypeDef *uart)
{

    if (__RARELY(uart == NULL)) {
        return -1;
    }
    uart ->IIR_FCR = UART_REG_FCR_FIFOE_MASK;
    return 0;
}
/*!
    \brief  uart TXFIFO transmitte
    \param  uart: uart parameter stuct
    \param  val: value of TXFIFO
    \retval 0,if uart!=null; otherwise -1;
*/
void dr1v90_uart_write(UART_DR1V90_TypeDef *uart, char val)
{
   if (__RARELY(uart == NULL)) {
        return;
    }
    while ((uart ->LSR & 0x20)==0);
    uart->RBR_THR_DLL = val & 0xFF ;
}

/*!
    \brief  uart RXFIFO receive
    \param  uart: uart parameter stuct
    \retval RXFIFO value
    UART_DR1V90_TypeDef *uart
    DR1V90_UART0
*/
int dr1v90_uart_read(UART_DR1V90_TypeDef *uart)
{
    uint32_t reg;
    if (__RARELY(uart == NULL)) {
        return -1;
    }
    while ( 0 == ((uart ->LSR) & 0x01));
    reg = uart ->RBR_THR_DLL;
    return (uint8_t)(reg & 0xFF);
}

