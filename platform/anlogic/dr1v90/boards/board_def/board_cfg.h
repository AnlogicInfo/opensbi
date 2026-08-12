/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) Anlogic Corporation or its affiliates.
 *
 */
#include <anlogic-dr1v90-hpf.h>
#include <anlogic-dr1v90-settings.h>
#define DR1V90_UART		((UART_DR1V90_TypeDef *)ANLSDK_CONSOLE_UART_BASE)
#define uart_clock		(AL_UART_CLOCK)
#define uart_baud		(ANLSDK_CONSOLE_UART_BAUD)
#define TIMER_CLOCK_RATE	50000000
#define DDR_BASE                0x00000000
#define DDR_SIZE                0x60000000
