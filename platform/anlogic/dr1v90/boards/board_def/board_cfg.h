#define DR1V90_UART0_ADDR	0xF8400000
#define DR1V90_UART1_ADDR	0xF8401000
#define DR1V90_UART		((UART_DR1V90_TypeDef *)DR1V90_UART0_ADDR)
#define uart_clock		(40000000UL)
#define uart_baud		(115200UL)
#define TIMER_CLOCK_RATE	50000000
#define DDR_BASE                0x00000000
#define DDR_SIZE                0x60000000
