#ifndef _SPI_H
#define _SPI_H

#include <stdint.h>

uint8_t spi_send(uint8_t c);
void spi_init(void);
void gpio_comm_init(void);
#endif
