/*
 * Copyright (c) 2022 BrainCo.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DT_BINDINGS_CLOCK_GD32L23X_CLOCKS_H_
#define ZEPHYR_INCLUDE_DT_BINDINGS_CLOCK_GD32L23X_CLOCKS_H_

#include "gd32-clocks-common.h"

/**
 * @name Register offsets
 * @{
 */

#define GD32_AHB1EN_OFFSET       0x14U
#define GD32_APB1EN_OFFSET       0x1CU
#define GD32_APB2EN_OFFSET       0x18U

/** @} */

/**
 * @name Clock enable/disable definitions for peripherals
 * @{
 */

/* AHB1 peripherals */
#define GD32_CLOCK_DMA        GD32_CLOCK_CONFIG(AHB1EN, 0U)
#define GD32_CLOCK_SRAM0      GD32_CLOCK_CONFIG(AHB1EN, 2U)
#define GD32_CLOCK_FMC        GD32_CLOCK_CONFIG(AHB1EN, 4U)
#define GD32_CLOCK_CRC        GD32_CLOCK_CONFIG(AHB1EN, 6U)
#define GD32_CLOCK_SRAM1      GD32_CLOCK_CONFIG(AHB1EN, 7U)
#define GD32_CLOCK_GPIOA      GD32_CLOCK_CONFIG(AHB1EN, 17U)
#define GD32_CLOCK_GPIOB      GD32_CLOCK_CONFIG(AHB1EN, 18U)
#define GD32_CLOCK_GPIOC      GD32_CLOCK_CONFIG(AHB1EN, 19U)
#define GD32_CLOCK_GPIOD      GD32_CLOCK_CONFIG(AHB1EN, 20U)
#define GD32_CLOCK_GPIOF      GD32_CLOCK_CONFIG(AHB1EN, 22U)

/* AHB2 peripherals */
#define GD32_CLOCK_CAU        GD32_CLOCK_CONFIG(AHB2EN, 1U)
#define GD32_CLOCK_TRNG       GD32_CLOCK_CONFIG(AHB2EN, 3U)

/* APB1 peripherals */
#define GD32_CLOCK_TIMER1     GD32_CLOCK_CONFIG(APB1EN, 0U)
#define GD32_CLOCK_TIMER2     GD32_CLOCK_CONFIG(APB1EN, 1U)
#define GD32_CLOCK_TIMER5     GD32_CLOCK_CONFIG(APB1EN, 4U)
#define GD32_CLOCK_TIMER6     GD32_CLOCK_CONFIG(APB1EN, 5U)
#define GD32_CLOCK_TIMER11    GD32_CLOCK_CONFIG(APB1EN, 8U)
#define GD32_CLOCK_LPTIMER    GD32_CLOCK_CONFIG(APB1EN, 9U)
#define GD32_CLOCK_SLCD       GD32_CLOCK_CONFIG(APB1EN, 10U)
#define GD32_CLOCK_WWDGT      GD32_CLOCK_CONFIG(APB1EN, 11U)
#define GD32_CLOCK_SPI1       GD32_CLOCK_CONFIG(APB1EN, 14U)
#define GD32_CLOCK_USART1     GD32_CLOCK_CONFIG(APB1EN, 17U)
#define GD32_CLOCK_LPUART     GD32_CLOCK_CONFIG(APB1EN, 18U)
#define GD32_CLOCK_UART3      GD32_CLOCK_CONFIG(APB1EN, 19U)
#define GD32_CLOCK_UART4      GD32_CLOCK_CONFIG(APB1EN, 20U)
#define GD32_CLOCK_I2C0       GD32_CLOCK_CONFIG(APB1EN, 21U)
#define GD32_CLOCK_I2C1       GD32_CLOCK_CONFIG(APB1EN, 22U)
#define GD32_CLOCK_USBD       GD32_CLOCK_CONFIG(APB1EN, 23U)
#define GD32_CLOCK_I2C2       GD32_CLOCK_CONFIG(APB1EN, 24U)
#define GD32_CLOCK_PMU        GD32_CLOCK_CONFIG(APB1EN, 28U)
#define GD32_CLOCK_DAC        GD32_CLOCK_CONFIG(APB1EN, 29U)
#define GD32_CLOCK_CTC        GD32_CLOCK_CONFIG(APB1EN, 30U)
#define GD32_CLOCK_BKP        GD32_CLOCK_CONFIG(APB1EN, 31U)

/* APB2 peripherals */
#define GD32_CLOCK_SYSCFG     GD32_CLOCK_CONFIG(APB2EN, 0U)
#define GD32_CLOCK_CMP        GD32_CLOCK_CONFIG(APB2EN, 1U)
#define GD32_CLOCK_ADC        GD32_CLOCK_CONFIG(APB2EN, 9U)
#define GD32_CLOCK_TIMER8     GD32_CLOCK_CONFIG(APB2EN, 11U)
#define GD32_CLOCK_SPI0       GD32_CLOCK_CONFIG(APB2EN, 12U)
#define GD32_CLOCK_USART0     GD32_CLOCK_CONFIG(APB2EN, 14U)
#define GD32_CLOCK_DBGMCU     GD32_CLOCK_CONFIG(APB2EN, 22U)

/** @} */

#endif /* ZEPHYR_INCLUDE_DT_BINDINGS_CLOCK_GD32F4XX_CLOCKS_H_ */