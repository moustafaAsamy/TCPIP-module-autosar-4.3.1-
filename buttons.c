/*
 * buttons.c
 *
 *  Created on: Oct 21, 2019
 *      Author: lenovo
 */


#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "driverlib/gpio.h"
#include "driverlib/rom_map.h"
#include <driverlib/interrupt.h>
#include "inc/hw_memmap.h"
#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "inc/hw_gpio.h"
//#include "enc28j60reg.h"
#include "inc/hw_ints.h"

#define BUTTONS_GPIO_PERIPH     SYSCTL_PERIPH_GPIOF
#define BUTTONS_GPIO_BASE       GPIO_PORTF_BASE
#define NUM_BUTTONS             2
#define LEFT_BUTTON             GPIO_PIN_4
#define RIGHT_BUTTON            GPIO_PIN_0
#define ALL_BUTTONS             (LEFT_BUTTON)

static uint8_t g_ui8ButtonStates = ALL_BUTTONS;
extern void ButtonsInit(void)
{

    //
    // Set each of the button GPIO pins as an input with a pull-up.
    //
    GPIODirModeSet(BUTTONS_GPIO_BASE, ALL_BUTTONS, GPIO_DIR_MODE_IN);
    MAP_GPIOPadConfigSet(BUTTONS_GPIO_BASE, ALL_BUTTONS, GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD_WPU);

    MAP_IntEnable(46);
    MAP_GPIOIntTypeSet(GPIO_PORTF_BASE, ALL_BUTTONS, GPIO_FALLING_EDGE);
    GPIOIntClear(GPIO_PORTF_BASE, ALL_BUTTONS);
    GPIOIntEnable(GPIO_PORTF_BASE, ALL_BUTTONS);
    g_ui8ButtonStates = GPIOPinRead(BUTTONS_GPIO_BASE, ALL_BUTTONS);
}





