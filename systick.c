


#include <stdint.h>
#include "inc/hw_memmap.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/systick.h"
#include "lwip_int.h"
#include "config.h"
#include "autosar_includes/TcpIp.h"
#include "led.h"


volatile uint32_t leds_timer = 0;   //Required every 1000 ms
volatile uint32_t TCp_counter = 0;   //Required every 500 ms 50 *10
volatile uint32_t UDp_counter = 0;   //Required every 600 ms
volatile uint32_t TCP_timer =   0;   //Required every 500 ms
volatile uint32_t main_function = 0;   //Required every 100 ms


extern void SysTickIntHandler(void)
{

    if ((main_function == 10 ) )
        {
            main_function =0;
            TcpIp_MainFunction();
        }
    if ((main_function > 10 ))
            {
                main_function =0;
                TcpIp_MainFunction();
            }

//    if ((TCp_counter == 50 ) )
//    {
//        TCp_counter =0;
//        app_task_tx_tcp();
//    }
//    if (  (TCp_counter > 50 ))
//        {
//            TCp_counter =0;
//            app_task_tx_tcp();
//        }

//    if ((UDp_counter == 70 ) || (UDp_counter > 70 ))
//       {
//           UDp_counter =0;
//           app_task_tx_udp();
//       }
    if ((TCP_timer == 50 ) )
        {
        TCP_timer=0;
        timer();
        }
    if ((TCP_timer > 50 ))
            {
            TCP_timer=0;
            timer();
            }
    if ((leds_timer == 100 ))
        {
        leds_timer=0;
        led_off();
        }
    if ( (leds_timer > 100 ))
            {
            leds_timer=0;
            led_off();
            }
      leds_timer ++;   //Required every 1000 ms
      TCp_counter ++;   //Required every 500 ms 50 *10
      UDp_counter ++;   //Required every 600 ms
      TCP_timer   ++;   //Required every 500 ms
      main_function ++;

}

extern void  timer_start(void)
{
    SysTickPeriodSet(systic_rate);
    IntMasterEnable();
    SysTickIntEnable();
    SysTickEnable();
    int x =SysCtlClockGet();
}
