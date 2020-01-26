/*
 * lwip_int.c
 *
 *  Created on: Sep 29, 2019
 *      Author: lenovo
 */

#include "enc28j60.h"
#include "lwip_int.h"
#include <stdint.h>
#include "config.h"
#include "timer.h"
#include "led.h"
#include "autosar_includes/TcpIp.h"
#include "SoAd_Cbk.h"
#include "lwip/udp.h"
#include "autosar_includes/TCPIP_config.h"
#include "string.h"

#include <stdbool.h>
#include <stdint.h>
#include "inc/hw_can.h"
#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"
#include "utils/uartstdio.h"
void InitConsole(void);
extern err_t enc_low_level_output(struct netif *netif, struct pbuf *p , const uint8* PhysAddrPtr );
extern void ButtonsInit(void);

uint8 Udp_buffer_RX [1800]={0};
uint8 Udp_buffer_TX [1800]={0};
uint8 TCP_buffer_RX [1800]={0};
uint8 TCP_buffer_TX [1800]={0};
udp_recv_fn recv = UDP_recv;

void ECU_int(struct netif *netif, uint8 controller_id ,  ip_addr_t *ipaddr, ip_addr_t *netmask,ip_addr_t *gw)
{
        gpio_comm_init();
        spi_init();
        ButtonsInit();
        enc_init(mac);
        timer_start();
        netif_add(netif, ipaddr, netmask, gw, NULL, NULL,NULL);
        netIf_List[0].ctr_ID =controller_id;
        netif_set_default(netif);
        netif->hwaddr[0] = mac[0];
        netif->hwaddr[1] = mac[1];
        netif->hwaddr[2] = mac[2];
        netif->hwaddr[3] = mac[3];
        netif->hwaddr[4] = mac[4];
        netif->hwaddr[5] = mac[5];
        netif->output = etharp_output;
        netif->linkoutput = enc_low_level_output;
        InitConsole();
        UARTprintf("55");
}

void SimpleDelay_2(void)
{
    SysCtlDelay(16000000 / 3);
}

void timer(void)
{
      tcp_slowtmr();
}

void app_task_tx_tcp(void)
{
    static int i ;
    memset(TCP_buffer_TX ,'1'+ i++ , 400);
    if  (sockets_list[0].state == established )
      {
        Std_ReturnType result = TcpIp_TcpTransmit( 0, TCP_buffer_TX, 400, 0);
      }
}



err_t conection_established(void *pvArg, struct tcp_pcb *psPcb, err_t iErr)
{
    if(iErr != ERR_OK)  // Check if there was a TCP error.
    {
        /* callback functions are deactivated */
        tcp_sent(psPcb, NULL);
        tcp_recv(psPcb, NULL);
        tcp_err(psPcb, NULL);
        tcp_close(psPcb);// Close the TCP connection.
        led_on(green);
        return (ERR_OK);
    }
    sockets_list[psPcb->socket_ID].state = established;
    tcp_recv(psPcb, TCPReceive);
    led_on(indego);
    SoAd_TcpConnected(psPcb->socket_ID); /* connection to autosar socket */
    return(ERR_OK);
}

err_t TCPReceive(void *pvArg, struct tcp_pcb *psPcb, struct pbuf *psBuf, err_t iErr)
{
        static int i =0;
        if(psBuf == 0)// Tell the application that the connection was closed.
        {
        Std_ReturnType error = TcpIp_Close(psPcb->socket_ID, 0);     // Close out the port.
        if (error ==E_OK){ return(ERR_OK);}
        }
        else
        {
        TcpIp_SockAddrType RemoteAddrPtr;
        RemoteAddrPtr.TcpIp_SockAddrInetType_t.addr[0] =(uint32)psPcb->remote_ip.addr;
        RemoteAddrPtr.TcpIp_SockAddrInetType_t.port = psPcb->remote_port;
        RemoteAddrPtr.TcpIp_SockAddrInetType_t.domain =sockets_list[psPcb->socket_ID].Domain;
        uint8 * ptr= (u8_t *)psBuf->payload;
        memcpy( TCP_buffer_RX  , (u8_t *)psBuf->payload,   psBuf->len);
        SoAd_RxIndication(  psPcb->socket_ID, & RemoteAddrPtr, (uint8 *)psBuf->payload, psBuf->len); // shoud copy the data not copythe pointer as it will be deleted
        tcp_recved(psPcb, psBuf->len);             // Indicate that you have received and processed this set of TCP data.
        pbuf_free(psBuf);                          // Free the memory space allocated for this receive.
        psBuf =NULL;
        led_on(white);
        // UARTprintf("  snd_buf  = %d  , rcv_wnd =  %d , snd_wl1 = %d , snd_wl2  = %d ,  %d   \n", psPcb->snd_buf,psPcb->snd_nxt ,psPcb->rcv_wnd , psPcb->snd_wl1 ,psPcb->snd_wl2 , i++);
        return(ERR_OK);
        }
}

void UDP_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,ip_addr_t *addr, u16_t port)
{
    led_off();
    led_on(red);
    memcpy( Udp_buffer_RX  , (u8_t *) p->payload,   p->len);
    TcpIp_SockAddrType RemoteAddrPtr ;
    RemoteAddrPtr.TcpIp_SockAddrInetType_t.addr[0] =(uint32)pcb->remote_ip.addr ;
    RemoteAddrPtr.TcpIp_SockAddrInetType_t.port = pcb->remote_port;
    RemoteAddrPtr.TcpIp_SockAddrInetType_t.domain =sockets_list[pcb->socket_id].Domain;
    SoAd_RxIndication( pcb->socket_id, & RemoteAddrPtr, (uint8 *)p->payload, p->len); // shoud copy the data not copythe pointer as it will be deleted
    pbuf_free(p);        // Free the memory space allocated for this receive.
    p =NULL;
}

void error_event(struct tcp_pcb *psPcb)
{
  sockets_list[psPcb->socket_ID].ptr_connection = 0; // most important when you delete , when rest is sent
 led_off();
 led_on (yellow);
 SimpleDelay_2();
 led_off();
 SimpleDelay_2();
 led_on (yellow);
 SimpleDelay_2();
 led_on (yellow);
 TcpIp_EventType Event =TCPIP_TCP_RESET;
 SoAd_TcpIpEvent( psPcb->socket_ID , Event ); // tammm 3ndy notfy the upper
}

void
InitConsole(void)
{
    //
    // Enable GPIO port A which is used for UART0 pins.
    // TODO: change this to whichever GPIO port you are using.
    //
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOA);

    //
    // Configure the pin muxing for UART0 functions on port A0 and A1.
    // This step is not necessary if your part does not support pin muxing.
    // TODO: change this to select the port/pin you are using.
    //
    GPIOPinConfigure(GPIO_PA0_U0RX);
    GPIOPinConfigure(GPIO_PA1_U0TX);

    //
    // Enable UART0 so that we can configure the clock.
    //
    SysCtlPeripheralEnable(SYSCTL_PERIPH_UART0);

    //
    // Use the internal 16MHz oscillator as the UART clock source.
    //
    UARTClockSourceSet(UART0_BASE, UART_CLOCK_PIOSC);

    //
    // Select the alternate (UART) function for these pins.
    // TODO: change this to select the port/pin you are using.
    //
    GPIOPinTypeUART(GPIO_PORTA_BASE, GPIO_PIN_0 | GPIO_PIN_1);

    //
    // Initialize the UART for console I/O.
    //
    UARTStdioConfig(0, 115200, 16000000);
}
