/*
 * config.h
 *
 *  Created on: Oct 20, 2019
 *      Author: lenovo
 */


#ifndef CONFIG_H_
#define CONFIG_H_

#include "lwip_int.h"

#define uincast 0
#define brodcast 1

#define tx 0
#define rx 0
#define tx2 0

#define TX 1
#define RX 0

#define data_lenght 800



#define tx_rx_1 0  /* driver tester*/
#define tx_rx_2 0

#define ECU1 1
#define ECU2 0
#define time_ticks    50  //50 ms
#define APP_TICKS     180
#define driver_tester 0
#define tcpip         1

#define  systic_rate  160000      // 10 ms

extern uint16_t ecu_1_S_port ;
extern uint16_t ecu_2_S_port ;
extern uint16_t ecu_1_D_port ;
extern struct netif netIf_List[5];
extern ip_addr_t dest_1_address ;
extern struct tcp_pcb * pcb;
extern struct netif g_sNetIF;
extern struct ip_addr ip_addr ;
extern struct ip_addr net_mask;
extern struct ip_addr gw_addr;
extern const uint8_t mac[6] ;
extern const uint8_t mac_addr_dest2[6] ;
extern const uint8_t mac_addr_S2[6]   ;
extern const uint8_t mac_addr_dest1[6]  ;
extern const uint8_t mac_addr_S1[6]    ;
#endif /* CONFIG_H_ */
