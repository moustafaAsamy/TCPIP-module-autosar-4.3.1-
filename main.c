

#include "lwip_int.h"
#include "autosar_includes/TCPIP_config.h"
#include "autosar_includes/TcpIp.h"
#include "config.h"

TcpIp_SocketIdType  SocketIdPtr ;
uint16 port =35;
TcpIp_SockAddrType RemoteAddrPtr ;

#if ECU1
int main()
  {
        RemoteAddrPtr.TcpIp_SockAddrInetType_t.addr[0]=0xfbb03020;
        RemoteAddrPtr.TcpIp_SockAddrInetType_t.domain= TCPIP_AF_INET;
        RemoteAddrPtr.TcpIp_SockAddrInetType_t.port= 70;
        ECU_int(&netIf_List[0], 0 ,  (ip_addr_t *)  &(TcpIpLocalAddr_list[0].TcpIpStaticIpAddressConfig_t.TcpIpStaticIpAddress)  , (ip_addr_t *)  & (TcpIpLocalAddr_list[0].TcpIpStaticIpAddressConfig_t.TcpIpNetmask) ,(ip_addr_t *)  &(TcpIpLocalAddr_list[0].TcpIpStaticIpAddressConfig_t.TcpIpDefaultRouter));
        TcpIp_SoAdGetSocket( TCPIP_AF_INET, TCPIP_IPPROTO_TCP,  &SocketIdPtr );
        TcpIp_Bind( SocketIdPtr, 0, &port );
        int x= TcpIp_TcpConnect( SocketIdPtr, & RemoteAddrPtr) ;
while(1)
{

}
}
#endif

#if ECU2
//TcpIp_SocketIdType* SocketIdPtr ;
//uint16 port =70;
//TcpIp_SockAddrType RemoteAddrPtr ;
//
//int main()
//  {
//        RemoteAddrPtr.TcpIp_SockAddrInetType_t.addr[0]=0xfbb03014;
//        RemoteAddrPtr.TcpIp_SockAddrInetType_t.domain= TCPIP_AF_INET;
//        RemoteAddrPtr.TcpIp_SockAddrInetType_t.port= 35;
//        ECU_int(&netIf_List[0], 0 ,  (ip_addr_t *)  &(TcpIpLocalAddr_list[0].TcpIpStaticIpAddressConfig_t.TcpIpStaticIpAddress)  , (ip_addr_t *)  & (TcpIpLocalAddr_list[0].TcpIpStaticIpAddressConfig_t.TcpIpNetmask) ,(ip_addr_t *)  &(TcpIpLocalAddr_list[0].TcpIpStaticIpAddressConfig_t.TcpIpDefaultRouter));
//        TcpIp_SoAdGetSocket( TCPIP_AF_INET, TCPIP_IPPROTO_TCP,  SocketIdPtr );
//        TcpIp_Bind( *SocketIdPtr, 0, &port );
//        TcpIp_TcpListen( TcpIp_SocketIdType SocketId, 0);
//while(1)
//{
//
//}
//}
#endif
