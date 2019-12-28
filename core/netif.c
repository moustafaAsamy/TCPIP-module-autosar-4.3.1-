
#include "lwip/opt.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/tcp_impl.h"

struct netif *netif_list;
struct netif *netif_default;



struct netif *netif_add(struct netif *netif, ip_addr_t *ipaddr, ip_addr_t *netmask,ip_addr_t *gw, void *state, netif_init_fn init, netif_input_fn input)
{
  /* reset new interface configuration state */
  ip_addr_set_zero(&netif->ip_addr);
  ip_addr_set_zero(&netif->netmask);
  ip_addr_set_zero(&netif->gw);
  netif->flags = 0;
  /* remember netif specific state information data */
  netif->input = input;
  netif_set_addr(netif, ipaddr, netmask, gw);
  /* call user specified initialization function for netif */
//  if (init(netif,netif->hwaddr) != ERR_OK)
//  { return NULL;}
  /* add this netif to the list */
  netif->next = netif_list;
  netif_list = netif;
  return netif;
}

/**
 * Change IP address configuration for a network interface (including netmask
 * and default gateway).
 *
 * @param netif the network interface to change
 * @param ipaddr the new IP address
 * @param netmask the new netmask
 * @param gw the new default gateway
 */
void netif_set_addr(struct netif *netif, ip_addr_t *ipaddr, ip_addr_t *netmask, ip_addr_t *gw)
{
    netif_set_ipaddr(netif, ipaddr);
    netif_set_netmask(netif, netmask);
    netif_set_gw(netif, gw);
}

void netif_set_gw(struct netif *netif, ip_addr_t *gw)
{ ip_addr_set(&(netif->gw), gw);}
void netif_set_netmask(struct netif *netif, ip_addr_t *netmask)
{ ip_addr_set(&(netif->netmask), netmask);}
void netif_set_default(struct netif *netif)
{netif_default = netif;}
void netif_set_ipaddr(struct netif *netif, ip_addr_t *ipaddr)
{ip_addr_set(&(netif->ip_addr), ipaddr);}



