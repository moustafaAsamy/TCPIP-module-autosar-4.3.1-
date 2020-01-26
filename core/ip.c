
#include "lwip/opt.h"
#include "lwip/ip.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/inet_chksum.h"
#include "lwip/netif.h"
#include "lwip/tcp_impl.h"
#include "lwip/udp.h"
#include "autosar_includes/TCPIP_config.h"
#include "config.h"

struct netif *current_netif;
const struct ip_hdr *current_header;  /* Header of the input packet currently being processed.*/
ip_addr_t current_iphdr_src;          /* Source IP address of current_header */
ip_addr_t current_iphdr_dest;         /* Destination IP address of current_header */
static u16_t ip_id;                   /* The IP header ID of the next outgoing IP packet */

#define LWIP_MAKE_U16(a, b) ((a << 8) | b)

/**
 * This function is called by the network interface device driver when
 * an IP packet is received. The function does the basic checks of the
 * IP header such as packet size being at least larger than the header
 * size etc. If the packet was not destined for us, the packet is
 * forwarded (using ip_forward). The IP checksum is always checked.
 *
 * Finally, the packet is sent to the upper layer protocol input function.
 * 
 * @param p the received IP packet (p->payload points to IP header)
 * @param inp the netif on which this packet was received
 * @return ERR_OK if the packet was processed (could return ERR_* if it wasn't
 *         processed, but currently always returns ERR_OK)
 */
err_t ip_input(struct pbuf *p, struct netif *inp)
{
  struct ip_hdr *iphdr;
  struct netif *netif;
  u16_t iphdr_hlen;
  u16_t iphdr_len;
  iphdr = (struct ip_hdr *)p->payload; /* identify the IP header */
  if (IPH_V(iphdr) != 4)
  {
    pbuf_free(p);
    return ERR_OK;
  }
  iphdr_hlen = IPH_HL(iphdr);                 /* obtain IP header length in number of 32-bit words */
  iphdr_hlen *= 4;                            /* calculate IP header length in bytes */
  iphdr_len = (IPH_LEN(iphdr));               /* obtain ip length in bytes */
  if ((iphdr_hlen > p->len) || (iphdr_len > p->tot_len))   /* header length exceeds first pbuf length, or ip length exceeds total pbuf length? */
  {
    pbuf_free(p); /* free (drop) packet pbufs */
    return ERR_OK;
  }
  if (inet_chksum(iphdr, iphdr_hlen) != 0)   /* verify checksum */
  {
    pbuf_free(p);
    return ERR_OK;
  }
  //pbuf_realloc(p, iphdr_len);                        /* Trim pbuf. This should have been done at the netif layer, * but we'll do it anyway just to be sure that its done. */
  ip_addr_copy(current_iphdr_dest, iphdr->dest);     /* copy IP addresses to aligned ip_addr_t */
  ip_addr_copy(current_iphdr_src, iphdr->src);

  /* match packet against an interface, i.e. is this packet for us? */
    /* start trying with inp. if that's not acceptable, start walking the
       list of configured netifs.
       'first' is used as a boolean to mark whether we started walking the list */
    int first = 1;
    netif = inp;
    do {
      /* interface is up and configured? */
      if ((!ip_addr_isany(&(netif->ip_addr))))/* unicast to this interface address? */
      {
        if (ip_addr_cmp(&current_iphdr_dest, &(netif->ip_addr)) ||  ip_addr_isbroadcast(&current_iphdr_dest, netif))  /* or broadcast on this interface network address? */
        { break;}/* break out of for loop */
      }
      if (first)
      {
        first = 0;
        netif = netif_list;
      }
      else
      {netif = netif->next;}
      if (netif == inp)
      {netif = netif->next;}
    } while(netif != NULL);
    if ((ip_addr_isbroadcast(&current_iphdr_src, inp)) || (ip_addr_ismulticast(&current_iphdr_src)))  /* broadcast or multicast packet source address? Compliant with RFC 1122: 3.2.1.3 */
    {
      /* packet source is not valid */
      pbuf_free(p);/* free (drop) packet pbufs */
      return ERR_OK;
    }
  if (netif == NULL)  /* packet not for us? */
  {
    /* packet not for us, route or discard */
    pbuf_free(p);
    return ERR_OK;
  }
  /* packet consists of multiple fragments? */
  if ((IPH_OFFSET(iphdr) & (IP_OFFMASK | IP_MF)) != 0)
  {
  /* IP_REASSEMBLY == 0, no packet fragment reassembly code present */
    pbuf_free(p);
    /* unsupported protocol feature */
    return ERR_OK;
  }
  /* send to upper layers */
  current_netif = inp;
  current_header = iphdr;
  {
    switch (IPH_PROTO(iphdr))
    {
    case IP_PROTO_UDP :
        udp_input(p, inp);
        break;
    case IP_PROTO_TCP:
      tcp_input(p, inp);
      break;
    default:
      pbuf_free(p);
    }
  }
  current_netif = NULL;
  current_header = NULL;
  ip_addr_set_any(&current_iphdr_src);
  ip_addr_set_any(&current_iphdr_dest);
  return ERR_OK;
}

/**
 * Sends an IP packet on a network interface. This function constructs
 * the IP header and calculates the IP header checksum. If the source
 * IP address is NULL, the IP address of the outgoing network
 * interface is filled in as source address.
 * If the destination IP address is IP_HDRINCL, p is assumed to already
 * include an IP header and p->payload points to it instead of the data.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == IP_HDRINCL, p already includes an IP
            header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 * @param netif the netif on which to send this packet
 * @return ERR_OK if the packet was sent OK
 *         ERR_BUF if p doesn't have enough space for IP/LINK headers
 *         returns errors returned by netif->output
 *
 * @note ip_id: RFC791 "some host may be able to simply use
 *  unique identifiers independent of destination"
 */
err_t ip_output_if(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,u8_t ttl, u8_t tos,u8_t proto, struct netif *netif)
{
  struct ip_hdr *iphdr;
  ip_addr_t dest_addr;
  u32_t chk_sum = 0;
  /* pbufs passed to IP must have a ref-count of 1 as their payload pointer gets altered as the packet is passed down the stack */
  if (dest != IP_HDRINCL)   /* Should the IP header be generated or is it already included in p? */
  {
    u16_t ip_hlen = IP_HLEN;
    if (pbuf_header(p, IP_HLEN)) /* generate IP header */
    {return ERR_BUF;}
    iphdr = (struct ip_hdr *)p->payload;
    IPH_TTL_SET(iphdr, ttl);
    IPH_PROTO_SET(iphdr, proto);
    chk_sum += LWIP_MAKE_U16(proto, ttl);
    ip_addr_copy(iphdr->dest, *dest);/* dest cannot be NULL here */
    chk_sum += ip4_addr_get_u32(&iphdr->dest) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->dest) >> 16;
    IPH_VHL_SET(iphdr, 4, ip_hlen / 4);     /* ip 4 ,lenght = 5 words*/
    IPH_TOS_SET(iphdr, tos);
    chk_sum += LWIP_MAKE_U16(tos, iphdr->_v_hl);
    IPH_LEN_SET(iphdr, (p->tot_len)); ////////////// very important
    chk_sum += iphdr->_len;
    IPH_OFFSET_SET(iphdr, 0);
    IPH_ID_SET(iphdr, (ip_id));
    chk_sum += iphdr->_id;
    ++ip_id;
    if (ip_addr_isany(src))
     { ip_addr_copy(iphdr->src, netif->ip_addr);}
     else
     {ip_addr_copy(iphdr->src, *src);}/* src cannot be NULL here */
    chk_sum += ip4_addr_get_u32(&iphdr->src) & 0xFFFF;
    chk_sum += ip4_addr_get_u32(&iphdr->src) >> 16;
    chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
    chk_sum = (chk_sum >> 16) + chk_sum;
    chk_sum = ~chk_sum;
    iphdr->_chksum = chk_sum;
    p->ref =1;
  }
  else /* IP header already included in p */
  {
    iphdr = (struct ip_hdr *)p->payload;
    ip_addr_copy(dest_addr, iphdr->dest);
    dest = &dest_addr;
  }
  return netif->output(netif, p, dest);
}

/*
 * Simple interface to ip_output_if. It finds the outgoing network
 * interface and calls upon ip_output_if to do the actual work.
 *
 * @param p the packet to send (p->payload points to the data, e.g. next
            protocol header; if dest == IP_HDRINCL, p already includes an IP
            header and p->payload points to that IP header)
 * @param src the source IP address to send from (if src == IP_ADDR_ANY, the
 *         IP  address of the netif used to send is used as source address)
 * @param dest the destination IP address to send the packet to
 * @param ttl the TTL value to be set in the IP header
 * @param tos the TOS value to be set in the IP header
 * @param proto the PROTOCOL to be set in the IP header
 *
 * @return ERR_RTE if no route is found
 *         see ip_output_if() for more return values
 */

err_t ip_output(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,u8_t ttl, u8_t tos, u8_t proto )
{
  struct netif *netif;
  if ((netif = ip_route(dest)) == NULL)/* pbufs passed to IP must have a ref-count of 1 as their payload pointer gets altered as the packet is passed down the stack */
  {return ERR_RTE;}
  return ip_output_if(p, src, dest, ttl, tos, proto, netif );
}

err_t ip_output_autosar(struct pbuf *p, ip_addr_t *src, ip_addr_t *dest,u8_t ttl, u8_t tos, u8_t proto, u8_t LocalAddrId   )
{
    u8_t i = TcpIpLocalAddr_list[LocalAddrId].TcpIpCtrlRef_t->TcpIpEthIfCtrlRef->EthIfCtrlIdx ; // Index of controller in controller list  is the id
    return ip_output_if(p, src, dest, ttl, tos, proto, &netIf_List[i]   );
}
/**
 * Finds the appropriate network interface for a given IP address. It
 * searches the list of network interfaces linearly. A match is found
 * if the masked IP address of the network interface equals the masked
 * IP address given to the function.
 *
 * @param dest the destination IP address for which to find the route
 * @return the netif on which to send to reach dest
 */

struct netif * ip_route(ip_addr_t *dest)
{
  struct netif *netif;
  for (netif = netif_list; netif != NULL; netif = netif->next)  /* iterate through netifs */
  {
      if (ip_addr_netcmp(dest, &(netif->ip_addr), &(netif->netmask)))
      { return netif; }  /* return netif on which to forward IP packet */
  }
  if ((netif_default == NULL))
  { return NULL; } /* no matching netif found, use default netif */
  return netif_default;
}

