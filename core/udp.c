
/* udp.c
 *
 * The code for the User Datagram Protocol UDP & UDPLite (RFC 3828).
 *
 */

/* @todo Check the use of '(struct udp_pcb).chksum_len_rx'!
 */

#include "lwip/opt.h"

#if LWIP_UDP /* don't build if not configured for use in lwipopts.h */

#include "lwip/udp.h"
#include "lwip/def.h"
#include "lwip/inet_chksum.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/mem.h"


#include <string.h>

#ifndef UDP_LOCAL_PORT_RANGE_START
/* From http://www.iana.org/assignments/port-numbers:
   "The Dynamic and/or Private Ports are those from 49152 through 65535" */
#define UDP_LOCAL_PORT_RANGE_START  0xc000
#define UDP_LOCAL_PORT_RANGE_END    0xffff
#define UDP_ENSURE_LOCAL_PORT_RANGE(port) (((port) & ~UDP_LOCAL_PORT_RANGE_START) + UDP_LOCAL_PORT_RANGE_START)
#endif

/* last local UDP port */
static u16_t udp_port = UDP_LOCAL_PORT_RANGE_START;

/* The list of UDP PCBs */
/* exported in udp.h (was static) */
struct udp_pcb *udp_pcbs;



/**
 * Allocate a new local UDP port.
 *
 * @return a new (free) local UDP port number
 */
static u16_t udp_new_port(void)
{
  u16_t n = 0;
  struct udp_pcb *pcb;
again:
  if (udp_port++ == UDP_LOCAL_PORT_RANGE_END) {
    udp_port = UDP_LOCAL_PORT_RANGE_START;
  }
  /* Check all PCBs. */
  for(pcb = udp_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb->local_port == udp_port) {
      if (++n > (UDP_LOCAL_PORT_RANGE_END - UDP_LOCAL_PORT_RANGE_START)) {
        return 0;
      }
      goto again;
    }
  }
  return udp_port;
}

/**
 * Process an incoming UDP datagram.
 *
 * Given an incoming UDP datagram (as a chain of pbufs) this function
 * finds a corresponding UDP PCB and hands over the pbuf to the pcbs
 * recv function. If no pcb is found or the datagram is incorrect, the
 * pbuf is freed.
 *
 * @param p pbuf to be demultiplexed to a UDP PCB.
 * @param inp network interface on which the datagram was received.
 *
 */
void udp_input(struct pbuf *p, struct netif *inp)
{
  struct udp_hdr *udphdr;
  struct udp_pcb *pcb, *prev;
  struct udp_pcb *uncon_pcb;
  struct ip_hdr *iphdr;
  u16_t src, dest;
  u8_t local_match;
  u8_t broadcast;
  iphdr = (struct ip_hdr *)p->payload;

  /* Check minimum length (IP header + UDP header) * and move payload pointer to UDP header */
  if (p->tot_len < (IPH_HL(iphdr) * 4 + UDP_HLEN) || pbuf_header(p, -(s16_t)(IPH_HL(iphdr) * 4)))
  {pbuf_free(p);}  /* drop short packets */
  udphdr = (struct udp_hdr *)p->payload;
  broadcast = ip_addr_isbroadcast(&current_iphdr_dest, inp);/* is broadcast packet ? */
  src  =  (udphdr->src);
  dest =  (udphdr->dest);
  prev = NULL;
  local_match = 0;
  uncon_pcb = NULL;
    /* Iterate through the UDP pcb list for a matching pcb.
     * 'Perfect match' pcbs (connected to the remote port & ip address) are
     * preferred. If no perfect match is found, the first unconnected pcb that
     * matches the local port and ip address gets the datagram. */
  for (pcb = udp_pcbs; pcb != NULL; pcb = pcb->next)
   {
      local_match = 0;
      /* compare PCB local addr+port to UDP destination addr+port */
      if (pcb->local_port == dest)
       {
        if ((!broadcast && ip_addr_isany(&pcb->local_ip)) || ip_addr_cmp(&(pcb->local_ip), &current_iphdr_dest) ||(broadcast &&(ip_addr_isany(&pcb->local_ip) ||ip_addr_netcmp(&pcb->local_ip, ip_current_dest_addr(), &inp->netmask))))
           {
             local_match = 1;
             if ((uncon_pcb == NULL) &&  ((pcb->flags & UDP_FLAGS_CONNECTED) == 0))
              {uncon_pcb = pcb;}    /* the first unconnected matching PCB */
           }
       /*  fully matching PCB ,compare PCB remote addr+port to UDP source addr+port */
        if ((local_match != 0) &&(pcb->remote_port == src) && ( ip_addr_isany(&pcb->remote_ip)   ||   ip_addr_cmp(  &(pcb->remote_ip), &current_iphdr_src) ) )
           {
               if (prev != NULL)/* the first fully matching PCB */
                {
                    /* move the pcb to the front of udp_pcbs so that is found faster next time */
                   prev->next = pcb->next;
                   pcb->next = udp_pcbs;
                   udp_pcbs = pcb;
                }
               break;
           }
      prev = pcb;
    }
    /* no fully matching pcb found? this line simply see if you don't have connected list so you are going to search on the unconnected then look for an unconnected pcb */
      if (pcb == NULL)
       {pcb = uncon_pcb;}
   }

  /* Check checksum if this is a match or if it was directed at us. */
  if (pcb != NULL || ip_addr_cmp(&inp->ip_addr, &current_iphdr_dest))
  {
     if (udphdr->chksum != 0)
      {
        if (inet_chksum_pseudo(p, ip_current_src_addr(), ip_current_dest_addr(), IP_PROTO_UDP, p->tot_len) != 0)
          {
          pbuf_free(p);
          }
      }
  }
  if(pbuf_header(p, -UDP_HLEN))  /* Can we cope with this failing? Just assert for now */
  {
     pbuf_free(p);
  }
  if (pcb != NULL)
   { /* callback */
     if (pcb->recv != NULL)
       {
          pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr(), src); /* now the recv function is responsible for freeing p */
       }
     else/* no recv function registered? then we have to free the pbuf! */
       {
         pbuf_free(p);
       }
    }
   else
    {
      pbuf_free(p);
    }
  }

err_t udp_send(struct udp_pcb *pcb, void * data, u16_t len, ip_addr_t *dst_ip, u16_t dst_port)
{
  struct udp_hdr *udphdr;
  ip_addr_t *src_ip;
  err_t err;
  struct pbuf *p;
  if (pcb->local_port == 0) /* if the PCB is not yet bound to a port, bind it here */
  {
    err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
    if (err != ERR_OK)
    {return err;}
  }
  if (   (p = pbuf_alloc(PBUF_udp, len) )== NULL) { return ERR_MEM;}  /* not enough space */           // Length of data only and payload point to the start of data
  memcpy(p->payload,(u8_t*)data ,len);
  pbuf_header(p, UDP_HLEN);
  udphdr = (struct udp_hdr *)p->payload;
  udphdr->src = (pcb->local_port);
  udphdr->dest = (dst_port);
  udphdr->chksum = 0x0000; 
  src_ip = &(pcb->local_ip);
  udphdr->len = (p->tot_len);
  u16_t udpchksum = inet_chksum_pseudo(p, src_ip, dst_ip, IP_PROTO_UDP, p->tot_len);/* calculate checksum */
  if (udpchksum == 0x0000)        /* chksum zero must become 0xffff, as zero means 'no checksum' */
   {udpchksum = 0xffff; }
  udphdr->chksum = udpchksum;
  err = ip_output(p, src_ip, dst_ip, pcb->ttl, pcb->tos, IP_PROTO_UDP);
  pbuf_free(p);
  return err;
  }
/**
 * Bind an UDP PCB.
 *
 * @param pcb UDP PCB to be bound with a local address ipaddr and port.
 * @param ipaddr local IP address to bind with. Use IP_ADDR_ANY to
 * bind to all local interfaces.
 * @param port local UDP port to bind with. Use 0 to automatically bind
 * to a random port between UDP_LOCAL_PORT_RANGE_START and
 * UDP_LOCAL_PORT_RANGE_END.
 *
 * ipaddr & port are expected to be in the same byte order as in the pcb.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occured.
 * - ERR_USE. The specified ipaddr and port are already bound to by
 * another UDP PCB.
 *
 * @see udp_disconnect()
 */
err_t udp_bind(struct udp_pcb *pcb, ip_addr_t *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;
  u8_t rebind;
  rebind = 0;
  for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next)
  {
    /* is this UDP PCB already on active list? */
    if (pcb == ipcb)
    {
      /* pcb may occur at most once in active list */
       /* pcb already in list, just rebind */
      rebind = 1;
    }
    /* By default, we don't allow to bind to a port that any other udp
       PCB is alread bound to, unless *all* PCBs with that port have that
       REUSEADDR flag set. */
    /* port matches that of PCB in list and REUSEADDR not set -> reject */
    else {
      if ((ipcb->local_port == port) &&
          /* IP address matches, or one is IP_ADDR_ANY? */
          (ip_addr_isany(&(ipcb->local_ip)) ||
           ip_addr_isany(ipaddr) ||
           ip_addr_cmp(&(ipcb->local_ip), ipaddr))) {
        /* other PCB already binds to this local IP and port */
         return ERR_USE;
      }
    }
  }
  ip_addr_set(&pcb->local_ip, ipaddr);
  /* no port specified? */
  if (port == 0)
  {
    port = udp_new_port();
    if (port == 0)
    {
       return ERR_USE;/* no more ports available in local range */
    }
  }
  pcb->local_port = port;
   /* pcb not active yet? */
  if (rebind == 0) /* place the PCB on the active list if not already there */
    {
    pcb->next = udp_pcbs;
    udp_pcbs = pcb;
  }
  return ERR_OK;
}
/**
 * Connect an UDP PCB.
 *
 * This will associate the UDP PCB with the remote address.
 *
 * @param pcb UDP PCB to be connected with remote address ipaddr and port.
 * @param ipaddr remote IP address to connect with.
 * @param port remote UDP port to connect with.
 *
 * @return lwIP error code
 *
 * ipaddr & port are expected to be in the same byte order as in the pcb.
 *
 * The udp pcb is bound to a random local port if not already bound.
 *
 * @see udp_disconnect()
 */
err_t udp_connect(struct udp_pcb *pcb, ip_addr_t *ipaddr, u16_t port)
{
  struct udp_pcb *ipcb;
  if (pcb->local_port == 0)
  {
    err_t err = udp_bind(pcb, &pcb->local_ip, pcb->local_port);
    if (err != ERR_OK)
    { return err;}
  }
  ip_addr_set(&pcb->remote_ip, ipaddr);
  pcb->remote_port = port;
  pcb->flags |= UDP_FLAGS_CONNECTED;
  /* Insert UDP PCB into the list of active UDP PCBs. */
  for (ipcb = udp_pcbs; ipcb != NULL; ipcb = ipcb->next)
  {
    if (pcb == ipcb)
    {return ERR_OK;}/* already on the list, just return */
  }
  /* PCB not yet on the list, add PCB now */
  pcb->next = udp_pcbs;
  udp_pcbs = pcb;
  return ERR_OK;
}

/**
 * Disconnect a UDP PCB
 *
 * @param pcb the udp pcb to disconnect.
 */
void udp_disconnect(struct udp_pcb *pcb)
{
  /* reset remote address association */
  ip_addr_set_any(&pcb->remote_ip);
  pcb->remote_port = 0;
  /* mark PCB as unconnected */
  pcb->flags &= ~UDP_FLAGS_CONNECTED;
}

/**
 * Set a receive callback for a UDP PCB
 *
 * This callback will be called when receiving a datagram for the pcb.
 *
 * @param pcb the pcb for wich to set the recv callback
 * @param recv function pointer of the callback function
 * @param recv_arg additional argument to pass to the callback function
 */
void udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg)
{
  /* remember recv() callback and user data */
  pcb->recv = recv;
  pcb->recv_arg = recv_arg;
}

/**
 * Remove an UDP PCB.
 *
 * @param pcb UDP PCB to be removed. The PCB is removed from the list of
 * UDP PCB's and the data structure is freed from memory.
 *
 * @see udp_new()
 */
void udp_remove(struct udp_pcb *pcb)
{
  struct udp_pcb *pcb2;
  /* pcb to be removed is first in list? */
  if (udp_pcbs == pcb)
  {
    /* make list start at 2nd pcb */
    udp_pcbs = udp_pcbs->next;
    /* pcb not 1st in list */
  }
  else
  {
    for (pcb2 = udp_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
      /* find pcb in udp_pcbs list */
      if (pcb2->next != NULL && pcb2->next == pcb) {
        /* remove pcb from list */
        pcb2->next = pcb->next;
      }
    }
  }
   mem_free(pcb); // to be tested
   pcb =0; // to avoid dangling pointer
}

/**
 * Create a UDP PCB.
 *
 * @return The UDP PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @see udp_remove()
 */
struct udp_pcb * udp_new(void)
{
  struct udp_pcb *pcb;
  pcb = (struct udp_pcb *)mem_malloc(sizeof(struct udp_pcb));
  /* could allocate UDP PCB? */
  if (pcb != NULL) {
    /* UDP Lite: by initializing to all zeroes, chksum_len is set to 0
     * which means checksum is generated over the whole datagram per default
     * (recommended as default by RFC 3828). */
    /* initialize PCB to all zeroes */
    memset(pcb, 0, sizeof(struct udp_pcb));
    pcb->ttl = UDP_TTL;
  }
  return pcb;
}

#endif /* LWIP_UDP */
