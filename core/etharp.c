
#include "lwip/opt.h"
#include "lwip/ip_addr.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/etharp.h"
#include "../enc28j60.h"

#include "autosar_includes/TcpIp.h"
#include "autosar_includes/ComStack_Types.h"
#include "Eth.h"
#include "string.h"

const struct eth_addr ethbroadcast = { {0xff,0xff,0xff,0xff,0xff,0xff}};
const struct eth_addr ethzero = {{0,0,0,0,0,0}};

uint8_t x[111];

struct eth_addr destt = { 0x00, 0xC0, 0x033, 0x50, 0x48, 0x14 };

u8_t new;
u8_t etharp_cached_entry;


/** the time an ARP entry stays valid after its last update,
 *  for ARP_TMR_INTERVAL = 5000, this is
 *  (240 * 5) seconds = 20 minutes.
 */
#define ARP_MAXAGE              240
/** Re-request a used ARP entry 1 minute before it would expire to prevent
 *  breaking a steadily used connection because the ARP entry timed out. */
#define ARP_AGE_REREQUEST_USED  (ARP_MAXAGE - 12)

/** the time an ARP entry stays pending after first request,
 *  for ARP_TMR_INTERVAL = 5000, this is
 *  (2 * 5) seconds = 10 seconds.
 *
 *  @internal Keep this number at least 2, otherwise it might
 *  run out instantly if the timeout occurs directly after a request.
 */
#define ARP_MAXPENDING 2

#define HWTYPE_ETHERNET 1

enum etharp_state {
  ETHARP_STATE_EMPTY = 0,
  ETHARP_STATE_PENDING,
  ETHARP_STATE_STABLE,
  ETHARP_STATE_STABLE_REREQUESTING
};

struct etharp_entry {
  /** Pointer to a single pending outgoing packet on this ARP entry. */
  struct pbuf *q;
  ip_addr_t ipaddr;
  struct netif *netif;
  struct eth_addr ethaddr;
  u8_t state;
  u8_t ctime;
};
static struct etharp_entry arp_table[ARP_TABLE_SIZE];
extern TcpIp_ArpCacheEntryType  list_of_arp_cache_lists[NO_controllers][max_cache];  // autosar

/** Compatibility define: free the queued pbuf */
#define free_etharp_q(q) pbuf_free(q)



/** Clean up ARP table entries */
static void
etharp_free_entry(int i,int ctr)
{
  /* remove from SNMP ARP index tree */
   /* and empty packet queue */
  if (arp_table[i].q != NULL) {
    /* remove all queued packets */

    free_etharp_q(arp_table[i].q);
    arp_table[i].q = NULL;
  }
  /* recycle entry for re-use */
  arp_table[i].state = ETHARP_STATE_EMPTY;
}

/**
 * Clears expired entries in the ARP table.
 *
 * This function should be called every ETHARP_TMR_INTERVAL milliseconds (5 seconds),
 * in order to expire entries in the ARP table.
 */
void etharp_tmr(void)
{
  u8_t i,ctr;
  /* remove expired entries from the ARP table */
 for(ctr=0;ctr<NO_controllers;ctr++)
 {
  for (i = 0; i < ARP_TABLE_SIZE; ++i) {
    u8_t state = arp_table[i].state;
    if (state != ETHARP_STATE_EMPTY)
     {
      arp_table[i].ctime++;
      if ((arp_table[i].ctime >= ARP_MAXAGE) || ((arp_table[i].state == ETHARP_STATE_PENDING)  && (arp_table[i].ctime >= ARP_MAXPENDING)))
      {
        etharp_free_entry(i,ctr);
      }
      else if (arp_table[i].state == ETHARP_STATE_STABLE_REREQUESTING)
      {
        /* Reset state to stable, so that the next transmitted packet will re-send an ARP request. */
        arp_table[i].state = ETHARP_STATE_STABLE;
      }
    }
  }
 }
}

/**
 * Search the ARP table for a matching or new entry.
 *
 * If an IP address is given, return a pending or stable ARP entry that matches
 * the address. If no match is found, create a new entry with this address set,
 * but in state ETHARP_EMPTY. The caller must check and possibly change the
 * state of the returned entry.
 *
 * If ipaddr is NULL, return a initialized new entry in state ETHARP_EMPTY.
 *
 * In all cases, attempt to create new entries from an empty entry. If no
 * empty entries are available and ETHARP_FLAG_TRY_HARD flag is set, recycle
 * old entries. Heuristic choose the least important entry for recycling.
 *
 * @param ipaddr IP address to find in ARP cache, or to add if not found.
 * @param flags @see definition of ETHARP_FLAG_*
 * @param netif netif related to this address (used for NETIF_HWADDRHINT)
 *
 * @return The ARP entry index that matched or is created, ERR_MEM if no
 * entry is found or could be recycled.
 */
static s8_t etharp_find_entry(ip_addr_t *ipaddr, u8_t flags ,u8_t ctr)
{
  u8_t i = 0 ;
  u8_t match =0;

   for (i = 0; i < ARP_TABLE_SIZE; ++i) /* search frist for an matiching entery */
   {
    u8_t state = arp_table[i].state;
    if (state != ETHARP_STATE_EMPTY)
     {
      if (ipaddr && ip_addr_cmp(ipaddr, &arp_table[i].ipaddr)) /* if given, does IP address match IP address in ARP entry? */
      {
       match =1;
       return i;
      }/* found exact IP address match, simply bail out */
     }
   }
  if (!match)
  {
  for (i = 0; i < ARP_TABLE_SIZE; ++i)
  {
      u8_t state = arp_table[i].state;
      if ( (state != ETHARP_STATE_STABLE) &&  (state != ETHARP_STATE_STABLE_REREQUESTING) )
       {
          if (ipaddr != NULL)                              /* IP address given? */
           {
              ip_addr_copy(arp_table[i].ipaddr, *ipaddr);   /* set IP address */
              arp_table[i].ctime = 0;
              arp_table[i].state = ETHARP_STATE_EMPTY;
              return i;
           }
       }
  }
}
  return -1;
}

/**
 * Send an IP packet on the network using netif->linkoutput
 * The ethernet header is filled in before sending.
 *
 * @params netif the lwIP network interface on which to send the packet
 * @params p the packet to send, p->payload pointing to the (uninitialized) ethernet header
 * @params src the source MAC address to be copied into the ethernet header
 * @params dst the destination MAC address to be copied into the ethernet header
 * @return ERR_OK if the packet was sent, any other err_t on failure
 */
static err_t etharp_send_ip(struct netif *netif, struct pbuf *p, struct eth_addr *src, struct eth_addr *dst)
{
  struct eth_hdr *ethhdr = (struct eth_hdr *)p->payload;
  ETHADDR32_COPY(&ethhdr->dest, dst) ;
  ETHADDR16_COPY(&ethhdr->src, src)  ;
  ethhdr->type = (ETHTYPE_IP);
  return netif->linkoutput(netif, (u8_t *) p->payload, dst->addr,p->len) ; /* send the packet */
}

/**
 * Update (or insert) a IP/MAC address pair in the ARP cache.
 *
 * If a pending entry is resolved, any queued packets will be sent
 * at this point.
 *
 * @param netif netif related to this entry (used for NETIF_ADDRHINT)
 * @param ipaddr IP address of the inserted ARP entry.
 * @param ethaddr Ethernet address of the inserted ARP entry.
 * @param flags @see definition of ETHARP_FLAG_*
 *
 * @return
 * - ERR_OK Succesfully updated ARP cache.
 * - ERR_MEM If we could not add a new ARP entry when ETHARP_FLAG_TRY_HARD was set.
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 * @see pbuf_free()
 */
static err_t etharp_update_arp_entry(struct netif *netif, ip_addr_t *ipaddr, struct eth_addr *ethaddr, u8_t flags)
{
  s8_t i;
  /* non-unicast address? */
  if (ip_addr_isany(ipaddr) ||  ip_addr_isbroadcast(ipaddr, netif) || ip_addr_ismulticast(ipaddr))
  {return ERR_ARG;}
  i = etharp_find_entry(ipaddr, flags,netif->ctr_ID); /* find or create ARP entry */
  if (i < 0)
  {return (err_t)i;}
  arp_table[i].state = ETHARP_STATE_STABLE;         /* mark it stable */
  arp_table[i].netif = netif;                       /* record network interface */
  ETHADDR32_COPY(&arp_table[i].ethaddr, ethaddr);   /* update address */
  arp_table[i].ctime = 0;                           /* reset time stamp */
  /* this is where we will send out queued packets! */
  if (arp_table[i].q != NULL)
  {
   struct pbuf *p = arp_table[i].q;
   arp_table[i].q = NULL;
   etharp_send_ip(netif, p, (struct eth_addr*)(netif->hwaddr), ethaddr);   /* send the queued IP packet */
   pbuf_free(p);   /* free the queued IP packet */
}
  return ERR_OK;
}

/**
 * Responds to ARP requests to us. Upon ARP replies to us, add entry to cache
 * send out queued IP packets. Updates cache with snooped address pairs.
 *
 * Should be called for incoming ARP packets. The pbuf in the argument
 * is freed by this function.
 *
 * @param netif The lwIP network interface on which the ARP packet pbuf arrived.
 * @param ethaddr Ethernet address of netif.
 * @param p The ARP packet that arrived on netif. Is freed by this function.
 *
 * @return NULL
 *
 * @see pbuf_free()
 */
static void etharp_arp_input(struct netif *netif, struct eth_addr *ethaddr, struct pbuf *p)
{
  struct etharp_hdr *hdr;
  struct eth_hdr *ethhdr;
  /* these are aligned properly, whereas the ARP header fields might not be */
  ip_addr_t sipaddr, dipaddr;
  u8_t for_us;
  /* drop short ARP packets: we have to check for p->len instead of p->tot_len here
     since a struct etharp_hdr is pointed to p->payload, so it musn't be chained! */
  if (p->len < SIZEOF_ETHARP_PACKET)
  {
    pbuf_free(p);
    return;
  }
  ethhdr = (struct eth_hdr *)p->payload;
  hdr =    (struct etharp_hdr *)((u8_t*)ethhdr + SIZEOF_ETH_HDR);
  /* RFC 826 "Packet Reception": */
  if ((hdr->hwtype != (HWTYPE_ETHERNET)) || (hdr->hwlen != ETHARP_HWADDR_LEN) || (hdr->protolen != sizeof(ip_addr_t)) || (hdr->proto != (ETHTYPE_IP)))
  {
    pbuf_free(p);   /* wrong ARP packet*/
    return;
  }
  /* Copy struct ip_addr2 to aligned ip_addr, to support compilers without
   * structure packing (not using structure copy which breaks strict-aliasing rules). */
  IPADDR2_COPY(&sipaddr, &hdr->sipaddr);
  IPADDR2_COPY(&dipaddr, &hdr->dipaddr);

  /* this interface is not configured? */
  if (ip_addr_isany(&netif->ip_addr))
  {for_us = 0;}
  else
  {for_us = (u8_t)ip_addr_cmp(&dipaddr, &(netif->ip_addr));}  /* ARP packet directed to us? */
  /* ARP message directed to us?
      -> add IP address in ARP cache; assume requester wants to talk to us,
         can result in directly sending the queued packets for this host.
     ARP message not directed to us?
      ->  update the source IP address in the cache, if present */
  /* now act on the message itself */
  switch (hdr->opcode)
  {
  /* ARP request? */
  case (ARP_REQUEST):
    /* ARP request. If it asked for our address, we send out a
     * reply. In any case, we time-stamp any existing ARP entry,
     * and possiby send out an IP packet that was queued on it. */
    /* ARP request for our address? */
    if (for_us)
    {
      /* Re-use pbuf to send ARP reply.
         Since we are re-using an existing pbuf, we can't call etharp_raw since
         that would allocate a new pbuf. */
      hdr->opcode = (ARP_REPLY);
      IPADDR2_COPY  (&hdr->dipaddr, &hdr->sipaddr);
      IPADDR2_COPY  (&hdr->sipaddr, &netif->ip_addr);
      ETHADDR16_COPY(&hdr->dhwaddr, &hdr->shwaddr);
      ETHADDR16_COPY(&ethhdr->dest, &hdr->shwaddr);
      ETHADDR16_COPY(&hdr->shwaddr, ethaddr);
      ETHADDR16_COPY(&ethhdr->src, ethaddr);
      /* hwtype, hwaddr_len, proto, protolen and the type in the ethernet header are already correct, we tested that before */
      netif->linkoutput(netif,(u8_t *) p->payload, ethhdr->dest.addr ,p->len);     /* send  ARP reply */
    /* we are not configured? */
    }
    else
    { }/* { for_us == 0 and netif->ip_addr.addr != 0 } */
    break;
  case (ARP_REPLY):
    /* ARP reply. We updated the ARP cache .*/
    etharp_update_arp_entry( netif , &sipaddr, &(hdr->shwaddr),0);
    break;
  default:
    break;
  }
  /* free ARP packet */
  pbuf_free(p);
}

/** Just a small helper function that sends a pbuf to an ethernet address
 * in the arp_table specified by the index 'arp_idx'.
 */
static err_t etharp_output_to_arp_index(struct netif *netif, struct pbuf *q, u8_t arp_idx)
{
   /* if arp table entry is about to expire: re-request it,
     but only if its state is ETHARP_STATE_STABLE to prevent flooding the
     network with ARP requests if this address is used frequently. */
  if ((arp_table[arp_idx].state == ETHARP_STATE_STABLE) && (arp_table[arp_idx].ctime >= ARP_AGE_REREQUEST_USED))
  {
    if (etharp_request(netif, &arp_table[arp_idx].ipaddr) == ERR_OK)
       {arp_table[arp_idx].state = ETHARP_STATE_STABLE_REREQUESTING;}
  }

  return etharp_send_ip(netif, q, (struct eth_addr*)(netif->hwaddr),&arp_table[arp_idx].ethaddr);
}

/**
 * Resolve and fill-in Ethernet address header for outgoing IP packet.
 *
 * For unicast addresses, the packet is submitted to etharp_query(). In
 * case the IP address is outside the local network, the IP address of
 * the gateway is used.
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param q The pbuf(s) containing the IP packet to be sent.
 * @param ipaddr The IP address of the packet destination.
 *
 * @return
 * - ERR_RTE No route to destination (no gateway to external networks),
 * or the return type of either etharp_query() or etharp_send_ip().
 */
err_t etharp_output(struct netif *netif, struct pbuf *q, ip_addr_t *ipaddr)
{
  struct eth_addr *dest;
  ip_addr_t *dst_addr = ipaddr;
  if (pbuf_header(q, sizeof(struct eth_hdr)) != 0)   /* make room for Ethernet header - should not fail */
  {
      return ERR_BUF;
  }
  if (ip_addr_isbroadcast(ipaddr, netif)) /* broadcast on Ethernet also */
  {
      dest = (struct eth_addr *)&ethbroadcast;
  }
  else /* unicast destination IP address? */
  {
    s8_t i;
    /* outside local network? if so, this can neither be a global broadcast nor a subnet broadcast. */
    if (!ip_addr_islinklocal(ipaddr))
    {
      if (!ip_addr_isany(&netif->gw))            /* interface has default gateway? */
      {
          dst_addr = &(netif->gw);
      }                /* send to hardware address of default gateway IP address */
      else                                       /* no default gateway available */
      {
          return ERR_RTE;/* no route to destination error (default gateway missing) */
      }
    }
    if ((ip_addr_cmp(dst_addr, &arp_table[etharp_cached_entry].ipaddr)) && (arp_table[etharp_cached_entry].state == ETHARP_STATE_STABLE))
    {
        return etharp_output_to_arp_index(netif, q, etharp_cached_entry);
    }
    for (i = 0; i < ARP_TABLE_SIZE; i++) /* find stable entry*/
    {
      if ((ip_addr_cmp(dst_addr, &arp_table[i].ipaddr)) && (arp_table[i].state == ETHARP_STATE_STABLE) ) /* found an existing, stable entry */
      {
        etharp_cached_entry=i;
        return etharp_output_to_arp_index(netif, q, i);
      }
    }
    return etharp_query(netif, dst_addr, q);  /* no entry found so make a request and  */
  }

  return etharp_send_ip(netif, q, (struct eth_addr*)(netif->hwaddr), dest);    /* send packet directly on the link */

}

/**
 * Send an ARP request for the given IP address and/or queue a packet.
 *
 * If the IP address was not yet in the cache, a pending ARP cache entry
 * is added and an ARP request is sent for the given address. The packet
 * is queued on this entry.
 *
 * If the IP address was already pending in the cache, a new ARP request
 * is sent for the given address. The packet is queued on this entry.
 *
 * If the IP address was already stable in the cache, and a packet is
 * given, it is directly sent and no ARP request is sent out.
 *
 * If the IP address was already stable in the cache, and no packet is
 * given, an ARP request is sent out.
 *
 * @param netif The lwIP network interface on which ipaddr
 * must be queried for.
 * @param ipaddr The IP address to be resolved.
 * @param q If non-NULL, a pbuf that must be delivered to the IP address.
 * q is not freed by this function.
 *
 * @note q must only be ONE packet, not a packet queue!
 *
 * @return
 * - ERR_BUF Could not make room for Ethernet header.
 * - ERR_MEM Hardware address unknown, and no more ARP entries available
 *   to query for address or queue the packet.
 * - ERR_MEM Could not queue packet due to memory shortage.
 * - ERR_RTE No route to destination (no gateway to external networks).
 * - ERR_ARG Non-unicast address given, those will not appear in ARP cache.
 *
 */
err_t etharp_query(struct netif *netif, ip_addr_t *ipaddr, struct pbuf *q)
{
  struct eth_addr * srcaddr = (struct eth_addr *)netif->hwaddr;
  err_t result = ERR_MEM;
  s8_t i; /* ARP entry index */
  if (ip_addr_isbroadcast(ipaddr, netif) ||ip_addr_ismulticast(ipaddr) ||ip_addr_isany(ipaddr)) /* non-unicast address? */
  {return ERR_ARG;}
  i = etharp_find_entry(ipaddr, 0,netif->ctr_ID);      /* find entry in ARP cache, ask to create entry if queueing packet */
  if (i < 0)  /* could not find or create entry? */
  {
    return (err_t)i;
  }
  /* mark a fresh entry as pending (we just sent a request) */
  if (arp_table[i].state == ETHARP_STATE_EMPTY)
  {
    arp_table[i].state = ETHARP_STATE_PENDING;
  }
  /* { i is either a STABLE or (new or existing) PENDING entry } */
  /* do we have a pending entry? or an implicit query request? */
  if ((arp_table[i].state == ETHARP_STATE_PENDING) || (q == NULL))
  {
    /* try to resolve it; send out ARP request */
    result = etharp_request(netif, ipaddr);
    if (q == NULL)
    {return result;}
  }
  /* packet given? */
  /* stable entry? */
  if (arp_table[i].state >= ETHARP_STATE_STABLE) /* we have a valid IP->Ethernet address mapping */
  {
     etharp_cached_entry= i;
    result = etharp_send_ip(netif, q, srcaddr, &(arp_table[i].ethaddr)); /* send the packet */
  }
  else if (arp_table[i].state == ETHARP_STATE_PENDING)
  {
      /* packet could be taken over? */
      if (q != NULL)
      {
        /* always queue one packet per ARP request only, freeing a previously queued packet */
        if (arp_table[i].q != NULL)
         {pbuf_free(arp_table[i].q);}
        arp_table[i].q = q;
        result = ERR_OK;
      }
      else
      { result = ERR_MEM;}
    }
    return result;
  }

/**
 * Send a raw ARP packet (opcode and all addresses can be modified)
 *
 * @param netif the lwip network interface on which to send the ARP packet
 * @param ethsrc_addr the source MAC address for the ethernet header
 * @param ethdst_addr the destination MAC address for the ethernet header
 * @param hwsrc_addr the source MAC address for the ARP protocol header
 * @param ipsrc_addr the source IP address for the ARP protocol header
 * @param hwdst_addr the destination MAC address for the ARP protocol header
 * @param ipdst_addr the destination IP address for the ARP protocol header
 * @param opcode the type of the ARP packet
 * @return ERR_OK if the ARP packet has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other err_t on failure
 */
#if !LWIP_AUTOIP
static
#endif /* LWIP_AUTOIP */

err_t etharp_raw(struct netif *netif, const struct eth_addr *ethsrc_addr,const struct eth_addr *ethdst_addr,const struct eth_addr *hwsrc_addr, const ip_addr_t *ipsrc_addr,const struct eth_addr *hwdst_addr, const ip_addr_t *ipdst_addr, const u16_t opcode)
{
  struct pbuf *p;
  err_t result = ERR_OK;
  struct eth_hdr *ethhdr;
  struct etharp_hdr *hdr;
  /* allocate a pbuf for the outgoing ARP request packet */
  p = pbuf_alloc(PBUF_RAW, SIZEOF_ETHARP_PACKET);
  if (p == NULL) /* could allocate a pbuf for an ARP request? */
  {return ERR_MEM;}
  ethhdr = (struct eth_hdr *)p->payload;   /* points to the Ethernet header*/
  hdr = (struct etharp_hdr *)((u8_t*)ethhdr + SIZEOF_ETH_HDR);  /* point to the arp_header*/
  hdr->opcode = (opcode);

  /* Write the ARP MAC-Addresses */
  ETHADDR16_COPY(&hdr->shwaddr, hwsrc_addr);
  ETHADDR16_COPY(&hdr->dhwaddr, hwdst_addr);

  /* Write the Ethernet MAC-Addresses */
  ETHADDR16_COPY(&ethhdr->dest, ethdst_addr);
  ETHADDR16_COPY(&ethhdr->src, ethsrc_addr);

  /* Copy struct ip_addr2 to aligned ip_adcdr, to support compilers without * structure packing. */
  IPADDR2_COPY(&hdr->sipaddr, ipsrc_addr);
  IPADDR2_COPY(&hdr->dipaddr, ipdst_addr);

  hdr->hwtype = (HWTYPE_ETHERNET);
  hdr->proto = (ETHTYPE_IP);
  /* set hwlen and protolen */
  hdr->hwlen = ETHARP_HWADDR_LEN;
  hdr->protolen = sizeof(ip_addr_t);
  ethhdr->type = (ETHTYPE_ARP);
  //driver_output(netif, p);


  result = netif->linkoutput(netif, (u8_t *)p->payload, ethdst_addr->addr ,p->len);  /* send ARP query */
  pbuf_free(p);                     /* free ARP query packet */
  p = NULL;
  return result;
}

/**
 * Send an ARP request packet asking for ipaddr.
 *
 * @param netif the lwip network interface on which to send the request
 * @param ipaddr the IP address for which to ask
 * @return ERR_OK if the request has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other err_t on failure
 */
err_t etharp_request(struct netif *netif, ip_addr_t *ipaddr)
{
   return etharp_raw(netif, (struct eth_addr *)netif->hwaddr , &ethbroadcast , (struct eth_addr *)netif->hwaddr , &netif->ip_addr , &ethzero , ipaddr, ARP_REQUEST);
}


/**
 * Process received ethernet frames. Using this function instead of directly
 * calling ip_input and passing ARP frames through etharp in ethernetif_input,
 * the ARP cache is protected from concurrent access.
 *
 * @param p the recevied packet, p->payload pointing to the ethernet header
 * @param netif the network interface on which the packet was received
 */
err_t
ethernet_input(struct pbuf *p, struct netif *netif)
{
  struct eth_hdr* ethhdr;
  u16_t type;
  s16_t ip_hdr_offset = SIZEOF_ETH_HDR;
  if (p->len <= SIZEOF_ETH_HDR)              /* a packet with only an ethernet header (or less) is not valid for us */
  {goto free_and_return; }
  ethhdr = (struct eth_hdr *)p->payload;     /* points to packet payload, which starts with an Ethernet header */
  type = ethhdr->type;
  if (ethhdr->dest.addr[0] & 1)              /* this might be a multicast or broadcast packet */
  {
   if (eth_addr_cmp(&ethhdr->dest, &ethbroadcast))
   { /*p->flags |= PBUF_FLAG_LLBCAST;*/ }          /* mark the pbuf as link-layer broadcast */
  }
  switch (type)
  {
    case (ETHTYPE_IP):            /* IP packet? */
      if(pbuf_header(p, -ip_hdr_offset))
      { goto free_and_return;}
      else
       {ip_input(p, netif);  }            /* pass to IP layer */
      break;
    case (ETHTYPE_ARP):           /* pass p to ARP module */
      etharp_arp_input(netif, (struct eth_addr*)(netif->hwaddr), p);
      break;
    default:
      goto free_and_return;
  }
  /* This means the pbuf is freed or consumed, so the caller doesn't have to free it again */
  return ERR_OK;
free_and_return:
  pbuf_free(p);
  return ERR_OK;
}


