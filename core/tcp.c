#include "lwip/opt.h"
#include "lwip/mem.h"
#include "lwip/tcp.h"
#include "lwip/tcp_impl.h"
#include "autosar_includes/TCPIP_config.h"
#include "lwip_int.h"
#include <string.h>

#ifndef TCP_LOCAL_PORT_RANGE_START
/* From http://www.iana.org/assignments/port-numbers:
   "The Dynamic and/or Private Ports are those from 49152 through 65535" */
#define TCP_LOCAL_PORT_RANGE_START        0xc000
#define TCP_LOCAL_PORT_RANGE_END          0xffff
#define TCP_ENSURE_LOCAL_PORT_RANGE(port) (((port) & ~TCP_LOCAL_PORT_RANGE_START) + TCP_LOCAL_PORT_RANGE_START)
#endif

#if LWIP_TCP_KEEPALIVE
#define TCP_KEEP_DUR(pcb)   ((pcb)->keep_cnt * (pcb)->keep_intvl)
#define TCP_KEEP_INTVL(pcb) ((pcb)->keep_intvl)
#else /* LWIP_TCP_KEEPALIVE */
#define TCP_KEEP_DUR(pcb)   TCP_MAXIDLE
#define TCP_KEEP_INTVL(pcb) TCP_KEEPINTVL_DEFAULT
#endif /* LWIP_TCP_KEEPALIVE */

const char * const tcp_state_str[] = {
  "CLOSED",      
  "LISTEN",      
  "SYN_SENT",    
  "SYN_RCVD",    
  "ESTABLISHED", 
  "FIN_WAIT_1",  
  "FIN_WAIT_2",  
  "CLOSE_WAIT",  
  "CLOSING",     
  "LAST_ACK",    
  "TIME_WAIT"   
};

/* last local TCP port */
static u16_t tcp_port = TCP_LOCAL_PORT_RANGE_START;
/* Incremented every coarse grained timer shot (typically every 500 ms). */
u32_t tcp_ticks;

/* The TCP PCB lists. */

/** List of all TCP PCBs bound but not yet (connected || listening) */
struct tcp_pcb *tcp_bound_pcbs;
/** List of all TCP PCBs in LISTEN state */
//union tcp_listen_pcbs_t tcp_listen_pcbs;
struct tcp_pcb * tcp_listen_pcbs;
/** List of all TCP PCBs that are in a state in which
 * they accept or send data. */
struct tcp_pcb *tcp_active_pcbs;
/** List of all TCP PCBs in TIME-WAIT state */
struct tcp_pcb *tcp_tw_pcbs;

#define NUM_TCP_PCB_LISTS               4
#define NUM_TCP_PCB_LISTS_NO_TIME_WAIT  3
/** An array with all (non-temporary) PCB lists, mainly used for smaller code size */
struct tcp_pcb ** const tcp_pcb_lists[] = {&tcp_listen_pcbs, &tcp_bound_pcbs,
  &tcp_active_pcbs, &tcp_tw_pcbs};

/** Only used for temporary storage. */
struct tcp_pcb *tcp_tmp_pcb;
u8_t tcp_active_pcbs_changed;

/** Timer counter to handle calling slow-timer from tcp_tmr() */ 
static u8_t tcp_timer;
static u8_t tcp_timer_ctr;
static u16_t tcp_new_port(void);

void
tcp_tmr(void)
{
  if (++tcp_timer & 1) {
    /* Call tcp_tmr() every 500 ms */
    tcp_slowtmr();
  }
}

/**
 * Closes the TX side of a connection held by the PCB.
 * For tcp_close(), a RST is sent if the application didn't receive all data
 * (tcp_recved() not called for all data passed to recv callback).
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it.
 *
 * @param pcb the tcp_pcb to close
 * @return ERR_OK if connection has been closed
 *         another err_t if closing failed and pcb is not freed
 */
static err_t
tcp_close_shutdown(struct tcp_pcb *pcb, u8_t rst_on_unacked_data)
{
  err_t err;

  // can skip now
  if (rst_on_unacked_data && ((pcb->state == ESTABLISHED) || (pcb->state == CLOSE_WAIT)))
  {
    if ((pcb->refused_data != NULL) || (pcb->rcv_wnd != TCP_WND)) {
      /* Not all data received by application, send RST to tell the remote
         side about this. */


      /* don't call tcp_abort here: we must not deallocate the pcb since
         that might not be expected when calling tcp_close */
      tcp_rst(pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip, &pcb->remote_ip,
        pcb->local_port, pcb->remote_port);

      tcp_pcb_purge(pcb);
      TCP_RMV_ACTIVE(pcb);
      if (pcb->state == ESTABLISHED) {
        /* move to TIME_WAIT since we close actively */
        pcb->state = TIME_WAIT;
        TCP_REG(&tcp_tw_pcbs, pcb);
      } else {
        /* CLOSE_WAIT: deallocate the pcb since we already sent a RST for it */
        mem_free(pcb);
      }
      return ERR_OK;
    }
  }
  switch (pcb->state) {
  case CLOSED:
    /* Closing a pcb in the CLOSED state might seem erroneous,
     * however, it is in this state once allocated and as yet unused
     * and the user needs some way to free it should the need arise.
     * Calling tcp_close() with a pcb that has already been closed, (i.e. twice)
     * or for a pcb that has been used and then entered the CLOSED state 
     * is erroneous, but this should never happen as the pcb has in those cases
     * been freed, and so any remaining handles are bogus. */
    err = ERR_OK;
    if (pcb->local_port != 0) {
      TCP_RMV(&tcp_bound_pcbs, pcb);
    }
    mem_free(pcb);
    pcb = NULL;
    break;
  case LISTEN:
    err = ERR_OK;
    tcp_pcb_remove(&tcp_listen_pcbs, pcb);
    mem_free(pcb);
    pcb = NULL;
    break;
  case SYN_SENT:
    err = ERR_OK;
    TCP_PCB_REMOVE_ACTIVE(pcb);
    mem_free(pcb);
    pcb = NULL;

    break;
  case SYN_RCVD:
    err = tcp_send_fin(pcb);
    if (err == ERR_OK) {

      pcb->state = FIN_WAIT_1;
    }
    break;
  case ESTABLISHED:
    err = tcp_send_fin(pcb);
    if (err == ERR_OK) {

      pcb->state = FIN_WAIT_1;
    }
    break;
  case CLOSE_WAIT:
    err = tcp_send_fin(pcb);
    if (err == ERR_OK) {

      pcb->state = LAST_ACK;
    }
    break;
  default:
    /* Has already been closed, do nothing. */
    err = ERR_OK;
    pcb = NULL;
    break;
  }

  if (pcb != NULL && err == ERR_OK) {
    /* To ensure all data has been sent when tcp_close returns, we have
       to make sure tcp_output doesn't fail.
       Since we don't really have to ensure all data has been sent when tcp_close
       returns (unsent data is sent from tcp timer functions, also), we don't care
       for the return value of tcp_output for now. */
    /* @todo: When implementing SO_LINGER, this must be changed somehow:
       If SOF_LINGER is set, the data should be sent and acked before close returns.
       This can only be valid for sequential APIs, not for the raw API. */
     tcp_output(pcb);
      sockets_list[pcb->socket_ID].data_flag =1;
  }
  return err;
}
/**
 * Closes the connection held by the PCB.
 *
 * Listening pcbs are freed and may not be referenced any more.
 * Connection pcbs are freed if not yet connected and may not be referenced
 * any more. If a connection is established (at least SYN received or in
 * a closing state), the connection is closed, and put in a closing state.
 * The pcb is then automatically freed in tcp_slowtmr(). It is therefore
 * unsafe to reference it (unless an error is returned).
 *
 * @param pcb the tcp_pcb to close
 * @return ERR_OK if connection has been closed
 *         another err_t if closing failed and pcb is not freed
 */
err_t
tcp_close(struct tcp_pcb *pcb)
{
  if (pcb->state != LISTEN)
  {
    /* Set a flag not to receive any more data... */
    pcb->flags |= TF_RXCLOSED;
  }
  /* ... and close */
  return tcp_close_shutdown(pcb, 1);
}

/**
 * Abandons a connection and optionally sends a RST to the remote
 * host.  Deletes the local protocol control block. This is done when
 * a connection is killed because of shortage of memory.
 *
 * @param pcb the tcp_pcb to abort
 * @param reset boolean to indicate whether a reset should be sent
 */
void tcp_abandon(struct tcp_pcb *pcb, int reset)
{
  u32_t seqno, ackno;
#if LWIP_CALLBACK_API  
  tcp_err_fn errf;
#endif /* LWIP_CALLBACK_API */
  void *errf_arg;
  /* pcb->state LISTEN not allowed here */
  /* Figure out on which TCP PCB list we are, and remove us. If we
     are in an active state, call the receive function associated with
     the PCB with a NULL argument, and send an RST to the remote end. */
  if (pcb->state == TIME_WAIT) {
    tcp_pcb_remove(&tcp_tw_pcbs, pcb);
    mem_free(pcb);
  } else {
    seqno = pcb->snd_nxt;
    ackno = pcb->rcv_nxt;
#if LWIP_CALLBACK_API
    errf = pcb->errf;
#endif /* LWIP_CALLBACK_API */
    errf_arg = pcb->callback_arg;
    TCP_PCB_REMOVE_ACTIVE(pcb);
    if (pcb->unacked != NULL) {
      tcp_segs_free(pcb->unacked);
    }
    if (pcb->unsent != NULL) {
      tcp_segs_free(pcb->unsent);
    }
#if TCP_QUEUE_OOSEQ    
    if (pcb->ooseq != NULL) {
      tcp_segs_free(pcb->ooseq);
    }
#endif /* TCP_QUEUE_OOSEQ */
    if (reset) {

      tcp_rst(seqno, ackno, &pcb->local_ip, &pcb->remote_ip, pcb->local_port, pcb->remote_port);
    }
    mem_free( pcb);
    TCP_EVENT_ERR(pcb);
  }
}

/**
 * Aborts the connection by sending a RST (reset) segment to the remote
 * host. The pcb is deallocated. This function never fails.
 *
 * ATTENTION: When calling this from one of the TCP callbacks, make
 * sure you always return ERR_ABRT (and never return ERR_ABRT otherwise
 * or you will risk accessing deallocated memory or memory leaks!
 *
 * @param pcb the tcp pcb to abort
 */
void
tcp_abort(struct tcp_pcb *pcb)
{
  tcp_abandon(pcb, 1);
}

/**
 * Binds the connection to a local portnumber and IP address. If the
 * IP address is not given (i.e., ipaddr == NULL), the IP address of
 * the outgoing network interface is used instead.
 *
 * @param pcb the tcp_pcb to bind (no check is done whether this pcb is
 *        already bound!)
 * @param ipaddr the local ip address to bind to (use IP_ADDR_ANY to bind
 *        to any local address
 * @param port the local port to bind to
 * @return ERR_USE if the port is already in use
 *         ERR_VAL if bind failed because the PCB is not in a valid state
 *         ERR_OK if bound
 */
err_t
tcp_bind(struct tcp_pcb *pcb, ip_addr_t *ipaddr, u16_t port)
{
  int i;
  int max_pcb_list = NUM_TCP_PCB_LISTS;
  struct tcp_pcb *cpcb;
  if (port == 0) {
    port = tcp_new_port();
    if (port == 0) {
      return ERR_BUF;
    }
  }

  /* Check if the address already is in use (on all lists) */
  for (i = 0; i < max_pcb_list; i++) {
    for(cpcb = *tcp_pcb_lists[i]; cpcb != NULL; cpcb = cpcb->next) {
      if (cpcb->local_port == port) {

        {
          if (ip_addr_isany(&(cpcb->local_ip)) ||
              ip_addr_isany(ipaddr) ||
              ip_addr_cmp(&(cpcb->local_ip), ipaddr)) {       // if the same IP address is used by anther connection
            return ERR_USE;
          }
        }
      }
    }
  }

  if (!ip_addr_isany(ipaddr)) {
    pcb->local_ip = *ipaddr;
  }
  pcb->local_port = port;
  TCP_REG(&tcp_bound_pcbs, pcb);

  return ERR_OK;
}



void tcp_listen(struct tcp_pcb *pcb , u16_t local_port ,ip_addr_t *ipaddr )
{
  /* already listening? */
  if (pcb->state == LISTEN)
  { }
  else
  {
    pcb->state = LISTEN;
    pcb->local_port = local_port;
    pcb->local_ip = *ipaddr;
    TCP_REG_LISTEN(pcb);
    tcp_sent(pcb, NULL);
    tcp_recv(pcb, NULL);
    pcb->connected =conection_established;
   }

}

/**
 * This function should be called by the application when it has
 * processed the data. The purpose is to advertise a larger window
 * when the data has been processed.
 *
 * @param pcb the tcp_pcb for which data is read
 * @param len the amount of bytes that have been read by the application
 */
void
tcp_recved(struct tcp_pcb *pcb, u16_t len)
{
  pcb->rcv_wnd += len;
  if (pcb->rcv_wnd > TCP_WND) {
    pcb->rcv_wnd = TCP_WND;
  }
}

/**
 * Allocate a new local TCP port.
 *
 * @return a new (free) local TCP port number
 */
static u16_t
tcp_new_port(void)
{
  u8_t i;
  u16_t n = 0;
  struct tcp_pcb *pcb;
  
again:
  if (tcp_port++ == TCP_LOCAL_PORT_RANGE_END) {
    tcp_port = TCP_LOCAL_PORT_RANGE_START;
  }
  /* Check all PCB lists. */
  for (i = 0; i < NUM_TCP_PCB_LISTS; i++) {
    for(pcb = *tcp_pcb_lists[i]; pcb != NULL; pcb = pcb->next) {
      if (pcb->local_port == tcp_port) {
        if (++n > (TCP_LOCAL_PORT_RANGE_END - TCP_LOCAL_PORT_RANGE_START)) {
          return 0;
        }
        goto again;
      }
    }
  }
  return tcp_port;
}

/**
 * Connects to another host. The function given as the "connected"
 * argument will be called when the connection has been established.
 *
 * @param pcb the tcp_pcb used to establish the connection
 * @param ipaddr the remote ip address to connect to
 * @param port the remote tcp port to connect to
 * @param connected callback function to call when connected (or on error)
 * @return ERR_VAL if invalid arguments are given
 *         ERR_OK if connect request has been sent
 *         other err_t values if connect request couldn't be sent
 */
err_t tcp_connect(struct tcp_pcb *pcb, ip_addr_t *ipaddr, u16_t port, tcp_connected_fn connected)
{
  err_t ret;
  u32_t iss;
  u16_t old_local_port=0;
  old_local_port =old_local_port ;
  if (ipaddr != NULL)                                    // make sure that you are not connecting a 0 address and you have an ip address
  {pcb->remote_ip = *ipaddr;}                            // assign the remote ip address
  else
  {return ERR_VAL;}
  pcb->remote_port = port;                               // assign the remote port no.
  old_local_port = pcb->local_port;
  iss = tcp_next_iss();
  pcb->rcv_nxt = 0;
  pcb->snd_nxt = iss;
  pcb->lastack = iss - 1;
  pcb->snd_lbb = iss - 1;
  pcb->rcv_wnd = TCP_WND;
  pcb->rcv_ann_wnd = TCP_WND;
  pcb->rcv_ann_right_edge = pcb->rcv_nxt;
  pcb->snd_wnd = TCP_WND;
  pcb->mss = 536;                                        // maxium segment size = 536
  pcb->connected =connected;
  if (pcb->local_port == 0)                              // if you don't have port no assign a new available one
    {
      pcb->local_port = tcp_new_port();
      if (pcb->local_port == 0)
      {return ERR_BUF;}
    }
  ret = tcp_enqueue_flags(pcb, TCP_SYN);                 /* Send a SYN together. */
  if (ret == ERR_OK)                                     /* SYN segment was enqueued, changed the pcbs state now */
  {
    pcb->state = SYN_SENT;
    TCP_REG_ACTIVE(pcb);                                 //  put the TCP in the active list
     tcp_output(pcb);                                     // send this syn segment
    sockets_list[pcb->socket_ID].data_flag =1;
  }
  return ret;
}

/**
 * Called every 500 ms and implements the retransmission timer and the timer that
 * removes PCBs that have been in TIME-WAIT for enough time. It also increments
 * various timers such as the inactivity timer in each PCB.
 *
 * Automatically called from tcp_tmr().
 */
void
tcp_slowtmr(void)
{
  struct tcp_pcb *pcb, *prev;
  u8_t pcb_remove;      /* flag if a PCB should be removed */
  u8_t pcb_reset;       /* flag if a RST should be sent when removing */
  ++tcp_ticks;
  ++tcp_timer_ctr;

tcp_slowtmr_start:
  /* Steps through all of the active PCBs. */
  prev = NULL;
  pcb = tcp_active_pcbs;
  while (pcb != NULL)
  {
    if (pcb->last_timer == tcp_timer_ctr)
    {
      /* skip this pcb, we have already processed it */
      pcb = pcb->next;
      continue;
    }
    pcb->last_timer = tcp_timer_ctr;
    pcb_remove = 0;
    pcb_reset = 0;


    /* case 1 if you are trying to open a connection and no response till 6 times  so remove*/
    if (pcb->state == SYN_SENT && pcb->nrtx == TCP_SYNMAXRTX)
    {
        ++pcb_remove;
    }

    /* case 2 no respose till 12 time  so remove */
    else if (pcb->nrtx == TCP_MAXRTX)
    {
        ++pcb_remove;
    }

    /* case 3 the timer expired and there is unacked */
    else
    {
     if(pcb->rtime >= 0)/* Increase the retransmission timer if it is running */
     { ++pcb->rtime; }
     if (pcb->unacked != NULL && pcb->rtime >= pcb->rto) /* if the timer expired and there is unacked */
     {
          /* Time for a retransmission. */
          /* Double retransmission time-out unless we are trying to
           * connect to somebody (i.e., we are in SYN_SENT).
           * */
      if (pcb->state != SYN_SENT)
      {pcb->rto =  pcb->rto *2;}
      pcb->rtime = 0;     /* Reset the retransmission timer. */
      tcp_rexmit_rto(pcb);
     }
    }

    /* Check if this PCB has stayed too long in FIN-WAIT-2 */
    if (pcb->state == FIN_WAIT_2)
    {
      /* If this PCB is in FIN_WAIT_2 because of SHUT_WR don't let it time out. */
      if (pcb->flags & TF_RXCLOSED)
      {
        /* PCB was fully closed (either through close() or SHUT_RDWR):normal FIN-WAIT timeout handling. */
        if (  (u32_t)(tcp_ticks - pcb->tmr) >TCP_FIN_WAIT_TIMEOUT / TCP_SLOW_INTERVAL)
        {++pcb_remove;}
      }
    }

    /* Check if KEEPALIVE should be sent */
    if(ip_get_option(pcb, SOF_KEEPALIVE) &&((pcb->state == ESTABLISHED) ||(pcb->state == CLOSE_WAIT)))
    {
      if((u32_t)(tcp_ticks - pcb->tmr) >(pcb->keep_idle + TCP_KEEP_DUR(pcb)) / TCP_SLOW_INTERVAL)
      {
        ++pcb_remove;
        ++pcb_reset;
      }
      else if((u32_t)(tcp_ticks - pcb->tmr) >  (pcb->keep_idle + pcb->keep_cnt_sent * TCP_KEEP_INTVL(pcb)) / TCP_SLOW_INTERVAL)
      {
        tcp_keepalive(pcb);
        pcb->keep_cnt_sent++;
      }
    }

    /* If this PCB has queued out of sequence data, but has been
       inactive for too long, will drop the data (it will eventually be retransmitted). */
#if TCP_QUEUE_OOSEQ
    if (pcb->ooseq != NULL && (u32_t)tcp_ticks - pcb->tmr >= pcb->rto * TCP_OOSEQ_TIMEOUT)
    {
      tcp_segs_free(pcb->ooseq);
      pcb->ooseq = NULL;
    }
#endif

    /* case Check if this PCB has stayed too long in SYN-RCVD */
    if (pcb->state == SYN_RCVD)
    {
      if ((u32_t)(tcp_ticks - pcb->tmr) >TCP_SYN_RCVD_TIMEOUT / TCP_SLOW_INTERVAL)
      { ++pcb_remove;}
    }

    /*case  Check if this PCB has stayed too long in LAST-ACK */
    if (pcb->state == LAST_ACK)
    {
      if ((u32_t)(tcp_ticks - pcb->tmr) > 2 * TCP_MSL / TCP_SLOW_INTERVAL)
      {++pcb_remove;}
    }

    /* If the PCB should be removed, do it. */
    if (pcb_remove)
    {
      struct tcp_pcb *pcb2;
      tcp_err_fn err_fn;
      void *err_arg;
      tcp_pcb_purge(pcb);
      /* Remove PCB from tcp_active_pcbs list. */
      if (prev != NULL)
      {prev->next = pcb->next;}
      else
      {tcp_active_pcbs = pcb->next;} /* This PCB was the first. */
      if (pcb_reset)
      {tcp_rst(pcb->snd_nxt, pcb->rcv_nxt, &pcb->local_ip, &pcb->remote_ip,pcb->local_port, pcb->remote_port);}

      err_fn = pcb->errf; /* Function to be called whenever a fatal error occurs. */
      pcb2 = pcb;
      pcb = pcb->next;
      mem_free( pcb2);
      tcp_active_pcbs_changed = 0;
//      TCP_EVENT_ERR( );
      if (tcp_active_pcbs_changed)
       { goto tcp_slowtmr_start;}
    }
    prev = pcb;
    pcb = pcb->next;
  }

   /* Steps through all of the TIME-WAIT PCBs. */
  prev = NULL;
//  pcb = tcp_tw_pcbs;
//  while (pcb != NULL)
//  {
//     pcb_remove = 0;
//    /* case Check if this PCB has stayed long enough in TIME-WAIT */
//    if ((u32_t)(tcp_ticks - pcb->tmr) > 2 * TCP_MSL / TCP_SLOW_INTERVAL)
//    {++pcb_remove; }
//
//    /* If the PCB should be removed, do it. */
//    if (1/*pcb_remove*/)
//    {
//      struct tcp_pcb *pcb2;
//      tcp_pcb_purge(pcb);
//      /* Remove PCB from tcp_tw_pcbs list. */
//      if (prev != NULL)
//      {prev->next = pcb->next;}
//      else
//      {tcp_tw_pcbs = pcb->next; } /* This PCB was the first. */
//      pcb2 = pcb;
//      pcb = pcb->next;
//      mem_free(pcb2);
//    }
//    else
//    {
//      prev = pcb;
//      pcb = pcb->next;
//    }
//  }
}

void
tcp_segs_free(struct tcp_seg *seg)
{
  while (seg != NULL) {
    struct tcp_seg *next = seg->next;
    tcp_seg_free(seg);
    seg = next;
  }
}

/**
 * Frees a TCP segment (tcp_seg structure).
 *
 * @param seg single tcp_seg to free
 */
void tcp_seg_free(struct tcp_seg *seg)
{
  if (seg != NULL) {
    if (seg->p != NULL)
    {
      pbuf_free(seg->p);
    }
    mem_free(seg);
  }
}
/**
 * Returns a copy of the given TCP segment.
 * The pbuf and data are not copied, only the pointers
 *
 * @param seg the old tcp_seg
 * @return a copy of seg
 */ 
struct tcp_seg * tcp_seg_copy(struct tcp_seg *seg)
{
  struct tcp_seg *cseg;

  cseg = (struct tcp_seg *)mem_malloc(sizeof(struct tcp_seg));
  if (cseg == NULL) {
    return NULL;
  }
  SMEMCPY((u8_t *)cseg, (const u8_t *)seg, sizeof(struct tcp_seg)); 
  pbuf_ref(cseg->p);
  return cseg;
}
/**
 * Default receive callback that is called if the user didn't register
 * a recv callback for the pcb.
 */
err_t tcp_recv_null(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  LWIP_UNUSED_ARG(arg);
  if (p != NULL) {
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
  } else if (err == ERR_OK) {
    return tcp_close(pcb);
  }
  return ERR_OK;
}
/**
 * Allocate a new tcp_pcb structure.
 *
 * @param prio priority for the new pcb
 * @return a new tcp_pcb that initially is in state CLOSED
 */
struct tcp_pcb * tcp_alloc(u8_t prio)
{
  struct tcp_pcb *pcb;
  u32_t iss;
  pcb = (struct tcp_pcb *)mem_malloc(sizeof(struct tcp_pcb));
  if (pcb == NULL)
  {
      return pcb;
  }
  if (pcb != NULL) {
    memset(pcb, 0, sizeof(struct tcp_pcb)); /* all elements are set to zero*/
    pcb->prio = prio;
    pcb->snd_buf = TCP_SND_BUF;
    pcb->snd_queuelen = 0;
    pcb->rcv_wnd = TCP_WND;
    pcb->rcv_ann_wnd = TCP_WND;
    pcb->tos = 0;
    pcb->ttl = TCP_TTL;
    pcb->mss = (TCP_MSS > 536) ? 536 : TCP_MSS;      /* As initial send MSS, we use TCP_MSS but limit it to 536. The send MSS is updated when an MSS option is received.*/
    pcb->rto = 3000 / TCP_SLOW_INTERVAL;
    pcb->sa = 0;
    pcb->sv = 3000 / TCP_SLOW_INTERVAL;
    pcb->rtime = -1;
    pcb->cwnd = 1;
    iss = tcp_next_iss();
    pcb->snd_wl2 = iss;    /* Sequence and acknowledgement numbers of last*/
    pcb->snd_nxt = iss;    /* next new seqno to be sent */
    pcb->lastack = iss;   /* Highest acknowledged seqno. */
    pcb->snd_lbb = iss;   //Sequence number of next byte to be buffered
    pcb->tmr = tcp_ticks;
    pcb->last_timer = tcp_timer_ctr;
    pcb->polltmr = 0;
    pcb->recv = tcp_recv_null;
    pcb->keep_idle  = TCP_KEEPIDLE_DEFAULT;/* Init KEEPALIVE timer */
    pcb->keep_cnt_sent = 0;
  }
  return pcb;
}

/**
 * Creates a new TCP protocol control block but doesn't place it on
 * any of the TCP PCB lists.
 * The pcb is not put on any list until binding using tcp_bind().
 *
 * @internal: Maybe there should be a idle TCP PCB list where these
 * PCBs are put on. Port reservation using tcp_bind() is implemented but
 * allocated pcbs that are not bound can't be killed automatically if wanting
 * to allocate a pcb with higher prio (@see tcp_kill_prio())
 *
 * @return a new tcp_pcb that initially is in state CLOSED
 */
struct tcp_pcb *
tcp_new(void)
{
  return tcp_alloc(TCP_PRIO_NORMAL);
}

/**
 * Used to specify the argument that should be passed callback
 * functions.
 *
 * @param pcb tcp_pcb to set the callback argument
 * @param arg void pointer argument to pass to callback functions
 */ 
void tcp_arg(struct tcp_pcb *pcb, void *arg)
{
  /* This function is allowed to be called for both listen pcbs and
     connection pcbs. */
  pcb->callback_arg = arg;
}

/**
 * Used to specify the function that should be called when a TCP
 * connection receives data.
 *
 * @param pcb tcp_pcb to set the recv callback
 * @param recv callback function to call for this pcb when data is received
 */ 
void
tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn recv)
{
  pcb->recv = recv;
}



/**
 * Used to specify the function that should be called when TCP data
 * has been successfully delivered to the remote host.
 *
 * @param pcb tcp_pcb to set the sent callback
 * @param sent callback function to call for this pcb when data is successfully sent
 */ 
void
tcp_sent(struct tcp_pcb *pcb, tcp_sent_fn sent)
{
  pcb->sent = sent;
}

/**
 * Used to specify the function that should be called when a fatal error
 * has occured on the connection.
 *
 * @param pcb tcp_pcb to set the err callback
 * @param err callback function to call for this pcb when a fatal error
 *        has occured on the connection
 */ 
void
tcp_err(struct tcp_pcb *pcb, tcp_err_fn err)
{
  pcb->errf = err;
}

/**
 * Used for specifying the function that should be called when a
 * LISTENing connection has been connected to another host.
 *
 * @param pcb tcp_pcb to set the accept callback
 * @param accept callback function to call for this pcb when LISTENing
 *        connection has been connected to another host
 */ 
void
tcp_accept(struct tcp_pcb *pcb, tcp_accept_fn accept)
{
  /* This function is allowed to be called for both listen pcbs and connection pcbs. */
  pcb->accept = accept;
}

/**
 * Purges a TCP PCB. Removes any buffered data and frees the buffer memory
 * (pcb->ooseq, pcb->unsent and pcb->unacked are freed).
 *
 * @param pcb tcp_pcb to purge. The pcb itself is not deallocated!
 */
void tcp_pcb_purge(struct tcp_pcb *pcb)
{
  if (pcb->state != CLOSED &&
     pcb->state != TIME_WAIT &&
     pcb->state != LISTEN) {
    if (pcb->refused_data != NULL) {

      pbuf_free(pcb->refused_data);
      pcb->refused_data = NULL;
    }
    if (pcb->unsent != NULL) {

    }
    if (pcb->unacked != NULL) {

    }
#if TCP_QUEUE_OOSEQ
    if (pcb->ooseq != NULL) {
     }
    tcp_segs_free(pcb->ooseq);
    pcb->ooseq = NULL;
#endif /* TCP_QUEUE_OOSEQ */

    /* Stop the retransmission timer as it will expect data on unacked
       queue if it fires */
    pcb->rtime = -1;

    tcp_segs_free(pcb->unsent); // do it by fo loop is better
    tcp_segs_free(pcb->unacked);
    pcb->unacked = pcb->unsent = NULL;
#if TCP_OVERSIZE
    pcb->unsent_oversize = 0;
#endif /* TCP_OVERSIZE */
  }
}

/**
 * Purges the PCB and removes it from a PCB list. Any delayed ACKs are sent first.
 *
 * @param pcblist PCB list to purge.
 * @param pcb tcp_pcb to purge. The pcb itself is NOT deallocated!
 */
void
tcp_pcb_remove(struct tcp_pcb **pcblist, struct tcp_pcb *pcb)
{
  TCP_RMV(pcblist, pcb);
  tcp_pcb_purge(pcb);
}

/**
 * Calculates a new initial sequence number for new connections.
 *
 * @return u32_t pseudo random sequence number
 */
u32_t
tcp_next_iss(void)
{
  static u32_t iss = 6510;
  iss += tcp_ticks;       /* XXX */
  return iss;
}

void tcp_timer_needed(void)
{

}




