/**
 * @file
 * Transmission Control Protocol, incoming traffic
 *
 * The input processing functions of the TCP layer.
 *
 * These functions are generally called in the order (ip_input() ->)
 * tcp_input() -> * tcp_process() -> tcp_receive() (-> application).
 *
 */
#include "lwip/opt.h"
#include "lwip/tcp_impl.h"
#include "lwip/def.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/mem.h"
#include "lwip/inet_chksum.h"
#include "autosar_includes/TCPIP_config.h"

extern struct tcp_pcb * TCP_list[5];

/* These variables are global to all functions involved in the input
   processing of TCP segments. They are set by the tcp_input()
   function. */
static struct tcp_seg inseg;
static struct tcp_hdr *tcphdr;
static struct ip_hdr *iphdr;
static u32_t seqno, ackno;
static u8_t flags;
static u16_t tcplen;
static u8_t last_state;
static u8_t recv_flags;
static struct pbuf *recv_data;
struct tcp_pcb *tcp_input_pcb;

static err_t tcp_process(struct tcp_pcb *pcb);
static void tcp_receive(struct tcp_pcb *pcb);
static err_t tcp_listen_input(struct tcp_pcb *pcb);
static err_t tcp_timewait_input(struct tcp_pcb *pcb);

/**
 * The initial input processing of TCP. It verifies the TCP header, demultiplexes
 * the segment between the PCBs and passes it on to tcp_process(), which implements
 * the TCP finite state machine. This function is called by the IP layer (in
 * ip_input()).
 *
 * @param p received TCP segment to process (p->payload pointing to the IP header)
 * @param inp network interface on which this segment was received
 */
void tcp_input(struct pbuf *p, struct netif *inp)
{
  struct tcp_pcb *pcb, *prev;
  struct tcp_pcb *lpcb;
  u8_t hdrlen;
  err_t err;
  iphdr =  (struct ip_hdr *)p->payload;                                      //  now the pointer points to the start of ip_header , then type_cast the pay_load to ip_header
  tcphdr = (struct tcp_hdr *)((u8_t *)p->payload + IPH_HL(iphdr) * 4);       //  address of pay_load + length of ip_header = start of tcp_header , then type_cast the address to tcp_header
  if (pbuf_header(p, -((s16_t)(IPH_HL(iphdr) * 4))) || (p->tot_len < sizeof(struct tcp_hdr)))      /* remove ip header from payload and point to tcp_header p->total -=header size */
  { goto dropped;}                                                                                 /* drop short packets */
  if (ip_addr_isbroadcast(&current_iphdr_dest, inp) ||ip_addr_ismulticast(&current_iphdr_dest))    /* Don't even process incoming broadcasts/multicasts. */
  { goto dropped;}
  /* due to padding it made an fault in crc calculaton it should be 20 not 30*/
  if( p->tot_len < 40 ){p->tot_len = 20;}
  if (       inet_chksum_pseudo(p,     ip_current_src_addr(),        ip_current_dest_addr(),      IP_PROTO_TCP,      p->tot_len) != 0)    /* Verify TCP checksum. */
  {       goto dropped;}
  hdrlen = TCPH_HDRLEN(tcphdr);                                   // data offset
  if(pbuf_header(p, -(hdrlen * 4)))                               /* Move the payload pointer in the pbuf so that it points to the TCP data instead of the TCP header. */
  { goto dropped;}
  /* Convert fields in TCP header to host byte order. */
  tcphdr->src = (tcphdr->src);
  tcphdr->dest = (tcphdr->dest);
  seqno = tcphdr->seqno = (tcphdr->seqno);
  ackno = tcphdr->ackno = (tcphdr->ackno);
  tcphdr->wnd = (tcphdr->wnd);
  flags = TCPH_FLAGS(tcphdr);
  tcplen = p->tot_len + ((flags & (TCP_FIN | TCP_SYN)) ? 1 : 0);        //data length only , if it is fin or syn add a byte
  prev = NULL;
  for(pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next)/* Demultiplex an incoming segment. First, we check if it is destined for an active connection. */
  {
    if (pcb->remote_port == tcphdr->src &&  pcb->local_port == tcphdr->dest  &&   ip_addr_cmp(&(pcb->remote_ip), &current_iphdr_src) &&  ip_addr_cmp(&(pcb->local_ip), &current_iphdr_dest))
    {
        /* Move this PCB to the front of the list so that subsequent
         lookups will be faster (we exploit locality in TCP segment
         arrivals). */
      if (prev != NULL)
      {
        prev->next = pcb->next;
        pcb->next = tcp_active_pcbs;
        tcp_active_pcbs = pcb;
      }
      break;
    }
    prev = pcb;
  }
  if (pcb == NULL)   /* If it did not go to an active connection, we check the connections in the TIME-WAIT state. */
  {
    for(pcb = tcp_tw_pcbs; pcb != NULL; pcb = pcb->next)
    {
       if (pcb->remote_port == tcphdr->src && pcb->local_port == tcphdr->dest && ip_addr_cmp(&(pcb->remote_ip), &current_iphdr_src) && ip_addr_cmp(&(pcb->local_ip), &current_iphdr_dest))
      {
        /* We don't really care enough to move this PCB to the front
           of the list since we are not very likely to receive that
           many segments for connections in TIME-WAIT. */
        tcp_timewait_input(pcb);
        pbuf_free(p);
        return;
      }
    }
    /* Finally, if we still did not get a match, we check all PCBs that are LISTENing for incoming connections. */
    prev = NULL;
    for(lpcb = tcp_listen_pcbs; lpcb != NULL; lpcb = lpcb->next)
    {
      if ( (lpcb->local_port == tcphdr->dest)  && (ip_addr_cmp(&(lpcb->local_ip), &current_iphdr_dest)) )
         { break; /* found a match */}
      prev = lpcb;
    }
    if (lpcb != NULL)
    {
      tcp_listen_input(lpcb);     // open the connection
      pbuf_free(p);               //  free the buffer
      return;
    }
  }
  if (pcb != NULL)                 /* The incoming segment belongs to a connection. */
  {
    /* Set up a tcp_seg structure. */
    inseg.next = NULL;
    inseg.len = p->tot_len;
    inseg.p = p;
    inseg.tcphdr = tcphdr;
    recv_data = NULL;
    recv_flags = 0;
//    if (flags & TCP_PSH)
//    {p->flags |= PBUF_FLAG_PUSH;}
    tcp_input_pcb = pcb;
    err = tcp_process(pcb);
    /* A return value of ERR_ABRT means that tcp_abort() was called
       and that the pcb has been freed. If so, we don't do anything. */
    if (err != ERR_ABRT)
    {
      if (recv_flags & TF_RESET)
      {
        /* TF_RESET means that the connection was reset by the other
           end. We then call the error callback to inform the
           application that the connection is dead before we
           deallocate the PCB. */
        TCP_EVENT_ERR(pcb);
        tcp_pcb_remove(&tcp_active_pcbs, pcb);

        mem_free(pcb);
      }
      else if (recv_flags & TF_CLOSED)
      {   // from lastack to here
        /* The connection has been closed and we will deallocate the
           PCB. */
        if (!(pcb->flags & TF_RXCLOSED)) {
          /* Connection closed although the application has only shut down the
             tx side: call the PCB's err callback and indicate the closure to
             ensure the application doesn't continue using the PCB. */
          TCP_EVENT_ERR(pcb);
        }
        tcp_pcb_remove(&tcp_active_pcbs, pcb);
        mem_free( pcb);
      }
      else
      {
        err = ERR_OK;
        if (recv_data != NULL)    // if there data in this incoming segment
        {
          if (pcb->flags & TF_RXCLOSED)
          {
            /* received data although already closed -> abort (send RST) to
               notify the remote host that not all data has been processed */
            pbuf_free(recv_data);
            tcp_abort(pcb);
            goto aborted;
          }
          TCP_EVENT_RECV(pcb, recv_data, ERR_OK, err);      /* Notify application that data has been received. from now it the responsibility of app */
        }

        /* If a FIN segment was received, we call the callback
           function with a NULL buffer to indicate EOF. */
        if (recv_flags & TF_GOT_FIN)
        {
           if (pcb->state != TIME_WAIT)
           {
            TCP_EVENT_CLOSED(pcb, err);     // tell the your app that you are received fin
            if (err == ERR_ABRT)
             {goto aborted;}
           }
        }
        tcp_input_pcb = NULL;
        tcp_output(pcb);/* Try to send something out. */
        sockets_list[pcb->socket_ID].data_flag =1;

      }
    }
    /* Jump target if pcb has been aborted in a callback (by calling tcp_abort()).
       Below this line, 'pcb' may not be dereferenced! */
aborted:
    tcp_input_pcb = NULL;
    recv_data = NULL;
    /* give up our reference to inseg.p */
    if (inseg.p != NULL)
    {
      pbuf_free(inseg.p);
      inseg.p = NULL;
    }
  }
  else  /* If no matching PCB was found, send a TCP RST (reset) to the sender. */
  {
    if (!(TCPH_FLAGS(tcphdr) & TCP_RST))
    {tcp_rst(ackno, seqno + tcplen, ip_current_dest_addr(), ip_current_src_addr(), tcphdr->dest, tcphdr->src); }
    pbuf_free(p);
  }
  return;
dropped:
  pbuf_free(p);
}

/**
 * Called by tcp_input() when a segment arrives for a listening
 * connection (from tcp_input()).
 *
 * @param pcb the tcp_pcb_listen for which a segment arrived
 * @return ERR_OK if the segment was processed
 *         another err_t on error
 *
 * @note the return value is not (yet?) used in tcp_input()
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
static err_t tcp_listen_input(struct tcp_pcb *pcb)
{
  struct tcp_pcb *npcb = pcb;
  err_t rc;

  if (flags & TCP_RST)
  {
    /* An incoming RST should be ignored. Return. */
    return ERR_OK;
  }

  /* In the LISTEN state, we check for incoming SYN segments,
     creates a new PCB, and responds with a SYN|ACK. */
  if (flags & TCP_ACK)
  {
    /* For incoming segments with the ACK flag set, respond with aRST. */
    tcp_rst(ackno, seqno + tcplen, ip_current_dest_addr(),ip_current_src_addr(), tcphdr->dest, tcphdr->src);
  }
  else if (flags & TCP_SYN)
  {
    ip_addr_copy(npcb->local_ip, current_iphdr_dest);              // local ip address
    npcb->local_port = pcb->local_port;                            //
    ip_addr_copy(npcb->remote_ip, current_iphdr_src);              //
    npcb->remote_port = tcphdr->src;                               // remote ip address
    npcb->state = SYN_RCVD;                                        // change into syn_rcvd state
    npcb->rcv_nxt = seqno + 1;                                     // recive_next no = the sequence of incoming frame  +1
    npcb->rcv_ann_right_edge = npcb->rcv_nxt;                      //
    npcb->snd_wnd = tcphdr->wnd;                                   // set th window to "window" in the incomng segment
    npcb->snd_wnd_max = tcphdr->wnd;
    npcb->ssthresh = npcb->snd_wnd;
    npcb->snd_wl1 = seqno - 1;                                    /* initialise to seqno-1 to force window update */
    npcb->callback_arg = pcb->callback_arg;
    npcb->accept = pcb->accept;
    TCP_REG_ACTIVE(npcb);                                          /* Register the new PCB so that we can begin receiving segments for it. */
    TCP_RMV_LISTEN(npcb);



    /* Send a SYN|ACK together with the MSS option. */
    rc = tcp_enqueue_flags(npcb, TCP_SYN | TCP_ACK);

    if (rc != ERR_OK)
    {
      tcp_abandon(npcb, 0);
      return rc;
    }
    return tcp_output(npcb);
    sockets_list[npcb->socket_ID].data_flag =1;
  }
  return ERR_OK;
}

/**
 * Called by tcp_input() when a segment arrives for a connection in
 * TIME_WAIT.
 *
 * @param pcb the tcp_pcb for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
static err_t
tcp_timewait_input(struct tcp_pcb *pcb)
{
  /* RFC 1337: in TIME_WAIT, ignore RST and ACK FINs + any 'acceptable' segments */
  /* RFC 793 3.9 Event Processing - Segment Arrives:
   * - first check sequence number - we skip that one in TIME_WAIT (always
   *   acceptable since we only send ACKs)
   * - second check the RST bit (... return) */
  if (flags & TCP_RST)  {
    return ERR_OK;
  }
  /* - fourth, check the SYN bit, */
  if (flags & TCP_SYN) {
    /* If an incoming segment is not acceptable, an acknowledgment
       should be sent in reply */
    if (TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, pcb->rcv_nxt+pcb->rcv_wnd)) {
      /* If the SYN is in the window it is an error, send a reset */
      tcp_rst(ackno, seqno + tcplen, ip_current_dest_addr(), ip_current_src_addr(),
        tcphdr->dest, tcphdr->src);
      return ERR_OK;
    }
  } else if (flags & TCP_FIN) {
    /* - eighth, check the FIN bit: Remain in the TIME-WAIT state.
         Restart the 2 MSL time-wait timeout.*/
    pcb->tmr = tcp_ticks;
  }

  if ((tcplen > 0))  {
    /* Acknowledge data, FIN or out-of-window SYN */
    pcb->flags |= TF_ACK_NOW;
    return tcp_output(pcb);
    sockets_list[pcb->socket_ID].data_flag =1;

  }
  return ERR_OK;
}

/**
 * Implements the TCP state machine. Called by tcp_input. In some
 * states tcp_receive() is called to receive data. The tcp_seg
 * argument will be freed by the caller (tcp_input()) unless the
 * recv_data pointer in the pcb is set.
 *
 * @param pcb the tcp_pcb for which a segment arrived
 *
 * @note the segment which arrived is saved in global variables, therefore only the pcb
 *       involved is passed as a parameter to this function
 */
static err_t tcp_process(struct tcp_pcb *pcb)
{
  struct tcp_seg *rseg;
  u8_t acceptable = 0;
  err_t err;
  err = ERR_OK;
  if (flags & TCP_RST) /* Process incoming RST segments. */
  {
    /* First, determine if the reset is acceptable. */
    if (pcb->state == SYN_SENT)
    {
      if (ackno == pcb->snd_nxt)
      { acceptable = 1;}
    }
    else
    {
      if (TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt,  pcb->rcv_nxt+pcb->rcv_wnd))
      {acceptable = 1;}
    }
    if (acceptable)
    {
      recv_flags |= TF_RESET;
      pcb->flags &= ~TF_ACK_DELAY;
      return ERR_RST;
    }
    else
    {return ERR_OK;}
  }
  if ((flags & TCP_SYN) && (pcb->state != SYN_SENT && pcb->state != SYN_RCVD))  /* Cope with new connection attempt after remote end crashed */
  {
    tcp_ack_now(pcb);
    return ERR_OK;
  }
  if ((pcb->flags & TF_RXCLOSED) == 0) /* Update the PCB (in)activity timer unless rx is closed (see tcp_shutdown) */
  { pcb->tmr = tcp_ticks; }
  pcb->keep_cnt_sent = 0;
  /*   TCP FSM. */
  switch (pcb->state)
  {
  case SYN_SENT:
    /* received SYN ACK with expected sequence number? */
    if ((flags & TCP_ACK) && (flags & TCP_SYN) && (ackno == (pcb->unacked->tcphdr->seqno) + 1))
    {
      pcb->snd_buf++;
      pcb->rcv_nxt = seqno + 1;
      pcb->rcv_ann_right_edge = pcb->rcv_nxt;
      pcb->lastack = ackno;
      pcb->snd_wnd = tcphdr->wnd;
      pcb->snd_wnd_max = tcphdr->wnd;
      pcb->snd_wl1 = seqno - 1;
      pcb->state = ESTABLISHED;
      --pcb->snd_queuelen;
      rseg = pcb->unacked;
      pcb->unacked = rseg->next;
      tcp_seg_free(rseg);
      if(pcb->unacked == NULL)     /* If there's nothing left to acknowledge, stop the retransmit timer, otherwise reset it to start again */
      {pcb->rtime = -1;}
      else
      {
        pcb->rtime = 0;
        pcb->nrtx = 0;
      }
      /* Call the user specified function to call when successfully connected. */
      TCP_EVENT_CONNECTED(pcb, ERR_OK, err);
      if (err == ERR_ABRT)
      {return ERR_ABRT;}
      tcp_ack_now(pcb);
    }
    else if (flags & TCP_ACK)  /* received ACK? possibly a half-open connection */
    {tcp_rst(ackno, seqno + tcplen, ip_current_dest_addr(), ip_current_src_addr(),tcphdr->dest, tcphdr->src);} /* send a RST to bring the other side in a non-synchronized state. */
    break;
  case SYN_RCVD:
    if (flags & TCP_ACK)
    {
      if (TCP_SEQ_BETWEEN(ackno, pcb->lastack+1, pcb->snd_nxt))               /* expected ACK number? *//// last_ack = isc ,ackno =isc+1 ,snd_nxt =isc+1
      {
        last_state =SYN_RCVD;
        pcb->state = ESTABLISHED;
        /* Call the accept function. */
        //TCP_EVENT_ACCEPT(pcb, ERR_OK, err);
        TCP_EVENT_CONNECTED(pcb, ERR_OK, err);
        if (err != ERR_OK)
        {
          /* If the accept function returns with an error, we abort
           * the connection. */
          /* Already aborted? */
          if (err != ERR_ABRT)
          {tcp_abort(pcb);}
          return ERR_ABRT;
        }
        /* If there was any data contained within this ACK,
         * we'd better pass it on to the application as well. */
        tcp_receive(pcb);
        if (recv_flags & TF_GOT_FIN)
        {
          tcp_ack_now(pcb);
          pcb->state = CLOSE_WAIT;
        }
      }
      else  /* incorrect ACK number, send RST */
      {tcp_rst(ackno, seqno + tcplen, ip_current_dest_addr(), ip_current_src_addr(),tcphdr->dest, tcphdr->src);}
    }
    else if ((flags & TCP_SYN) && (seqno == pcb->rcv_nxt - 1))     /* Looks like another copy of the SYN - retransmit our SYN-ACK */
    {tcp_rexmit_rto(pcb); }
    break;
  case CLOSE_WAIT:
    /* FALLTHROUGH */
  case ESTABLISHED:
    tcp_receive(pcb);
    if (recv_flags & TF_GOT_FIN)                                   /* passive close */
    {
      tcp_ack_now(pcb);
      pcb->state = CLOSE_WAIT;
    }
    break;
  case FIN_WAIT_1:
    tcp_receive(pcb);
    if (recv_flags & TF_GOT_FIN)
    {
      if ((flags & TCP_ACK) && (ackno == pcb->snd_nxt))
      {
        tcp_ack_now(pcb);
        tcp_pcb_purge(pcb);
        TCP_RMV_ACTIVE(pcb);
        pcb->state = TIME_WAIT;
        TCP_REG(&tcp_tw_pcbs, pcb);
      }
      else
      {
        tcp_ack_now(pcb);
        pcb->state = CLOSING;
      }
    }
    else if ((flags & TCP_ACK) && (ackno == pcb->snd_nxt)) // wait the other side to send it own fin it has only send its ack
    {
       (pcb)->flags &= ~TF_ACK_NOW;                        // pervent the from sending ack ,as this flag was set due to the agrthium
        pcb->state = FIN_WAIT_2;
    }
    break;
  case FIN_WAIT_2:
    tcp_receive(pcb);
    if (recv_flags & TF_GOT_FIN)
    {
      tcp_ack_now(pcb);
      tcp_pcb_purge(pcb);
      TCP_RMV_ACTIVE(pcb);
      pcb->state = TIME_WAIT;
      TCP_REG(&tcp_tw_pcbs, pcb);
    }
    break;
  case CLOSING:
    tcp_receive(pcb);
    if (flags & TCP_ACK && ackno == pcb->snd_nxt)
    {
      tcp_pcb_purge(pcb);
      TCP_RMV_ACTIVE(pcb);
      pcb->state = TIME_WAIT;
      TCP_REG(&tcp_tw_pcbs, pcb);
    }
    break;
  case LAST_ACK:
    tcp_receive(pcb);
    if (flags & TCP_ACK && ackno == pcb->snd_nxt)
    {recv_flags |= TF_CLOSED;}
    break;
  default:
    break;
  }
  return ERR_OK;
}


static void tcp_receive(struct tcp_pcb *pcb)
{
  struct tcp_seg *next;
  struct tcp_seg *prev, *cseg;
  u32_t right_wnd_edge;
  if (flags & TCP_ACK)
  {
    right_wnd_edge = pcb->snd_wnd + pcb->snd_wl2;
    if (     TCP_SEQ_LT(pcb->snd_wl1, seqno) ||
            (pcb->snd_wl1 == seqno && TCP_SEQ_LT(pcb->snd_wl2, ackno)) ||
            (pcb->snd_wl2 == ackno && tcphdr->wnd > pcb->snd_wnd) )
    {
    /* keep track of the biggest window announced by the remote host to calculate the maximum segment size */
      pcb->snd_wnd = tcphdr->wnd;
      if (pcb->snd_wnd_max < tcphdr->wnd)
      { pcb->snd_wnd_max = tcphdr->wnd;}
      pcb->snd_wl1 = seqno;
      pcb->snd_wl2 = ackno;
    }
    if (TCP_SEQ_LEQ(ackno, pcb->lastack))
    {/*will be handled in time out if we send data and receive ack for last segment , if we receive a old duplicate ACK ignore it  */ }

     /*         *****************************sender waits for new ACK*****************************
     *                                       ________________________
     * We come here only when the ACK acknowledges new data.
     * "don't enter" if ackno come for a segment which was already ackked and removed from the list                         ackno < lastack +1
     * "don't enter" if ackno come for a sequence number which is greater than send next which is impossible                ackno > snd_nxt
     * we enter only here when we have already sent data and just now we received the ACK for this data or many data segment after this segment
     *
     */
    else if (TCP_SEQ_BETWEEN(ackno, pcb->lastack+1, pcb->snd_nxt))
    {
      pcb->nrtx = 0;                           /* Reset the number of retransmissions. */
      pcb->rto = 3;                            /* Reset the retransmission time-out. */
      pcb->lastack = ackno;
      /* Remove segment from the unacknowledged list if the incoming ACK acknowledges them.
       * the (pcb->unacked->tcphdr->seqno  + its length ) must be <= ackno
      */
      while (pcb->unacked != NULL &&  TCP_SEQ_LEQ( (pcb->unacked->tcphdr->seqno) +TCP_TCPLEN(pcb->unacked), ackno))
      {
        next = pcb->unacked;
        pcb->unacked = pcb->unacked->next;
        pcb->snd_queuelen =  pcb->snd_queuelen -1 ;
        tcp_seg_free(next);
      }
      /* If there's nothing left to acknowledge, stop the retransmit timer, otherwise reset it to start again */
      if(pcb->unacked == NULL)
        {pcb->rtime = -1;}
      else
        {pcb->rtime = 0;}
      /* End of ACK for new data processing. */
    }
  }
  /*         *****************************a receiver receive data or a sender receive data with the ACK *****************************
   *                                      _______________________     __________________________________
   * ONLY If the incoming segment contains data , we must process it further unless the pcb already received a FIN.
   * (RFC 793, chapter 3.9, "SEGMENT ARRIVES" in states CLOSE-WAIT, CLOSING, LAST-ACK and TIME-WAIT: "Ignore the segment text.")
  */
  /* This code basically does three things:

    +) If the incoming segment contains data that is the next
    in-sequence data, this data is passed to the application. This
    might involve trimming the first edge of the data.
    The rcv_nxt variable and the advertised window are adjusted.

    +) If the incoming segment has data that is above the next
    sequence number expected (->rcv_nxt), the segment is placed on
    the ->ooseq queue. This is done by finding the appropriate
    place in the ->ooseq queue (which is ordered by sequence
    number) and trim the segment in both ends if needed. An
    immediate ACK is sent to indicate that we received an
    out-of-sequence segment.

    +) Finally, we check if the first segment on the ->ooseq queue
    now is in sequence (i.e., if rcv_nxt >= ooseq->seqno). If
    rcv_nxt > ooseq->seqno, we must trim the first edge of the
    segment on ->ooseq before we adjust rcv_nxt. The data in the
    segments that are now on sequence are chained onto the
    incoming segment so that we only need to call the application
    once.
    */

  if ((tcplen > 0) && (pcb->state < CLOSE_WAIT))
  {
   /* the sequence < rcv_nxt , must be a duplicate of a packet that has already been correctly handled */
   if (TCP_SEQ_LT(seqno, pcb->rcv_nxt))
   { tcp_ack_now(pcb);}
   if (TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt,  pcb->rcv_nxt + pcb->rcv_wnd - 1))
   {
      if (pcb->rcv_nxt == seqno)        /* in sequence segment*/
      {
        tcplen = TCP_TCPLEN(&inseg);   /* length of data only without header +1 if syn or fin */
        pcb->rcv_nxt = seqno + tcplen;      /*  advance the recv-next by the data length */
        pcb->rcv_wnd -= tcplen;             /*  remove from the receiver window available the lengh of incoming segment */
        if (inseg.p->tot_len > 0)
        {
            /* Since this pbuf now is the responsibility of the application, we delete our reference to it so that we won't (mistakingly) deallocate it. */
            recv_data = inseg.p;
            inseg.p = NULL;
        }
        /* If the segment was a FIN, we set the TF_GOT_FIN flag that will
         be used to indicate to the application that the remote side has
         closed its end of the connection.
         */
        if (TCPH_FLAGS(inseg.tcphdr) & TCP_FIN)
        {recv_flags |= TF_GOT_FIN;}

        if (pcb->ooseq != NULL)
        {
          if (TCPH_FLAGS(inseg.tcphdr) & TCP_FIN)
          {
            /* Received in-order FIN means anything that was received
             * out of order must now have been received in-order,
             * so bin the ooseq queue
            */
            while (pcb->ooseq != NULL)
            {
              struct tcp_seg *old_ooseq = pcb->ooseq;
              pcb->ooseq = pcb->ooseq->next;
              tcp_seg_free(old_ooseq);
            }
          }
        /* We now check if we have segments on the ->ooseq queue that are now in sequence. */
         while ( pcb->ooseq != NULL && pcb->ooseq->tcphdr->seqno == pcb->rcv_nxt)
         {
          cseg = pcb->ooseq;
          seqno = pcb->ooseq->tcphdr->seqno;
          pcb->rcv_nxt += TCP_TCPLEN(cseg);
          pcb->rcv_wnd -= TCP_TCPLEN(cseg);
          if (cseg->p->tot_len > 0)
           {
            /* Chain this pbuf onto the pbuf that we will pass to the application. */
            if (recv_data)
            {pbuf_cat(recv_data, cseg->p);}
            else
            { recv_data = cseg->p;}
            cseg->p = NULL;
           }
          if (TCPH_FLAGS(cseg->tcphdr) & TCP_FIN)
           {
            recv_flags |= TF_GOT_FIN;
            if (pcb->state == ESTABLISHED)
            {  pcb->state = CLOSE_WAIT; }    /* force passive close or we can move to active close */
           }
          pcb->ooseq = cseg->next;
          tcp_seg_free(cseg);
         }
        }
        tcp_ack(pcb);                /* Acknowledge the segment(s). */
      }
      else /* We get here if the incoming segment is out-of-sequence. */
      {
        tcp_send_empty_ack(pcb);
        /* We queue the segment on the ->ooseq queue. */
        if (pcb->ooseq == NULL)
        {pcb->ooseq = tcp_seg_copy(&inseg);}
        else
        {
        /* If the queue is not empty, we walk through the queue and
           try to find a place where the sequence number of the
           incoming segment is between the sequence numbers of the
           previous and the next segment on the ->ooseq queue. That is
           the place where we put the incoming segment. If needed, we
           trim the second edges of the previous and the incoming
           segment so that it will fit into the sequence.

           If the incoming segment has the same sequence number as a
           segment on the ->ooseq queue, we discard the segment that
           contains less data.
        */
           prev = NULL;
           for(next = pcb->ooseq; next != NULL; next = next->next)
            {
                if (prev == NULL)
                {
                 if (TCP_SEQ_LT(seqno, next->tcphdr->seqno))
                  {
                    /* The sequence number of the incoming segment is lower
                       than the sequence number of the first segment on the
                       queue. We put the incoming segment first on the queue.
                    */
                    cseg = tcp_seg_copy(&inseg);
                    if (cseg != NULL)
                     {
                        pcb->ooseq = cseg;
                        cseg->next = next;
                     }
                    break;
                  }
                }
                else
                {
                    if (TCP_SEQ_BETWEEN(seqno, prev->tcphdr->seqno+1, next->tcphdr->seqno-1))
                     {
                        /* The sequence number of the incoming segment is in
                           between the sequence numbers of the previous and
                           the next segment on ->ooseq.
                        */
                        cseg = tcp_seg_copy(&inseg);
                        if (cseg != NULL)
                        {
                          prev->next = cseg;
                          cseg->next = next;
                        }
                        break;
                      }
                }
                /* If the "next" segment is the last segment on the
                ooseq queue, we add the incoming segment to the end
                of the list.
                */
                if (next->next == NULL && TCP_SEQ_GT(seqno, next->tcphdr->seqno))
                 {
                    if (TCPH_FLAGS(next->tcphdr) & TCP_FIN)
                     { break;  /* segment "next" already contains all data */}
                    next->next = tcp_seg_copy(&inseg);
                    break;
                 }
                prev = next;
            }
        }
      }
    }
    else
    {tcp_send_empty_ack(pcb);}
  }
  else
  {
    if(last_state == SYN_RCVD)/*if you have received your waited ACK do not make any thing*/
    {last_state =  ESTABLISHED;}
    /* Segments with length 0 is taken care of here. */
    if(  !  TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd-1))
    { tcp_ack_now(pcb);}
  }
}




