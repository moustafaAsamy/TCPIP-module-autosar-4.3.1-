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

//extern struct tcp_pcb * TCP_list[5];
extern void UARTprintf(const char *pcString, ...);
/* These variables are global to all functions involved in the input
   processing of TCP segments. They are set by the tcp_input()
   function. */
static struct tcp_seg inseg;
struct tcp_seg seg_arry[30]={0};
static struct tcp_hdr *tcphdr;
static struct ip_hdr *iphdr;
static u32_t seqno, ackno;
static u8_t flags;
static u16_t tcplen;
static u8_t last_state;
static u8_t recv_flags;
static struct pbuf *recv_data;
struct tcp_pcb *tcp_input_pcb;

static void tcp_oos_insert_segment(struct tcp_seg *cseg, struct tcp_seg *next);
static err_t tcp_process(struct tcp_pcb *pcb);
static void tcp_receive(struct tcp_pcb *pcb);
static err_t tcp_listen_input(struct tcp_pcb *pcb);
static err_t tcp_timewait_input(struct tcp_pcb *pcb);
extern tcp_fast_rexmit(struct tcp_pcb *pcb  );
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
  if(pbuf_header(p, -(hdrlen * 4)))                                /* Move the payload pointer in the pbuf so that it points to the TCP data instead of the TCP header. */
  { goto dropped;}
  /* Convert fields in TCP header to host byte order. */
  tcphdr->src = (tcphdr->src);
  tcphdr->dest = (tcphdr->dest);
  seqno = tcphdr->seqno = (tcphdr->seqno);
  ackno = tcphdr->ackno = (tcphdr->ackno);
  tcphdr->wnd = (tcphdr->wnd);
  flags = TCPH_FLAGS(tcphdr);
  tcplen = p->tot_len + ((flags & (TCP_FIN | TCP_SYN)) ? 1 : 0);        //data length only , if it is fin or syn add a byte
  UARTprintf("Received :>  ackno =  %d   ,  seqno =  %d  ,   len =   %d \n",tcphdr->ackno , tcphdr->seqno , tcplen );
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
        if (pcb->flags & TF_RXCLOSED) {
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
      }
    }
    /* Jump target if pcb has been aborted in a callback (by calling tcp_abort()).
       Below this line, 'pcb' may not be dereferenced! */
aborted:
    tcp_input_pcb = NULL;
    recv_data = NULL;
    /* give up our reference to inseg.p */
    if (inseg.p != NULL) /*&& (pcb->ooseq == NULL) )*/
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
  if ((pcb->flags & TF_RXCLOSED) == 0) /* Update the PCB (in)activity timer unless rx is closed (see tcp_shutdown) */  /////mohmmmmmmmmmmmmmmm
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
       (pcb)->flags &= ~TF_ACK_NOW;
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
    //dont do any thing if you recve old ack , till time out
     struct tcp_seg *next;
   #if TCP_QUEUE_OOSEQ
     struct tcp_seg *prev, *cseg;
   #endif /* TCP_QUEUE_OOSEQ */
     struct pbuf *p;
     s32_t off;
     s16_t m;
     u32_t right_wnd_edge;
     u16_t new_tot_len;
     int found_dupack = 0;
   #if TCP_OOSEQ_MAX_BYTES || TCP_OOSEQ_MAX_PBUFS
     u32_t ooseq_blen;
     u16_t ooseq_qlen;
   #endif /* TCP_OOSEQ_MAX_BYTES || TCP_OOSEQ_MAX_PBUFS */

     if (flags & TCP_ACK) {
       right_wnd_edge = pcb->snd_wnd + pcb->snd_wl2;

       /* Update window. */  //   First reception  after send for the sender will be true                 last seqno == seqno             is ackno < ackno       or   (last ackno == ackno )
       if (     TCP_SEQ_LT(pcb->snd_wl1, seqno) ||             (   pcb->snd_wl1 ==   seqno   &&     TCP_SEQ_LT(pcb->snd_wl2, ackno))  ||  (pcb->snd_wl2 == ackno && tcphdr->wnd > pcb->snd_wnd)     )
          {
           //when you receive an  ack from the receiver for your data +new data              TCP_SEQ_LT(pcb->snd_wl1, seqno) true
           //when you receive an only ack from the receiver for your data                     pcb->snd_wl1 ==   seqno         true       ack for fin
         pcb->snd_wnd = tcphdr->wnd;
         /* keep track of the biggest window announced by the remote host to calculate
            the maximum segment size */
         if (pcb->snd_wnd_max < tcphdr->wnd) {
           pcb->snd_wnd_max = tcphdr->wnd;
         }
         pcb->snd_wl1 = seqno;
         pcb->snd_wl2 = ackno;
          }
       /* (From Stevens TCP/IP Illustrated Vol II, p970.) Its only a
        * duplicate ack if:
        * 1) It doesn't ACK new data
        * 2) length of received packet is zero (i.e. no payload)
        * 3) the advertised window hasn't changed
        * 4) There is outstanding unacknowledged data (retransmission timer running)
        * 5) The ACK is == biggest ACK sequence number so far seen (snd_una)
        *
        * If it passes all five, should process as a dupack:
        * a) dupacks < 3: do nothing
        * b) dupacks == 3: fast retransmit
        * c) dupacks > 3: increase cwnd
        *
        * If it only passes 1-3, should reset dupack counter (and add to
        * stats, which we don't do in lwIP)
        *
        * If it only passes 1, should reset dupack counter
        *
        */

       /* Clause 1 */     /// if ackno == lastackno , it could be that this tcb IS RECIVER ONLY and doesnot send data , each time it recive data segment it recive its same ackon no. as threr n recive window advane
       // if ackno < lastackno , there is a potintional
       if (TCP_SEQ_LEQ(ackno, pcb->lastack)) {
         pcb->acked = 0;
         /* Clause 2 */
         if (tcplen == 0) {
           /* Clause 3 */
           if (pcb->snd_wl2 + pcb->snd_wnd == right_wnd_edge){
             /* Clause 4 */
             if (pcb->rtime >= 0) {
               /* Clause 5 */
               if (pcb->lastack == ackno) {
                   tcp_fast_rexmit(pcb ); // very important
               }
             }
           }
         }

         /* If Clause (1) or more is true, but not a duplicate ack, reset
          * count of consecutive duplicate acks */
         if (!found_dupack) {
           pcb->dupacks = 0;
         }

           ///We come here when the ACK acknowledges new data                     y3nay enta kont b3t we delkaty getlk ack   mohmmmm   |syn_rec|
       } else if (TCP_SEQ_BETWEEN(ackno, pcb->lastack+1, pcb->snd_nxt))         //  will enter also if out of sequence                  |*******|
       {
         /* We come here when the ACK acknowledges new data. */

         /* Reset the "IN Fast Retransmit" flag, since we are no longer
            in fast retransmit. Also reset the congestion window to the
            slow start threshold. */
         if (pcb->flags & TF_INFR) {
           pcb->flags &= ~TF_INFR;
           pcb->cwnd = pcb->ssthresh;
         }

         /* Reset the number of retransmissions. */
         pcb->nrtx = 0;

         /* Reset the retransmission time-out. */
         pcb->rto = (pcb->sa >> 3) + pcb->sv;

         /* Update the send buffer space. Diff between the two can never exceed 64K? */
         pcb->acked = (u16_t)(ackno - pcb->lastack);

         pcb->snd_buf += pcb->acked;

         /* Reset the fast retransmit variables. */
         pcb->dupacks = 0;
         pcb->lastack = ackno;

         /* Remove segment from the unacknowledged list if the incoming ACK acknowlegdes them. */
          // i will not enter here if i am reciving data && i am not waiting for ack
                                                                           // seg)->seq= 600    +       //  seg)->len=500      <=     ackno=1600     // if out of seunce send you a old ack do not enter
                                                                          // seg)->seq= 1100    +       //  seg)->len=500      <=     ackno=1600     // if out of seunce send you a old ack do not enter

         while (pcb->unacked != NULL &&  TCP_SEQ_LEQ(      (pcb->unacked->tcphdr->seqno) +TCP_TCPLEN(pcb->unacked)     ,       ackno)) // last-segment which was unacked ( seqno  +"data =0" +1  -   ackno=iss+1 <0  )in case of syn_rec ok
         {

           next = pcb->unacked;
           pcb->unacked = pcb->unacked->next;



           /* Prevent ACK for FIN to generate a sent event */
           if ((pcb->acked != 0) && ((TCPH_FLAGS(next->tcphdr) & TCP_FIN) != 0)) {
             pcb->acked--;
           }

           pcb->snd_queuelen = pcb->snd_queuelen -1;
           tcp_seg_free(next);

            if (pcb->snd_queuelen != 0) {

           }
         }

         /* If there's nothing left to acknowledge, stop the retransmit
            timer, otherwise reset it to start again */
         if(pcb->unacked == NULL)
           pcb->rtime = -1;         // stop
         else
           pcb->rtime = 0;         //restart it increment y one each 500 ms

         pcb->polltmr = 0;
       }
       else {
         /* Fix bug bug #21582: out of sequence ACK, didn't really ack anything */
         pcb->acked = 0;
       }
     }
     /* If the incoming segment contains data, we must process it
        further unless the pcb already received a FIN.
        (RFC 793, chapeter 3.9, "SEGMENT ARRIVES" in states CLOSE-WAIT, CLOSING, LAST-ACK and TIME-WAIT: "Ignore the segment text.") */

     if ((tcplen > 0) && (pcb->state < CLOSE_WAIT)) {
       /* This code basically does three things:

       +) If the incoming segment contains data that is the next
       in-sequence data, this data is passed to the application. This
       might involve trimming the first edge of the data.
       The rcv_nxt variable and the advertised window are adjusted.   <<  mmhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhmm

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

       /* First, we check if we must trim the first edge. We have to do
          this if the sequence number of the incoming segment is less
          than rcv_nxt, and the sequence number plus the length of the
          segment is larger than rcv_nxt. */
       /*    if (TCP_SEQ_LT(seqno, pcb->rcv_nxt)){
             if (TCP_SEQ_LT(pcb->rcv_nxt, seqno + tcplen)) {*/

             //  if  sequence number < rcv_nxt
       if (TCP_SEQ_BETWEEN(pcb->rcv_nxt, seqno + 1, seqno + tcplen - 1))  // check that the segment lies
       {
       }
      else {
         if (TCP_SEQ_LT(seqno, pcb->rcv_nxt))        //if the sequnce no.in the incoming segement is less than the recvive_next then it must be a duplicate o send late once more
         {
           /* the whole segment is < rcv_nxt */
           /* must be a duplicate of a packet that has already been correctly handled */
           tcp_ack_now(pcb);
         }
       }
   /****<><>                       <><golden rule       <><>  rcv_nxt    <= seqno <  rcv_nxt + rcv_wnd - 1   <>
       /* The sequence number must be within the window (above rcv_nxt and below rcv_nxt + rcv_wnd) in order to be further processed. */
       if (TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt,  pcb->rcv_nxt + pcb->rcv_wnd - 1))
           {
         if (pcb->rcv_nxt == seqno)
         {
           /* The incoming segment is the next in sequence. We check if
              we have to trim the end of the segment and update rcv_nxt
              and pass the data to the application. */
           tcplen = TCP_TCPLEN(&inseg); // length of data only without header

   #if TCP_QUEUE_OOSEQ
           /* Received in-sequence data, adjust ooseq data if:
              - FIN has been received or
              - inseq overlaps with ooseq */
           if (pcb->ooseq != NULL) {
             if (TCPH_FLAGS(inseg.tcphdr) & TCP_FIN) {
                /* Received in-order FIN means anything that was received
                * out of order must now have been received in-order, so
                * bin the ooseq queue */
               while (pcb->ooseq != NULL) {
                 struct tcp_seg *old_ooseq = pcb->ooseq;
                 pcb->ooseq = pcb->ooseq->next;
                 tcp_seg_free(old_ooseq);
               }
             } else {
               next = pcb->ooseq;
               /* Remove all segments on ooseq that are covered by inseg already.
                * FIN is copied from ooseq to inseg if present. */
               while (next &&  TCP_SEQ_GEQ(seqno + tcplen, next->tcphdr->seqno + next->len)) // 600,1100 . 600+1500
               {
                 /* inseg cannot have FIN here (already processed above) */
                 if (TCPH_FLAGS(next->tcphdr) & TCP_FIN &&
                     (TCPH_FLAGS(inseg.tcphdr) & TCP_SYN) == 0) {
                   TCPH_SET_FLAG(inseg.tcphdr, TCP_FIN);
                   tcplen = TCP_TCPLEN(&inseg);
                 }
                 prev = next;
                 next = next->next;
                 tcp_seg_free(prev);
               }
               /* Now trim right side of inseg if it overlaps with the first
                * segment on ooseq */
               if (next &&
                   TCP_SEQ_GT(seqno + tcplen, next->tcphdr->seqno))
               {
                 /* inseg cannot have FIN here (already processed above) */
                 inseg.len = (u16_t)(next->tcphdr->seqno - seqno);
                 if (TCPH_FLAGS(inseg.tcphdr) & TCP_SYN) {
                   inseg.len -= 1;
                 }
                 //pbuf_realloc(inseg.p, inseg.len);
                 tcplen = TCP_TCPLEN(&inseg);

               }
               pcb->ooseq = next;
             }
           }
   #endif /* TCP_QUEUE_OOSEQ */

           pcb->rcv_nxt = seqno + tcplen;      // advance the recv-next by the data length
           /* Update the receiver's (our) window. */
            pcb->rcv_wnd -= tcplen;        //  remove from the receiver window available the length of incoming segment

           /* If there is data in the segment, we make preparations to
              pass this up to the application. The ->recv_data variable
              is used for holding the pbuf that goes to the
              application. The code for reassembling out-of-sequence data
              chains its data on this pbuf as well.

              If the segment was a FIN, we set the TF_GOT_FIN flag that will
              be used to indicate to the application that the remote side has
              closed its end of the connection. */
           if (inseg.p->tot_len > 0) {
             recv_data = inseg.p;                                         // save the data to be used  by application
             /* Since this pbuf now is the responsibility of the
                application, we delete our reference to it so that we won't
                (mistakingly) deallocate it. */
             inseg.p = NULL;                  /// good embeded c mannnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn
           }
           if (TCPH_FLAGS(inseg.tcphdr) & TCP_FIN) {
              recv_flags |= TF_GOT_FIN;
           }

   #if TCP_QUEUE_OOSEQ
           /* We now check if we have segments on the ->ooseq queue that
              are now in sequence. */
           while (pcb->ooseq != NULL && pcb->ooseq->tcphdr->seqno == pcb->rcv_nxt) /////////////////mohm fash555555555555555555555555
           {
             cseg = pcb->ooseq;
             seqno = pcb->ooseq->tcphdr->seqno;////if this is the real nxt segment which we have received it but not in order , seqno = pcb->ooseq->tcphdr->seqno =1100

             pcb->rcv_nxt += TCP_TCPLEN(cseg); // seg > len of this next
                pcb->rcv_wnd -= TCP_TCPLEN(cseg);

             tcp_update_rcv_ann_wnd(pcb);

             if (cseg->p->tot_len > 0) {
               /* Chain this pbuf onto the pbuf that we will pass to
                  the application. */
               if (recv_data) {
                 pbuf_cat(recv_data, cseg->p);     // concat the new data to the old
               } else {
                 recv_data = cseg->p;
               }
               cseg->p = NULL;
             }
             if (TCPH_FLAGS(cseg->tcphdr) & TCP_FIN) {
                recv_flags |= TF_GOT_FIN;
               if (pcb->state == ESTABLISHED) { /* force passive close or we can move to active close */
                 pcb->state = CLOSE_WAIT;
               }
             }

             pcb->ooseq = cseg->next;
             tcp_seg_free(cseg);
           }
   #endif /* TCP_QUEUE_OOSEQ */
           /* Acknowledge the segment(s). */
           tcp_ack(pcb);
         }
       else                       /// out of segment
         {
           /* We get here if the incoming segment is out-of-sequence. */
           tcp_send_empty_ack(pcb);  // could be busy or delayed in the network but it will be arrive after soon ,send ack with next expected seqno_
   #if TCP_QUEUE_OOSEQ
           /* We queue the segment on the ->ooseq queue. */
           if (pcb->ooseq == NULL)
           {
             pcb->ooseq = tcp_seg_copy(&inseg);
           }
           else
           {

               //skip
             /* If the queue is not empty, we walk through the queue and
                try to find a place where the sequence number of the
                incoming segment is between the sequence numbers of the
                previous and the next segment on the ->ooseq queue.
                That is the place where we put the incoming segment. If needed, we
                trim the second edges of the previous and the incoming
                segment so that it will fit into the sequence.


                If the incoming segment has the same sequence number as a
                segment on the ->ooseq queue, we discard the segment that
                contains less data. */

             prev = NULL;
             for(next = pcb->ooseq; next != NULL; next = next->next)
             {
               if (seqno == next->tcphdr->seqno)
               {
                 /* The sequence number of the incoming segment is the same as the sequence number of the segment on  ->ooseq.
                  * We check the lengths to see which one to discard. */

                 if (inseg.len > next->len)
                 {
                   /* The incoming segment is larger than the old
                      segment. We replace some segments with the new
                      one. */
                   cseg = tcp_seg_copy(&inseg);
                   if (cseg != NULL)
                   {
                     if (prev != NULL)
                     {
                       prev->next = cseg;
                     }
                     else
                     {
                       pcb->ooseq = cseg;
                     }
                     tcp_oos_insert_segment(cseg, next);//copy , next is element of now
                   }
                   break;
                 } else {
                   /* Either the lenghts are the same or the incoming
                      segment was smaller than the old one; in either
                      case, we ditch the incoming segment. */
                   break;
                 }
               }
              else {
                 if (prev == NULL) {
                   if (TCP_SEQ_LT(seqno, next->tcphdr->seqno))
                   {
                     /* The sequence number of the incoming segment is lower
                        than the sequence number of the first segment on the
                        queue. We put the incoming segment first on the
                        queue. */
                     cseg = tcp_seg_copy(&inseg);
                     if (cseg != NULL) {
                       pcb->ooseq = cseg;
                       tcp_oos_insert_segment(cseg, next);
                     }
                     break;
                   }
                 }
                 else {
                   /*if (TCP_SEQ_LT(prev->tcphdr->seqno, seqno) &&
                     TCP_SEQ_LT(seqno, next->tcphdr->seqno)) {*/
                   if (TCP_SEQ_BETWEEN(seqno, prev->tcphdr->seqno+1, next->tcphdr->seqno-1)) {
                     /* The sequence number of the incoming segment is in
                        between the sequence numbers of the previous and
                        the next segment on ->ooseq. We trim trim the previous
                        segment, delete next segments that included in received segment
                        and trim received, if needed. */
                     cseg = tcp_seg_copy(&inseg);
                     if (cseg != NULL) {
                       if (TCP_SEQ_GT(prev->tcphdr->seqno + prev->len, seqno)) {
                         /* We need to trim the prev segment. */
                         prev->len = (u16_t)(seqno - prev->tcphdr->seqno);
                         //pbuf_realloc(prev->p, prev->len);
                       }
                       prev->next = cseg;
                       tcp_oos_insert_segment(cseg, next);
                     }
                     break;
                   }
                 }
                 /* If the "next" segment is the last segment on the
                    ooseq queue, we add the incoming segment to the end
                    of the list. */
                 if (next->next == NULL &&
                     TCP_SEQ_GT(seqno, next->tcphdr->seqno)) {
                   if (TCPH_FLAGS(next->tcphdr) & TCP_FIN) {
                     /* segment "next" already contains all data */
                     break;
                   }
                   next->next = tcp_seg_copy(&inseg);
                   if (next->next != NULL) {
                     if (TCP_SEQ_GT(next->tcphdr->seqno + next->len, seqno)) {
                       /* We need to trim the last segment. */
                       next->len = (u16_t)(seqno - next->tcphdr->seqno);
                       //pbuf_realloc(next->p, next->len);
                     }
                     /* check if the remote side overruns our receive window */
                     if ((u32_t)tcplen + seqno > pcb->rcv_nxt + (u32_t)pcb->rcv_wnd) {
                        if (TCPH_FLAGS(next->next->tcphdr) & TCP_FIN) {
                         /* Must remove the FIN from the header as we're trimming
                          * that byte of sequence-space from the packet */
                         TCPH_FLAGS_SET(next->next->tcphdr, TCPH_FLAGS(next->next->tcphdr) &~ TCP_FIN);
                       }
                       /* Adjust length of segment to fit in the window. */
                       next->next->len = pcb->rcv_nxt + pcb->rcv_wnd - seqno;
                       //pbuf_realloc(next->next->p, next->next->len);
                       tcplen = TCP_TCPLEN(next->next);

                     }
                   }
                   break;
                 }
               }
               prev = next;
             }
             prev->next = tcp_seg_copy(&inseg);
           }
   #if TCP_OOSEQ_MAX_BYTES || TCP_OOSEQ_MAX_PBUFS
           /* Check that the data on ooseq doesn't exceed one of the limits
              and throw away everything above that limit. */
           ooseq_blen = 0;
           ooseq_qlen = 0;
           prev = NULL;
           for(next = pcb->ooseq; next != NULL; prev = next, next = next->next) {
             struct pbuf *p = next->p;
             ooseq_blen += p->tot_len;
             ooseq_qlen += pbuf_clen(p);
             if ((ooseq_blen > TCP_OOSEQ_MAX_BYTES) ||
                 (ooseq_qlen > TCP_OOSEQ_MAX_PBUFS)) {
                /* too much ooseq data, dump this and everything after it */
                tcp_segs_free(next);
                if (prev == NULL) {
                  /* first ooseq segment is too much, dump the whole queue */
                  pcb->ooseq = NULL;
                } else {
                  /* just dump 'next' and everything after it */
                  prev->next = NULL;
                }
                break;
             }
           }
   #endif /* TCP_OOSEQ_MAX_BYTES || TCP_OOSEQ_MAX_PBUFS */
   #endif /* TCP_QUEUE_OOSEQ */
         }
       }//end of golden rule      ///
       else {
         /* The incoming segment is not withing the window. */
         tcp_send_empty_ack(pcb);
       }
     } else {
          if(last_state == "SYN_RCVD")
          {
              last_state =  ESTABLISHED;
          }
       /* Segments with length 0 is taken care of here. Segments that
          fall out of the window are ACKed. */
       /*if (TCP_SEQ_GT(pcb->rcv_nxt, seqno) ||
         TCP_SEQ_GEQ(seqno, pcb->rcv_nxt + pcb->rcv_wnd)) {*/        // seqno == lastack  , if iam a sender and  has just recived ack for the
       if(  !  TCP_SEQ_BETWEEN(seqno, pcb->rcv_nxt, pcb->rcv_nxt + pcb->rcv_wnd-1))
       {
         tcp_ack_now(pcb);
       }
     }
}



/**
 * Insert segment into the list (segments covered with new one will be deleted)
 *
 * Called from tcp_receive()
 */
static void tcp_oos_insert_segment(struct tcp_seg *cseg, struct tcp_seg *next)
{
  struct tcp_seg *old_seg;

  if (TCPH_FLAGS(cseg->tcphdr) & TCP_FIN) {
    /* received segment overlaps all following segments */
    tcp_segs_free(next);
    next = NULL;
  }
  else {
    /* delete some following segments
       oos queue may have segments with FIN flag */
    while (next &&
           TCP_SEQ_GEQ((seqno + cseg->len),
                      (next->tcphdr->seqno + next->len))) {
      /* cseg with FIN already processed */
      if (TCPH_FLAGS(next->tcphdr) & TCP_FIN) {
        TCPH_SET_FLAG(cseg->tcphdr, TCP_FIN);
      }
      old_seg = next;
      next = next->next;
      tcp_seg_free(old_seg);
    }
  }
  cseg->next = next;
}
