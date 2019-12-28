

#ifndef __LWIP_PBUF_H__
#define __LWIP_PBUF_H__

#include "lwip/opt.h"
#include "lwip/err.h"

#define PBUF_TRANSPORT_HLEN 20
#define PBUF_IP_HLEN        20

typedef enum {
  PBUF_TRANSPORT,
  PBUF_udp,
  PBUF_IP,
  PBUF_LINK,
  PBUF_RAW
} pbuf_layer;


struct pbuf
{
  /** next pbuf in singly linked pbuf chain */
  struct pbuf *next;
  /** pointer to the actual data in the buffer */
  void *payload;
  /**
   * total length of this buffer and all next buffers in chain
   * belonging to the same packet.
   *
   * For non-queue packet chains this is the invariant:
   * p->tot_len == p->len + (p->next? p->next->tot_len: 0)
   */
  u16_t tot_len;
  /** length of this buffer */
  u16_t len;
  /** misc flags */
  u8_t flags;
  /**
   * the reference count always equals the number of pointers
   * that refer to this pbuf. This can be pointers from an application,
   * the stack itself, or pbuf->next pointers from a chain.
   */
  u16_t ref;
};

struct pbuf *pbuf_alloc(pbuf_layer l, u16_t length);
u8_t pbuf_header(struct pbuf *p, s16_t header_size);
void pbuf_ref(struct pbuf *p);
u8_t pbuf_free(struct pbuf *p);
void  pbuf_cat(struct pbuf *head, struct pbuf *tail);




#endif /* __LWIP_PBUF_H__ */
