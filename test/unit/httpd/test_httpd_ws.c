#include "test_httpd_ws.h"

#include "lwip/apps/httpd.h"
#include "lwip/apps/httpd_ws.h"
#include "lwip/apps/httpd_ws_priv.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/stats.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "../tcp/tcp_helper.h"

#include <string.h>
#include <stdio.h>

#if !LWIP_HTTPD_SUPPORT_WEBSOCKET
#error "This test needs LWIP_HTTPD_SUPPORT_WEBSOCKET"
#endif

/* The tests act as a WebSocket client: they inject TCP segments into the
 * stack (tcp_helper), collect everything httpd sends on the test netif and
 * acknowledge it. Some tests feed crafted pbuf chains directly to the recv
 * callback of the server pcb to control pbuf boundaries. */

#define WS_TEST_PORT_BASE 0x4000
#define WS_RX_MAX         20000
#define WS_MSG_MAX        5000

static struct netif ws_netif;
static struct test_tcp_txcounters ws_txc;
static struct netif *old_netif_list;
static struct netif *old_netif_default;

/* client side of one connection */
struct ws_client {
  u16_t port;
  u32_t cli_seq;   /* next sequence number we send */
  u32_t srv_seq;   /* next sequence number expected from the server */
  u8_t got_fin;
  u8_t got_rst;
  u8_t rx[WS_RX_MAX];
  u32_t rx_len;    /* bytes received from the server */
  u32_t rx_pos;    /* bytes parsed by the test */
  u8_t no_ack;     /* do not acknowledge received data */
};

static struct ws_client cl1, cl2, cl3;
static u16_t next_port;

/* what the handlers saw */
static struct {
  int opens;
  int msgs;
  int closes;
  int pings;
  int pongs;
  int sent_calls;
  u32_t sent_bytes;
  u16_t close_code;
  char close_reason[126];
  u16_t msg_len;
  u8_t msg_opcode;
  u8_t msg[WS_MSG_MAX];
  u8_t msg_was_chain;
  u8_t echo;
  struct altcp_pcb *last_pcb;
  httpd_ws_auth_result_t auth_result;
} ev;

/*---------------------------------------------------------------------------*/
/* handlers */

static void
h_open(const httpd_ws_req_t *req)
{
  ev.opens++;
  ev.last_pcb = req->pcb;
}

static void
h_msg(struct altcp_pcb *pcb, void *ctx, const u8_t *data, u16_t len, u8_t opcode)
{
  LWIP_UNUSED_ARG(ctx);
  ev.msgs++;
  ev.msg_len = len;
  ev.msg_opcode = opcode;
  ev.msg_was_chain = 0;
  if (len <= WS_MSG_MAX) {
    memcpy(ev.msg, data, len);
  }
  if (ev.echo) {
    httpd_ws_write(pcb, data, len, opcode);
  }
}

static void
h_msg_pbuf(struct altcp_pcb *pcb, void *ctx, struct pbuf *p, u16_t len, u8_t opcode)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(ctx);
  ev.msgs++;
  ev.msg_len = len;
  ev.msg_opcode = opcode;
  ev.msg_was_chain = (u8_t)(p->next != NULL);
  fail_unless(p->tot_len == len);
  if (len <= WS_MSG_MAX) {
    pbuf_copy_partial(p, ev.msg, len, 0);
  }
}

static void
h_close(struct altcp_pcb *pcb, void *ctx, u16_t code, const u8_t *reason, u16_t reason_len)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(ctx);
  ev.closes++;
  ev.close_code = code;
  memset(ev.close_reason, 0, sizeof(ev.close_reason));
  if ((reason != NULL) && (reason_len < sizeof(ev.close_reason))) {
    memcpy(ev.close_reason, reason, reason_len);
  }
}

static void
h_ping(struct altcp_pcb *pcb, void *ctx, const u8_t *payload, u16_t len)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(ctx);
  LWIP_UNUSED_ARG(payload);
  LWIP_UNUSED_ARG(len);
  ev.pings++;
}

static void
h_pong(struct altcp_pcb *pcb, void *ctx, const u8_t *payload, u16_t len)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(ctx);
  LWIP_UNUSED_ARG(payload);
  LWIP_UNUSED_ARG(len);
  ev.pongs++;
}

static httpd_ws_auth_result_t
h_auth(const httpd_ws_req_t *req)
{
  LWIP_UNUSED_ARG(req);
  return ev.auth_result;
}

static void
h_sent(struct altcp_pcb *pcb, void *ctx, u16_t len)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(ctx);
  ev.sent_calls++;
  ev.sent_bytes += len;
}

static const httpd_ws_handler_t ws_handlers[] = {
  /* uri,      open,   msg,   msg_pbuf,   close,   ping,   pong,   auth,   ctx,  sent */
  { "/flat",   h_open, h_msg, NULL,       h_close, h_ping, h_pong, NULL,   NULL, h_sent },
  { "/chain",  h_open, NULL,  h_msg_pbuf, h_close, h_ping, h_pong, NULL,   NULL, h_sent },
  { "/nocb",   h_open, NULL,  NULL,       h_close, NULL,   NULL,   NULL,   NULL, NULL },
  { "/auth",   h_open, h_msg, NULL,       h_close, NULL,   NULL,   h_auth, NULL, NULL },
  { "/basic",  h_open, h_msg, NULL,       h_close, NULL,   NULL,   NULL,   NULL, NULL }
};

/*---------------------------------------------------------------------------*/
/* client helpers */

static void
cl_input(struct ws_client *c, const void *data, u16_t len, u8_t flags)
{
  ip_addr_t src = test_remote_ip;
  ip_addr_t dst = test_local_ip;
  static u8_t buf[1600];
  struct pbuf *p;
  LWIP_ASSERT("segment too long", len <= sizeof(buf));
  if (len > 0) {
    memcpy(buf, data, len);
  }
  p = tcp_create_segment(&src, &dst, c->port, HTTPD_SERVER_PORT, (len > 0) ? buf : NULL, len,
                         c->cli_seq, c->srv_seq, flags);
  fail_unless(p != NULL);
  if (p != NULL) {
    test_tcp_input(p, &ws_netif);
  }
  c->cli_seq += len;
  if (flags & (TCP_SYN | TCP_FIN)) {
    c->cli_seq++;
  }
}

static struct ws_client *
cl_by_port(u16_t port)
{
  if (cl1.port == port) {
    return &cl1;
  }
  if (cl2.port == port) {
    return &cl2;
  }
  if (cl3.port == port) {
    return &cl3;
  }
  return NULL;
}

/* parse everything the server sent, ack it; loop until quiet */
static void
ws_pump(void)
{
  int rounds;
  for (rounds = 0; rounds < 50; rounds++) {
    struct pbuf *pkts = ws_txc.tx_packets;
    struct pbuf *q;
    struct ws_client *to_ack[3];
    int n_ack = 0, i;
    if (pkts == NULL) {
      return;
    }
    ws_txc.tx_packets = NULL;
    for (q = pkts; q != NULL; q = q->next) {
      const u8_t *b = (const u8_t *)q->payload;
      u16_t iphl = (u16_t)((b[0] & 0x0F) * 4);
      const u8_t *t = b + iphl;
      u16_t tcphl = (u16_t)((t[12] >> 4) * 4);
      u16_t dport = (u16_t)((t[2] << 8) | t[3]);
      u32_t seq = ((u32_t)t[4] << 24) | ((u32_t)t[5] << 16) | ((u32_t)t[6] << 8) | t[7];
      u8_t flags = t[13];
      u16_t plen = (u16_t)(q->len - iphl - tcphl);
      struct ws_client *c = cl_by_port(dport);
      if (c == NULL) {
        continue;
      }
      if (flags & TCP_RST) {
        c->got_rst = 1;
        continue;
      }
      if (flags & TCP_SYN) {
        c->srv_seq = seq + 1;
        continue;
      }
      if ((seq == c->srv_seq) && (plen > 0)) {
        fail_unless(c->rx_len + plen <= WS_RX_MAX);
        memcpy(&c->rx[c->rx_len], t + tcphl, plen);
        c->rx_len += plen;
        c->srv_seq += plen;
      }
      if ((flags & TCP_FIN) && (seq + plen == c->srv_seq) && !c->got_fin) {
        c->got_fin = 1;
        c->srv_seq++;
      }
      if (!c->no_ack) {
        for (i = 0; i < n_ack; i++) {
          if (to_ack[i] == c) {
            break;
          }
        }
        if (i == n_ack) {
          to_ack[n_ack++] = c;
        }
      }
    }
    pbuf_free(pkts);
    for (i = 0; i < n_ack; i++) {
      cl_input(to_ack[i], NULL, 0, TCP_ACK);
    }
  }
}

static void
cl_connect(struct ws_client *c)
{
  memset(c, 0, sizeof(*c));
  c->port = next_port++;
  c->cli_seq = 0x1000;
  cl_input(c, NULL, 0, TCP_SYN);
  ws_pump(); /* SYN-ACK */
  fail_unless(c->srv_seq != 0);
  cl_input(c, NULL, 0, TCP_ACK);
  ws_pump();
}

static void
cl_send(struct ws_client *c, const void *data, u32_t len)
{
  const u8_t *d = (const u8_t *)data;
  while (len > 0) {
    u16_t n = (u16_t)((len > 1000) ? 1000 : len);
    cl_input(c, d, n, TCP_ACK | TCP_PSH);
    d += n;
    len -= n;
    ws_pump();
  }
}

static void
cl_send_segments(struct ws_client *c, const u8_t *data, u32_t len, u16_t seg)
{
  while (len > 0) {
    u16_t n = (u16_t)((len > seg) ? seg : len);
    cl_input(c, data, n, TCP_ACK | TCP_PSH);
    data += n;
    len -= n;
    ws_pump();
  }
}

static const char ws_key[] = "dGhlIHNhbXBsZSBub25jZQ==";
static const char ws_accept[] = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

static u16_t
build_request(char *buf, size_t size, const char *uri, const char *extra,
              const char *version, const char *key, const char *connection)
{
  int n = snprintf(buf, size,
                   "GET %s HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n"
                   "Connection: %s\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: %s\r\n%s\r\n",
                   uri, connection, key, version, extra);
  return (u16_t)n;
}

/* send an upgrade request; returns 1 if the server answered 101 */
static int
cl_upgrade(struct ws_client *c, const char *uri)
{
  char req[400];
  u16_t len = build_request(req, sizeof(req), uri, "", "13", ws_key, "keep-alive, Upgrade");
  cl_send(c, req, len);
  if ((c->rx_len >= 12) && (memcmp(c->rx, "HTTP/1.1 101", 12) == 0)) {
    const char *end = lwip_strnstr((const char *)c->rx, "\r\n\r\n", c->rx_len);
    fail_unless(end != NULL);
    fail_unless(lwip_strnstr((const char *)c->rx, ws_accept, c->rx_len) != NULL);
    c->rx_pos = (u32_t)(end + 4 - (const char *)c->rx);
    return 1;
  }
  return 0;
}

static int
cl_status(const struct ws_client *c, const char *status)
{
  return (c->rx_len >= 12) && (memcmp(c->rx, status, 12) == 0);
}

/* build a masked client frame */
static u32_t
mk_frame(u8_t *out, u8_t b0, const void *payload, u32_t len, u8_t ext64)
{
  static const u8_t mask[4] = { 0x37, 0xfa, 0x21, 0x3d };
  u32_t i, h = 0;
  out[h++] = b0;
  if ((len < 126) && !ext64) {
    out[h++] = (u8_t)(0x80 | len);
  } else if ((len <= 0xFFFF) && !ext64) {
    out[h++] = 0x80 | 126;
    out[h++] = (u8_t)(len >> 8);
    out[h++] = (u8_t)len;
  } else {
    out[h++] = 0x80 | 127;
    out[h++] = 0;
    out[h++] = 0;
    out[h++] = 0;
    out[h++] = 0;
    out[h++] = (u8_t)(len >> 24);
    out[h++] = (u8_t)(len >> 16);
    out[h++] = (u8_t)(len >> 8);
    out[h++] = (u8_t)len;
  }
  memcpy(&out[h], mask, 4);
  h += 4;
  for (i = 0; i < len; i++) {
    out[h + i] = (u8_t)(((const u8_t *)payload)[i] ^ mask[i & 3]);
  }
  return h + len;
}

/* parse the next server frame; returns 0 if none is complete */
static int
cl_frame(struct ws_client *c, u8_t *b0, u8_t *payload, u32_t *len)
{
  u32_t avail = c->rx_len - c->rx_pos;
  const u8_t *f = &c->rx[c->rx_pos];
  u32_t h = 2, l;
  if (avail < 2) {
    return 0;
  }
  fail_unless((f[1] & 0x80) == 0); /* server frames are not masked */
  l = f[1] & 0x7F;
  if (l == 126) {
    if (avail < 4) {
      return 0;
    }
    l = ((u32_t)f[2] << 8) | f[3];
    h = 4;
  } else if (l == 127) {
    if (avail < 10) {
      return 0;
    }
    l = ((u32_t)f[6] << 24) | ((u32_t)f[7] << 16) | ((u32_t)f[8] << 8) | f[9];
    h = 10;
  }
  if (avail < h + l) {
    return 0;
  }
  *b0 = f[0];
  if (payload != NULL) {
    memcpy(payload, f + h, l);
  }
  *len = l;
  c->rx_pos += h + l;
  return 1;
}

static void
expect_close_frame(struct ws_client *c, u16_t code)
{
  u8_t b0 = 0, pl[130];
  u32_t len = 0;
  fail_unless(cl_frame(c, &b0, pl, &len));
  fail_unless(b0 == (0x80 | WS_OPCODE_CLOSE));
  fail_unless(len >= 2);
  fail_unless((((u16_t)pl[0] << 8) | pl[1]) == code);
}

static struct tcp_pcb *
srv_pcb(const struct ws_client *c)
{
  struct tcp_pcb *pcb;
  for (pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    if (pcb->remote_port == c->port) {
      return pcb;
    }
  }
  return NULL;
}

/* deliver a pbuf chain directly to the server pcb's recv callback */
static void
srv_recv_chain(struct ws_client *c, const u8_t *data, u16_t len, u16_t piece)
{
  struct tcp_pcb *pcb = srv_pcb(c);
  struct pbuf *p = NULL;
  u16_t off = 0;
  fail_unless(pcb != NULL);
  if (pcb == NULL) {
    return;
  }
  while (off < len) {
    u16_t n = (u16_t)((len - off > piece) ? piece : (len - off));
    struct pbuf *q = pbuf_alloc(PBUF_RAW, n, PBUF_POOL);
    fail_unless(q != NULL);
    memcpy(q->payload, &data[off], n);
    if (p == NULL) {
      p = q;
    } else {
      pbuf_cat(p, q);
    }
    off = (u16_t)(off + n);
  }
  pcb->rcv_wnd = (tcpwnd_size_t)(pcb->rcv_wnd - len);
  if (pcb->recv(pcb->callback_arg, pcb, p, ERR_OK) != ERR_OK) {
    pbuf_free(p);
  }
  ws_pump();
}

static void
polls(int n)
{
  int i;
  for (i = 0; i < n * HTTPD_POLL_INTERVAL; i++) {
    tcp_slowtmr();
    ws_pump();
  }
}

/*---------------------------------------------------------------------------*/
/* setup / teardown */

static void
httpd_ws_setup(void)
{
  old_netif_list = netif_list;
  old_netif_default = netif_default;
  netif_list = NULL;
  netif_default = NULL;
  test_tcp_init_netif(&ws_netif, &ws_txc, &test_local_ip, &test_netmask);
  ws_txc.copy_tx_packets = 1;
  netif_set_default(&ws_netif);
  memset(&ev, 0, sizeof(ev));
  memset(&cl1, 0, sizeof(cl1));
  memset(&cl2, 0, sizeof(cl2));
  memset(&cl3, 0, sizeof(cl3));
  next_port = WS_TEST_PORT_BASE;
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
  httpd_init();
  httpd_ws_register_handlers(ws_handlers, LWIP_ARRAYSIZE(ws_handlers));
  httpd_ws_set_basic_auth(NULL, NULL);
}

static void
httpd_ws_teardown(void)
{
  tcp_remove_all();
  if (ws_txc.tx_packets != NULL) {
    pbuf_free(ws_txc.tx_packets);
    ws_txc.tx_packets = NULL;
  }
  netif_list = old_netif_list;
  netif_default = old_netif_default;
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

/*---------------------------------------------------------------------------*/
/* tests */

START_TEST(test_httpd_ws_sha1_base64)
{
  static const char abc[] = "abc";
  u8_t d[HTTPD_WS_SHA1_DIGEST_LEN];
  static const u8_t abc_digest[HTTPD_WS_SHA1_DIGEST_LEN] = {
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
    0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
  };
  char key[sizeof(ws_key) - 1 + 36];
  char out[32];
  u16_t n;
  LWIP_UNUSED_ARG(_i);

  httpd_ws_sha1((const u8_t *)abc, 3, d);
  fail_unless(memcmp(d, abc_digest, sizeof(d)) == 0);
  memcpy(key, ws_key, sizeof(ws_key) - 1);
  memcpy(&key[sizeof(ws_key) - 1], "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
  httpd_ws_sha1((const u8_t *)key, (u16_t)sizeof(key), d);
  n = httpd_ws_base64_encode(d, sizeof(d), out);
  fail_unless(n == 28);
  fail_unless(memcmp(out, ws_accept, 28) == 0);
  n = httpd_ws_base64_encode((const u8_t *)abc, 1, out);
  fail_unless((n == 4) && (memcmp(out, "YQ==", 4) == 0));
  n = httpd_ws_base64_encode((const u8_t *)abc, 2, out);
  fail_unless((n == 4) && (memcmp(out, "YWI=", 4) == 0));
}
END_TEST

/* handshake accepted, Accept value checked, open_cb called */
START_TEST(test_httpd_ws_handshake_ok)
{
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  fail_unless(ev.opens == 1);
  fail_unless(!cl1.got_fin);
  /* query string is ignored for matching */
  cl_connect(&cl2);
  fail_unless(cl_upgrade(&cl2, "/flat?x=1"));
  fail_unless(ev.opens == 2);
}
END_TEST

/* invalid upgrade requests are answered and closed (audit item k) */
START_TEST(test_httpd_ws_handshake_errors)
{
  char req[400];
  u16_t len;
  LWIP_UNUSED_ARG(_i);

  /* Connection without "upgrade" token -> 400 */
  cl_connect(&cl1);
  len = build_request(req, sizeof(req), "/flat", "", "13", ws_key, "keep-alive");
  cl_send(&cl1, req, len);
  fail_unless(cl_status(&cl1, "HTTP/1.1 400"));
  fail_unless(cl1.got_fin);

  /* unsupported version -> 426 with Sec-WebSocket-Version */
  cl_connect(&cl2);
  len = build_request(req, sizeof(req), "/flat", "", "8", ws_key, "Upgrade");
  cl_send(&cl2, req, len);
  fail_unless(cl_status(&cl2, "HTTP/1.1 426"));
  fail_unless(lwip_strnstr((const char *)cl2.rx, "Sec-WebSocket-Version: 13", cl2.rx_len) != NULL);
  fail_unless(cl2.got_fin);

  /* bad key length -> 400 */
  cl_connect(&cl3);
  len = build_request(req, sizeof(req), "/flat", "", "13", "abc", "Upgrade");
  cl_send(&cl3, req, len);
  fail_unless(cl_status(&cl3, "HTTP/1.1 400"));
  fail_unless(cl3.got_fin);

  /* unknown URI -> 404 */
  tcp_remove_all();
  httpd_init();
  cl_connect(&cl1);
  fail_unless(!cl_upgrade(&cl1, "/nothere"));
  fail_unless(cl_status(&cl1, "HTTP/1.1 404"));
  fail_unless(cl1.got_fin);
  fail_unless(ev.opens == 0);
}
END_TEST

/* auth_cb and Basic authentication */
START_TEST(test_httpd_ws_handshake_auth)
{
  char req[400];
  u16_t len;
  LWIP_UNUSED_ARG(_i);

  ev.auth_result = HTTPD_WS_AUTH_REJECTED;
  cl_connect(&cl1);
  fail_unless(!cl_upgrade(&cl1, "/auth"));
  fail_unless(cl_status(&cl1, "HTTP/1.1 401"));

  ev.auth_result = HTTPD_WS_AUTH_FORBIDDEN;
  cl_connect(&cl2);
  fail_unless(!cl_upgrade(&cl2, "/auth"));
  fail_unless(cl_status(&cl2, "HTTP/1.1 403"));

  ev.auth_result = HTTPD_WS_AUTH_OK;
  cl_connect(&cl3);
  fail_unless(cl_upgrade(&cl3, "/auth"));

  tcp_remove_all();
  httpd_init();
  /* user:pass -> dXNlcjpwYXNz */
  httpd_ws_set_basic_auth("user", "pass");
  cl_connect(&cl1);
  fail_unless(!cl_upgrade(&cl1, "/basic"));
  fail_unless(cl_status(&cl1, "HTTP/1.1 401"));
  cl_connect(&cl2);
  len = build_request(req, sizeof(req), "/basic", "Authorization: Basic dXNlcjp3cm9uZw==\r\n",
                      "13", ws_key, "Upgrade");
  cl_send(&cl2, req, len);
  fail_unless(cl_status(&cl2, "HTTP/1.1 401"));
  cl_connect(&cl3);
  len = build_request(req, sizeof(req), "/basic", "Authorization: Basic dXNlcjpwYXNz\r\n",
                      "13", ws_key, "Upgrade");
  cl_send(&cl3, req, len);
  fail_unless(cl_status(&cl3, "HTTP/1.1 101"));
  httpd_ws_set_basic_auth(NULL, NULL);
}
END_TEST

/* no free connection state -> 503 instead of "101 then failure" */
START_TEST(test_httpd_ws_handshake_503)
{
  LWIP_UNUSED_ARG(_i);
  LWIP_ASSERT("test assumes 2 connections", MEMP_NUM_PARALLEL_HTTPD_WEBSOCKET_CONNS == 2);
  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  cl_connect(&cl2);
  fail_unless(cl_upgrade(&cl2, "/chain"));
  cl_connect(&cl3);
  fail_unless(!cl_upgrade(&cl3, "/flat"));
  fail_unless(cl_status(&cl3, "HTTP/1.1 503"));
  fail_unless(cl3.got_fin);
  fail_unless(ev.opens == 2);
}
END_TEST

/* text message received, echoed by the application */
START_TEST(test_httpd_ws_echo_text)
{
  static const char hello[] = "Hello, lwIP";
  u8_t f[64], b0, pl[64];
  u32_t n, len;
  LWIP_UNUSED_ARG(_i);

  ev.echo = 1;
  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  n = mk_frame(f, 0x80 | WS_OPCODE_TEXT, hello, sizeof(hello) - 1, 0);
  cl_send(&cl1, f, n);
  fail_unless(ev.msgs == 1);
  fail_unless(ev.msg_opcode == WS_OPCODE_TEXT);
  fail_unless(ev.msg_len == sizeof(hello) - 1);
  fail_unless(memcmp(ev.msg, hello, sizeof(hello) - 1) == 0);
  fail_unless(cl_frame(&cl1, &b0, pl, &len));
  fail_unless(b0 == (0x80 | WS_OPCODE_TEXT));
  fail_unless((len == sizeof(hello) - 1) && (memcmp(pl, hello, len) == 0));
  fail_unless(ev.sent_calls > 0);
}
END_TEST

/* 3000 byte binary message: 16-bit length, 700-byte segments, header split
   into 1-byte segments */
START_TEST(test_httpd_ws_binary_segmented)
{
  static u8_t data[3000], f[3100];
  u32_t i, n;
  LWIP_UNUSED_ARG(_i);

  for (i = 0; i < sizeof(data); i++) {
    data[i] = (u8_t)(i * 7);
  }
  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  n = mk_frame(f, 0x80 | WS_OPCODE_BIN, data, sizeof(data), 0);
  cl_send_segments(&cl1, f, 8, 1);
  cl_send_segments(&cl1, f + 8, n - 8, 700);
  fail_unless(ev.msgs == 1);
  fail_unless(ev.msg_len == sizeof(data));
  fail_unless(memcmp(ev.msg, data, sizeof(data)) == 0);

  /* same with the pbuf API */
  cl_connect(&cl2);
  fail_unless(cl_upgrade(&cl2, "/chain"));
  cl_send_segments(&cl2, f, n, 700);
  fail_unless(ev.msgs == 2);
  fail_unless(ev.msg_len == sizeof(data));
  fail_unless(memcmp(ev.msg, data, sizeof(data)) == 0);
}
END_TEST

/* several frames in one pbuf chain, chain split at every possible size
   (audit item d: header/frame across pbuf boundaries) */
START_TEST(test_httpd_ws_pbuf_chain_boundaries)
{
  static u8_t stream[400], d1[130], d2[140];
  u32_t n, i;
  u16_t piece;
  int round;
  LWIP_UNUSED_ARG(_i);

  for (i = 0; i < sizeof(d1); i++) {
    d1[i] = (u8_t)(i + 1);
  }
  for (i = 0; i < sizeof(d2); i++) {
    d2[i] = (u8_t)(255 - i);
  }
  n = mk_frame(stream, 0x80 | WS_OPCODE_BIN, d1, 5, 0);
  n += mk_frame(&stream[n], 0x80 | WS_OPCODE_PING, "pp", 2, 0);
  n += mk_frame(&stream[n], 0x80 | WS_OPCODE_BIN, d1, sizeof(d1), 0);
  n += mk_frame(&stream[n], 0x80 | WS_OPCODE_BIN, d2, sizeof(d2), 1);
  n += mk_frame(&stream[n], 0x80 | WS_OPCODE_BIN, d1, 0, 0);

  for (round = 0; round < 2; round++) {
    for (piece = 1; piece <= 40; piece++) {
      struct ws_client *c = &cl1;
      tcp_remove_all();
      httpd_init();
      memset(&ev, 0, sizeof(ev));
      cl_connect(c);
      fail_unless(cl_upgrade(c, round ? "/chain" : "/flat"));
      srv_recv_chain(c, stream, (u16_t)n, piece);
      fail_unless(ev.msgs == 4);
      fail_unless(ev.pings == 1);
      fail_unless(ev.msg_len == 0); /* last message is empty */
      fail_unless(!c->got_fin);
    }
  }
  /* verify the content of the large frames once more with one big piece */
  tcp_remove_all();
  httpd_init();
  memset(&ev, 0, sizeof(ev));
  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/chain"));
  n = mk_frame(stream, 0x80 | WS_OPCODE_BIN, d2, sizeof(d2), 0);
  srv_recv_chain(&cl1, stream, (u16_t)n, 7);
  fail_unless((ev.msgs == 1) && (ev.msg_len == sizeof(d2)));
  fail_unless(memcmp(ev.msg, d2, sizeof(d2)) == 0);
}
END_TEST

/* control frames are handled without data callbacks (audit item e) */
START_TEST(test_httpd_ws_control_without_callbacks)
{
  u8_t f[64], b0, pl[64];
  u32_t n, len;
  static const u8_t close_pl[] = { 0x03, 0xE9, 'b', 'y', 'e' }; /* 1001 "bye" */
  LWIP_UNUSED_ARG(_i);

  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/nocb"));
  n = mk_frame(f, 0x80 | WS_OPCODE_PING, "abc", 3, 0);
  cl_send(&cl1, f, n);
  fail_unless(cl_frame(&cl1, &b0, pl, &len));
  fail_unless(b0 == (0x80 | WS_OPCODE_PONG));
  fail_unless((len == 3) && (memcmp(pl, "abc", 3) == 0));
  /* data is discarded silently */
  n = mk_frame(f, 0x80 | WS_OPCODE_TEXT, "data", 4, 0);
  cl_send(&cl1, f, n);
  fail_unless(ev.msgs == 0);
  n = mk_frame(f, 0x80 | WS_OPCODE_CLOSE, close_pl, sizeof(close_pl), 0);
  cl_send(&cl1, f, n);
  expect_close_frame(&cl1, 1001);
  fail_unless(cl1.got_fin);
  fail_unless(ev.closes == 1);
  fail_unless(ev.close_code == 1001);
  fail_unless(strcmp(ev.close_reason, "bye") == 0);
}
END_TEST

static void
check_protocol_error(u8_t b0, int masked, u16_t expected_code)
{
  u8_t f[64];
  u32_t n;
  tcp_remove_all();
  httpd_init();
  memset(&ev, 0, sizeof(ev));
  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  n = mk_frame(f, b0, "xy", 2, 0);
  if (!masked) {
    /* remove the mask bit and key, payload sent as is */
    f[1] &= 0x7F;
    memmove(&f[2], "xy", 2);
    n = 4;
  }
  cl_send(&cl1, f, n);
  expect_close_frame(&cl1, expected_code);
  fail_unless(cl1.got_fin);
  fail_unless(ev.closes == 1);
  fail_unless(ev.close_code == expected_code);
  fail_unless(ev.msgs == 0);
}

/* reserved opcodes, RSV bits, unmasked frames, lone continuation
   (audit items f and k) */
START_TEST(test_httpd_ws_protocol_errors)
{
  LWIP_UNUSED_ARG(_i);
  check_protocol_error(0x80 | 0x03, 1, WS_CLOSE_PROTOCOL_ERROR);
  check_protocol_error(0x80 | 0x0B, 1, WS_CLOSE_PROTOCOL_ERROR);
  check_protocol_error(0x80 | 0x40 | WS_OPCODE_TEXT, 1, WS_CLOSE_PROTOCOL_ERROR);
  check_protocol_error(0x80 | WS_OPCODE_TEXT, 0, WS_CLOSE_PROTOCOL_ERROR);
  check_protocol_error(0x80 | WS_OPCODE_CONT, 1, WS_CLOSE_PROTOCOL_ERROR);
  check_protocol_error(WS_OPCODE_PING, 1, WS_CLOSE_PROTOCOL_ERROR); /* fragmented control */
}
END_TEST

/* oversized messages: 64-bit length, flat buffer limit (1009) */
START_TEST(test_httpd_ws_too_big)
{
  static u8_t f[LWIP_HTTPD_WS_RX_BUF_SIZE + 32];
  static u8_t data[LWIP_HTTPD_WS_RX_BUF_SIZE + 1];
  u32_t n;
  LWIP_UNUSED_ARG(_i);

  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  /* 64-bit length encoding of a small payload is accepted */
  n = mk_frame(f, 0x80 | WS_OPCODE_BIN, "abc", 3, 1);
  cl_send(&cl1, f, n);
  fail_unless((ev.msgs == 1) && (ev.msg_len == 3));
  /* one byte more than the buffer: rejected after the header */
  n = mk_frame(f, 0x80 | WS_OPCODE_BIN, data, sizeof(data), 0);
  cl_send(&cl1, f, 20);
  expect_close_frame(&cl1, WS_CLOSE_MESSAGE_TOO_BIG);
  fail_unless(cl1.got_fin);
  fail_unless(ev.close_code == WS_CLOSE_MESSAGE_TOO_BIG);
  LWIP_UNUSED_ARG(n);

  /* length with the upper 32 bits set */
  cl_connect(&cl2);
  fail_unless(cl_upgrade(&cl2, "/chain"));
  n = mk_frame(f, 0x80 | WS_OPCODE_BIN, "abc", 3, 1);
  f[5] = 1;
  cl_send(&cl2, f, 14);
  expect_close_frame(&cl2, WS_CLOSE_MESSAGE_TOO_BIG);
  fail_unless(cl2.got_fin);
}
END_TEST

/* client starts the close handshake: one Close answer, then TCP close */
START_TEST(test_httpd_ws_close_by_client)
{
  u8_t f[64], b0;
  u32_t n, len;
  static const u8_t close_pl[] = { 0x03, 0xE8, 'o', 'k' };
  LWIP_UNUSED_ARG(_i);

  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  n = mk_frame(f, 0x80 | WS_OPCODE_CLOSE, close_pl, sizeof(close_pl), 0);
  cl_send(&cl1, f, n);
  expect_close_frame(&cl1, 1000);
  fail_unless(!cl_frame(&cl1, &b0, NULL, &len)); /* exactly one Close */
  fail_unless(cl1.got_fin);
  fail_unless((ev.closes == 1) && (ev.close_code == 1000));
  fail_unless(strcmp(ev.close_reason, "ok") == 0);
  /* invalid close code */
  cl_connect(&cl2);
  fail_unless(cl_upgrade(&cl2, "/flat"));
  f[0] = 0x03;
  f[1] = 0xED; /* 1005 must not be sent */
  n = mk_frame(f + 8, 0x80 | WS_OPCODE_CLOSE, f, 2, 0);
  cl_send(&cl2, f + 8, n);
  expect_close_frame(&cl2, WS_CLOSE_PROTOCOL_ERROR);
  fail_unless(cl2.got_fin);
}
END_TEST

/* server starts the close handshake (audit item j) */
START_TEST(test_httpd_ws_close_by_server)
{
  u8_t f[64], b0;
  u32_t n, len;
  static const u8_t close_pl[] = { 0x03, 0xE8 };
  LWIP_UNUSED_ARG(_i);

  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  fail_unless(httpd_ws_close(ev.last_pcb, 1000, (const u8_t *)"bye", 3) == ERR_OK);
  ws_pump();
  expect_close_frame(&cl1, 1000);
  fail_unless(httpd_ws_write(ev.last_pcb, (const u8_t *)"x", 1, WS_OPCODE_TEXT) == ERR_CLSD);
  fail_unless(httpd_ws_close(ev.last_pcb, 1000, NULL, 0) == ERR_CLSD);
  fail_unless(!cl1.got_fin);
  n = mk_frame(f, 0x80 | WS_OPCODE_CLOSE, close_pl, sizeof(close_pl), 0);
  cl_send(&cl1, f, n);
  fail_unless(!cl_frame(&cl1, &b0, NULL, &len)); /* not echoed again */
  fail_unless(cl1.got_fin);
  fail_unless((ev.closes == 1) && (ev.close_code == 1000));

  /* peer never answers: TCP is closed after the close timeout */
  cl_connect(&cl2);
  fail_unless(cl_upgrade(&cl2, "/flat"));
  fail_unless(httpd_ws_close(ev.last_pcb, 1001, NULL, 0) == ERR_OK);
  ws_pump();
  expect_close_frame(&cl2, 1001);
  polls(LWIP_HTTPD_WS_CLOSE_TIMEOUT_POLLS - 1);
  fail_unless(!cl2.got_fin);
  polls(1);
  fail_unless(cl2.got_fin);
  fail_unless((ev.closes == 2) && (ev.close_code == 1001));
}
END_TEST

/* TCP reset: close_cb is called once with 1006 (audit item h) */
START_TEST(test_httpd_ws_reset)
{
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/chain"));
  cl_input(&cl1, NULL, 0, TCP_RST | TCP_ACK);
  fail_unless(ev.closes == 1);
  fail_unless(ev.close_code == WS_CLOSE_ABNORMAL);
  fail_unless(httpd_ws_write(ev.last_pcb, (const u8_t *)"x", 1, WS_OPCODE_TEXT) == ERR_CONN);
}
END_TEST

/* keep-alive: PING after the interval, close without answer (audit item g) */
START_TEST(test_httpd_ws_ping_timeout)
{
  u8_t f[32], b0;
  u32_t n, len;
  LWIP_UNUSED_ARG(_i);

  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  polls(LWIP_HTTPD_WS_PING_INTERVAL_POLLS - 1);
  fail_unless(!cl_frame(&cl1, &b0, NULL, &len));
  polls(1);
  fail_unless(cl_frame(&cl1, &b0, NULL, &len));
  fail_unless(b0 == (0x80 | WS_OPCODE_PING));
  /* answer: stays open for another interval */
  n = mk_frame(f, 0x80 | WS_OPCODE_PONG, NULL, 0, 0);
  cl_send(&cl1, f, n);
  fail_unless(ev.pongs == 1);
  polls(LWIP_HTTPD_WS_PING_INTERVAL_POLLS + LWIP_HTTPD_WS_PONG_TIMEOUT_POLLS - 1);
  fail_unless(!cl1.got_fin);
  /* second PING not answered */
  polls(1);
  fail_unless(cl1.got_fin);
  fail_unless((ev.closes == 1) && (ev.close_code == WS_CLOSE_ABNORMAL));
}
END_TEST

/* fragmented messages on receive, PING between fragments */
START_TEST(test_httpd_ws_rx_fragments)
{
  u8_t f[300];
  u32_t n;
  int round;
  LWIP_UNUSED_ARG(_i);

  for (round = 0; round < 2; round++) {
    struct ws_client *c = round ? &cl2 : &cl1;
    memset(&ev, 0, sizeof(ev));
    cl_connect(c);
    fail_unless(cl_upgrade(c, round ? "/chain" : "/flat"));
    n = mk_frame(f, WS_OPCODE_TEXT, "He", 2, 0);
    n += mk_frame(&f[n], 0x80 | WS_OPCODE_PING, NULL, 0, 0);
    n += mk_frame(&f[n], WS_OPCODE_CONT, "llo, ", 5, 0);
    n += mk_frame(&f[n], 0x80 | WS_OPCODE_CONT, "world", 5, 0);
    cl_send(c, f, n);
    fail_unless(ev.msgs == 1);
    fail_unless(ev.pings == 1);
    fail_unless(ev.msg_opcode == WS_OPCODE_TEXT);
    fail_unless((ev.msg_len == 12) && (memcmp(ev.msg, "Hello, world", 12) == 0));
    if (round) {
      fail_unless(ev.msg_was_chain);
    }
    /* new data frame while a message is open -> 1002 */
    n = mk_frame(f, WS_OPCODE_BIN, "a", 1, 0);
    n += mk_frame(&f[n], 0x80 | WS_OPCODE_BIN, "b", 1, 0);
    cl_send(c, f, n);
    {
      u8_t b0 = 0, pl[8];
      u32_t len;
      fail_unless(cl_frame(c, &b0, pl, &len)); /* PONG */
      fail_unless(b0 == (0x80 | WS_OPCODE_PONG));
    }
    expect_close_frame(c, WS_CLOSE_PROTOCOL_ERROR);
    fail_unless(c->got_fin);
  }
}
END_TEST

/* message size limit over all fragments */
START_TEST(test_httpd_ws_rx_fragments_too_big)
{
  static u8_t data[LWIP_HTTPD_WS_RX_BUF_SIZE], f[LWIP_HTTPD_WS_RX_BUF_SIZE + 64];
  u32_t n;
  LWIP_UNUSED_ARG(_i);

  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  n = mk_frame(f, WS_OPCODE_BIN, data, sizeof(data) - 10, 0);
  n += mk_frame(&f[n], 0x80 | WS_OPCODE_CONT, data, 10, 0);
  cl_send(&cl1, f, n);
  fail_unless((ev.msgs == 1) && (ev.msg_len == sizeof(data)));
  n = mk_frame(f, WS_OPCODE_BIN, data, sizeof(data) - 10, 0);
  n += mk_frame(&f[n], 0x80 | WS_OPCODE_CONT, data, 11, 0);
  cl_send(&cl1, f, n);
  expect_close_frame(&cl1, WS_CLOSE_MESSAGE_TOO_BIG);
  fail_unless(ev.msgs == 1);
}
END_TEST

#if LWIP_HTTPD_WS_UTF8_CHECK
/* UTF-8 validation of text messages (1007) */
START_TEST(test_httpd_ws_utf8)
{
  static const u8_t euro[] = { 0xE2, 0x82, 0xAC };
  static const u8_t bad[] = { 'a', 0xC0, 0xAF };            /* overlong '/' */
  static const u8_t surrogate[] = { 0xED, 0xA0, 0x80 };     /* U+D800 */
  u8_t f[64];
  u32_t n;
  LWIP_UNUSED_ARG(_i);

  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/chain"));
  /* code point split over two fragments */
  n = mk_frame(f, WS_OPCODE_TEXT, euro, 1, 0);
  n += mk_frame(&f[n], 0x80 | WS_OPCODE_CONT, &euro[1], 2, 0);
  cl_send(&cl1, f, n);
  fail_unless((ev.msgs == 1) && (ev.msg_len == 3));
  /* binary is not checked */
  n = mk_frame(f, 0x80 | WS_OPCODE_BIN, bad, sizeof(bad), 0);
  cl_send(&cl1, f, n);
  fail_unless(ev.msgs == 2);
  n = mk_frame(f, 0x80 | WS_OPCODE_TEXT, bad, sizeof(bad), 0);
  cl_send(&cl1, f, n);
  expect_close_frame(&cl1, WS_CLOSE_INVALID_PAYLOAD);
  fail_unless(cl1.got_fin);

  cl_connect(&cl2);
  fail_unless(cl_upgrade(&cl2, "/flat"));
  n = mk_frame(f, 0x80 | WS_OPCODE_TEXT, surrogate, sizeof(surrogate), 0);
  cl_send(&cl2, f, n);
  expect_close_frame(&cl2, WS_CLOSE_INVALID_PAYLOAD);

  /* truncated sequence at the end of the message */
  cl_connect(&cl3);
  fail_unless(cl_upgrade(&cl3, "/flat"));
  n = mk_frame(f, 0x80 | WS_OPCODE_TEXT, euro, 2, 0);
  cl_send(&cl3, f, n);
  expect_close_frame(&cl3, WS_CLOSE_INVALID_PAYLOAD);
  fail_unless(ev.msgs == 2);
}
END_TEST
#endif /* LWIP_HTTPD_WS_UTF8_CHECK */

/* transmit: header encodings, all-or-nothing writes (audit item c) */
START_TEST(test_httpd_ws_tx_lengths)
{
  static u8_t data[0x10010], pl[2000];
  static const u32_t lens[] = { 0, 125, 126, 1000, 1500 };
  u8_t b0;
  u32_t len, i;
  struct altcp_pcb *pcb;
  LWIP_UNUSED_ARG(_i);

  for (i = 0; i < sizeof(data); i++) {
    data[i] = (u8_t)i;
  }
  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  pcb = ev.last_pcb;
  for (i = 0; i < LWIP_ARRAYSIZE(lens); i++) {
    fail_unless(httpd_ws_write(pcb, data, lens[i], WS_OPCODE_BIN) == ERR_OK);
    ws_pump();
    fail_unless(cl_frame(&cl1, &b0, pl, &len));
    fail_unless((b0 == (0x80 | WS_OPCODE_BIN)) && (len == lens[i]));
    fail_unless(memcmp(pl, data, len) == 0);
  }
  /* 65532..65535 used to overflow a u16 frame length; larger than the
     send buffer now: nothing is queued */
  fail_unless(httpd_ws_write(pcb, data, 65533, WS_OPCODE_BIN) == ERR_MEM);
  fail_unless(httpd_ws_write(pcb, data, 0x10001, WS_OPCODE_BIN) == ERR_MEM);
  ws_pump();
  fail_unless(!cl_frame(&cl1, &b0, NULL, &len));
  fail_unless(httpd_ws_write(pcb, data, 10, 0x05) == ERR_ARG);
  fail_unless(httpd_ws_write(pcb, NULL, 10, WS_OPCODE_BIN) == ERR_ARG);
}
END_TEST

/* transmit fragments, sent_cb */
START_TEST(test_httpd_ws_tx_fragments)
{
  u8_t b0, pl[64];
  u32_t len;
  struct altcp_pcb *pcb;
  LWIP_UNUSED_ARG(_i);

  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  pcb = ev.last_pcb;
  fail_unless(httpd_ws_write_fragment(pcb, (const u8_t *)"a", 1, WS_OPCODE_CONT, 0) == ERR_VAL);
  ev.sent_calls = 0;
  fail_unless(httpd_ws_write_fragment(pcb, (const u8_t *)"He", 2, WS_OPCODE_TEXT, 0) == ERR_OK);
  fail_unless(httpd_ws_write(pcb, (const u8_t *)"x", 1, WS_OPCODE_TEXT) == ERR_INPROGRESS);
  fail_unless(httpd_ws_write_fragment(pcb, (const u8_t *)"x", 1, WS_OPCODE_TEXT, 0) == ERR_VAL);
  fail_unless(httpd_ws_ping(pcb, NULL, 0) == ERR_OK);
  fail_unless(httpd_ws_write_fragment(pcb, (const u8_t *)"llo", 3, WS_OPCODE_CONT, 1) == ERR_OK);
  fail_unless(httpd_ws_write(pcb, (const u8_t *)"x", 1, WS_OPCODE_TEXT) == ERR_OK);
  ws_pump();
  fail_unless(cl_frame(&cl1, &b0, pl, &len) && (b0 == WS_OPCODE_TEXT) && (len == 2));
  fail_unless(cl_frame(&cl1, &b0, pl, &len) && (b0 == (0x80 | WS_OPCODE_PING)) && (len == 0));
  fail_unless(cl_frame(&cl1, &b0, pl, &len) && (b0 == (0x80 | WS_OPCODE_CONT)) && (len == 3));
  fail_unless(cl_frame(&cl1, &b0, pl, &len) && (b0 == (0x80 | WS_OPCODE_TEXT)) && (len == 1));
  fail_unless(ev.sent_calls > 0);
}
END_TEST

/* broadcast keeps going when one peer cannot take the message */
START_TEST(test_httpd_ws_broadcast)
{
  static u8_t data[1400];
  u8_t b0;
  u32_t len;
  int i;
  err_t err = ERR_OK;
  LWIP_UNUSED_ARG(_i);

  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  cl_connect(&cl2);
  fail_unless(cl_upgrade(&cl2, "/chain"));
  fail_unless(httpd_ws_broadcast((const u8_t *)"all", 3, WS_OPCODE_TEXT) == ERR_OK);
  fail_unless(httpd_ws_broadcast_uri("/chain", (const u8_t *)"two", 3, WS_OPCODE_TEXT) == ERR_OK);
  fail_unless(httpd_ws_broadcast_uri("/none", (const u8_t *)"x", 1, WS_OPCODE_TEXT) == ERR_ARG);
  ws_pump();
  fail_unless(cl_frame(&cl1, &b0, NULL, &len) && (len == 3));
  fail_unless(!cl_frame(&cl1, &b0, NULL, &len));
  fail_unless(cl_frame(&cl2, &b0, NULL, &len) && (len == 3));
  fail_unless(cl_frame(&cl2, &b0, NULL, &len) && (len == 3));

  /* client 2 stops acknowledging: its send buffer fills up */
  cl2.no_ack = 1;
  for (i = 0; (i < 40) && (err == ERR_OK); i++) {
    err = httpd_ws_broadcast(data, sizeof(data), WS_OPCODE_BIN);
    ws_pump();
  }
  fail_unless(err == ERR_MEM);
  /* client 1 got every message */
  for (; i > 0; i--) {
    fail_unless(cl_frame(&cl1, &b0, NULL, &len) && (len == sizeof(data)));
  }
}
END_TEST

/* repeated open/close cycles do not leak (pool and heap checked in teardown) */
START_TEST(test_httpd_ws_cycles)
{
  u8_t f[16];
  u32_t n;
  int i;
  LWIP_UNUSED_ARG(_i);

  for (i = 0; i < 6; i++) {
    cl_connect(&cl1);
    fail_unless(cl_upgrade(&cl1, (i & 1) ? "/chain" : "/flat"));
    n = mk_frame(f, WS_OPCODE_TEXT, "ab", 2, 0); /* leave a message open */
    cl_send(&cl1, f, n);
    n = mk_frame(f, 0x80 | WS_OPCODE_CLOSE, NULL, 0, 0);
    cl_send(&cl1, f, n);
    expect_close_frame(&cl1, 1000);
    fail_unless(cl1.got_fin);
    cl_input(&cl1, NULL, 0, TCP_ACK | TCP_FIN);
    ws_pump();
  }
  fail_unless(ev.closes == 6);
  fail_unless(ev.close_code == WS_CLOSE_NO_STATUS);
}
END_TEST

/* a normal GET still works next to an open WebSocket */
START_TEST(test_httpd_ws_plain_get)
{
  static const char get[] = "GET /index.html HTTP/1.0\r\n\r\n";
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  fail_unless(cl_upgrade(&cl1, "/flat"));
  cl_connect(&cl2);
  cl_send(&cl2, get, sizeof(get) - 1);
  fail_unless(cl_status(&cl2, "HTTP/1.0 200"));
  fail_unless(cl2.got_fin);
  fail_unless(!cl1.got_fin);
}
END_TEST

Suite *
httpd_ws_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_httpd_ws_sha1_base64),
    TESTFUNC(test_httpd_ws_handshake_ok),
    TESTFUNC(test_httpd_ws_handshake_errors),
    TESTFUNC(test_httpd_ws_handshake_auth),
    TESTFUNC(test_httpd_ws_handshake_503),
    TESTFUNC(test_httpd_ws_echo_text),
    TESTFUNC(test_httpd_ws_binary_segmented),
    TESTFUNC(test_httpd_ws_pbuf_chain_boundaries),
    TESTFUNC(test_httpd_ws_control_without_callbacks),
    TESTFUNC(test_httpd_ws_protocol_errors),
    TESTFUNC(test_httpd_ws_too_big),
    TESTFUNC(test_httpd_ws_close_by_client),
    TESTFUNC(test_httpd_ws_close_by_server),
    TESTFUNC(test_httpd_ws_reset),
    TESTFUNC(test_httpd_ws_ping_timeout),
    TESTFUNC(test_httpd_ws_rx_fragments),
    TESTFUNC(test_httpd_ws_rx_fragments_too_big),
#if LWIP_HTTPD_WS_UTF8_CHECK
    TESTFUNC(test_httpd_ws_utf8),
#endif /* LWIP_HTTPD_WS_UTF8_CHECK */
    TESTFUNC(test_httpd_ws_tx_lengths),
    TESTFUNC(test_httpd_ws_tx_fragments),
    TESTFUNC(test_httpd_ws_broadcast),
    TESTFUNC(test_httpd_ws_cycles),
    TESTFUNC(test_httpd_ws_plain_get)
  };
  return create_suite("HTTPD_WS", tests, sizeof(tests) / sizeof(testfunc), httpd_ws_setup, httpd_ws_teardown);
}
