#include "test_httpd_cors.h"

#include "lwip/apps/httpd.h"
#include "lwip/apps/fs.h"
#if LWIP_HTTPD_POST_DISPATCH
#include "lwip/apps/httpd_post_dispatch.h"
#endif /* LWIP_HTTPD_POST_DISPATCH */
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/stats.h"
#include "lwip/prot/tcp.h"
#include "../tcp/tcp_helper.h"

#include <string.h>
#include <stdio.h>

/* Tests for the OPTIONS method and the CORS headers of httpd.
 *
 * The tests act as an HTTP client: they inject TCP segments into the stack
 * (tcp_helper), collect everything httpd sends on the test netif and
 * acknowledge it.
 *
 * The suite is written for the test lwipopts.h (OPTIONS and CORS on), but
 * also builds and passes with LWIP_HTTPD_SUPPORT_OPTIONS and/or
 * LWIP_HTTPD_CORS set to 0 (e.g. -DLWIP_HTTPD_SUPPORT_OPTIONS=0 in CC):
 * then OPTIONS must be answered with 501 and no CORS header may appear. */

#if !LWIP_HTTPD_DYNAMIC_HEADERS || !LWIP_HTTPD_CUSTOM_FILES || !LWIP_HTTPD_SUPPORT_POST || \
    !LWIP_HTTPD_SUPPORT_11_KEEPALIVE || !LWIP_HTTPD_SUPPORT_REQUESTLIST || !LWIP_HTTPD_SUPPORT_EXTSTATUS
#error "This test needs LWIP_HTTPD_DYNAMIC_HEADERS, LWIP_HTTPD_CUSTOM_FILES, LWIP_HTTPD_SUPPORT_POST, LWIP_HTTPD_SUPPORT_11_KEEPALIVE, LWIP_HTTPD_SUPPORT_REQUESTLIST and LWIP_HTTPD_SUPPORT_EXTSTATUS"
#endif

#define CORS_TEST_PORT_BASE 0x5000
#define CORS_RX_MAX         4000

#define ACAO "Access-Control-Allow-Origin:"

static struct netif cors_netif;
static struct test_tcp_txcounters cors_txc;
static struct netif *old_netif_list;
static struct netif *old_netif_default;

/* client side of one connection */
struct cors_client {
  u16_t port;
  u32_t cli_seq;   /* next sequence number we send */
  u32_t srv_seq;   /* next sequence number expected from the server */
  u8_t got_fin;
  u8_t got_rst;
  char rx[CORS_RX_MAX + 1];
  u32_t rx_len;    /* bytes received from the server */
};

static struct cors_client cl1;
static u16_t next_port;

/* what the application callbacks saw */
static struct {
  int opens;          /* fs_open_custom() calls */
  int post_begins;    /* httpd_post_begin() calls */
  int hook_calls;
  char hook_uri[64];
  u16_t hook_rsp_max;
} ev;

/*---------------------------------------------------------------------------*/
/* application side: custom files */

static const char file_txt[] = "hello";
static const char file_err[] = "<html>error</html>";
static const char file_posted[] = "posted";
static const char file_own[] =
  "HTTP/1.0 200 OK\r\n"
  ACAO " https://own.example\r\n"
  "Content-Type: text/plain\r\n"
  "\r\n"
  "own";

static int
cors_set_file(struct fs_file *file, const char *data, int len, u8_t flags)
{
  memset(file, 0, sizeof(struct fs_file));
  file->data = data;
  file->len = len;
  file->index = len;
  file->flags = flags;
  return 1;
}

static int
cors_fs_open(struct fs_file *file, const char *name)
{
  ev.opens++;
  if (!strcmp(name, "/cors.txt")) {
    return cors_set_file(file, file_txt, sizeof(file_txt) - 1, FS_FILE_FLAGS_HEADER_PERSISTENT);
  }
  if (!strcmp(name, "/501.html") || !strcmp(name, "/400.html")) {
    return cors_set_file(file, file_err, sizeof(file_err) - 1, FS_FILE_FLAGS_HEADER_PERSISTENT);
  }
  if (!strcmp(name, "/posted.html")) {
    return cors_set_file(file, file_posted, sizeof(file_posted) - 1, FS_FILE_FLAGS_HEADER_PERSISTENT);
  }
  if (!strcmp(name, "/own.html")) {
    return cors_set_file(file, file_own, sizeof(file_own) - 1, FS_FILE_FLAGS_HEADER_INCLUDED);
  }
  return 0;
}

#if LWIP_HTTPD_CUSTOM_FILE_PROVIDERS
/* several modules provide custom files: register as a provider */
static struct fs_custom_provider cors_provider;
#else /* LWIP_HTTPD_CUSTOM_FILE_PROVIDERS */
int
fs_open_custom(struct fs_file *file, const char *name)
{
  return cors_fs_open(file, name);
}

void
fs_close_custom(struct fs_file *file)
{
  LWIP_UNUSED_ARG(file);
}
#endif /* LWIP_HTTPD_CUSTOM_FILE_PROVIDERS */

/*---------------------------------------------------------------------------*/
/* application side: POST */

static err_t
cors_post_begin(void *connection, const char *uri, const char *http_request,
                u16_t http_request_len, int content_len, char *response_uri,
                u16_t response_uri_len, u8_t *post_auto_wnd)
{
  LWIP_UNUSED_ARG(connection);
  LWIP_UNUSED_ARG(uri);
  LWIP_UNUSED_ARG(http_request);
  LWIP_UNUSED_ARG(http_request_len);
  LWIP_UNUSED_ARG(content_len);
  LWIP_UNUSED_ARG(response_uri);
  LWIP_UNUSED_ARG(response_uri_len);
  LWIP_UNUSED_ARG(post_auto_wnd);
  ev.post_begins++;
  return ERR_OK;
}

static err_t
cors_post_receive(void *connection, struct pbuf *p)
{
  LWIP_UNUSED_ARG(connection);
  pbuf_free(p);
  return ERR_OK;
}

static void
cors_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
  LWIP_UNUSED_ARG(connection);
  strncpy(response_uri, "/posted.html", response_uri_len);
}

#if LWIP_HTTPD_POST_DISPATCH
/* several modules handle POST: register a sink for "/form" */
static u8_t
cors_post_match(const char *uri, const char *http_request, u16_t http_request_len)
{
  LWIP_UNUSED_ARG(http_request);
  LWIP_UNUSED_ARG(http_request_len);
  return (u8_t)!strcmp(uri, "/form");
}

static const struct httpd_post_sink cors_sink = {
  "cors", cors_post_match, cors_post_begin, cors_post_receive, cors_post_finished
};
#else /* LWIP_HTTPD_POST_DISPATCH */
err_t
httpd_post_begin(void *connection, const char *uri, const char *http_request,
                 u16_t http_request_len, int content_len, char *response_uri,
                 u16_t response_uri_len, u8_t *post_auto_wnd)
{
  return cors_post_begin(connection, uri, http_request, http_request_len, content_len,
                         response_uri, response_uri_len, post_auto_wnd);
}

err_t
httpd_post_receive_data(void *connection, struct pbuf *p)
{
  return cors_post_receive(connection, p);
}

void
httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
  cors_post_finished(connection, response_uri, response_uri_len);
}
#endif /* LWIP_HTTPD_POST_DISPATCH */

/*---------------------------------------------------------------------------*/
/* application side: OPTIONS hook */

#if LWIP_HTTPD_SUPPORT_OPTIONS
/* Echo the request "Origin" if it is allowed, with credentials;
   "/nolen" answers without Content-Length; everything else: built-in answer */
static u16_t
cors_hook(const char *uri, const char *headers, u16_t headers_len, char *rsp, u16_t rsp_max)
{
  static const char allowed[] = "https://app.example.com";
  const char *origin;
  int n;

  ev.hook_calls++;
  ev.hook_rsp_max = rsp_max;
  strncpy(ev.hook_uri, uri, sizeof(ev.hook_uri) - 1);

  if (!strcmp(uri, "/nolen")) {
    n = snprintf(rsp, rsp_max, "HTTP/1.1 404 Not Found\r\n\r\n");
    return ((n > 0) && (n < rsp_max)) ? (u16_t)n : 0;
  }
  /* the request headers end with an empty line, so reading up to the
     CR after the value stays inside them */
  origin = lwip_strnistr(headers, "\r\nOrigin: ", headers_len);
  if ((origin != NULL) && !strncmp(origin + 10, allowed, sizeof(allowed) - 1) &&
      (origin[10 + sizeof(allowed) - 1] == '\r')) {
    n = snprintf(rsp, rsp_max,
                 "HTTP/1.1 204 No Content\r\n"
                 ACAO " %s\r\n"
                 "Access-Control-Allow-Credentials: true\r\n"
                 "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                 "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
                 "Vary: Origin\r\n"
                 "Content-Length: 0\r\n"
                 "\r\n", allowed);
    return ((n > 0) && (n < rsp_max)) ? (u16_t)n : 0;
  }
  return 0;
}
#endif /* LWIP_HTTPD_SUPPORT_OPTIONS */

/*---------------------------------------------------------------------------*/
/* client helpers */

static void
cl_input(struct cors_client *c, const void *data, u16_t len, u8_t flags)
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
    test_tcp_input(p, &cors_netif);
  }
  c->cli_seq += len;
  if (flags & (TCP_SYN | TCP_FIN)) {
    c->cli_seq++;
  }
}

/* collect everything the server sent, ack it; loop until quiet */
static void
cors_pump(struct cors_client *c)
{
  int rounds;
  for (rounds = 0; rounds < 50; rounds++) {
    struct pbuf *pkts = cors_txc.tx_packets;
    struct pbuf *q;
    int ack = 0;
    if (pkts == NULL) {
      return;
    }
    cors_txc.tx_packets = NULL;
    for (q = pkts; q != NULL; q = q->next) {
      const u8_t *b = (const u8_t *)q->payload;
      u16_t iphl = (u16_t)((b[0] & 0x0F) * 4);
      const u8_t *t = b + iphl;
      u16_t tcphl = (u16_t)((t[12] >> 4) * 4);
      u16_t dport = (u16_t)((t[2] << 8) | t[3]);
      u32_t seq = ((u32_t)t[4] << 24) | ((u32_t)t[5] << 16) | ((u32_t)t[6] << 8) | t[7];
      u8_t flags = t[13];
      u16_t plen = (u16_t)(q->len - iphl - tcphl);
      if (dport != c->port) {
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
        fail_unless(c->rx_len + plen <= CORS_RX_MAX);
        if (c->rx_len + plen <= CORS_RX_MAX) {
          memcpy(&c->rx[c->rx_len], t + tcphl, plen);
          c->rx_len += plen;
          c->rx[c->rx_len] = 0;
        }
        c->srv_seq += plen;
        ack = 1;
      }
      if ((flags & TCP_FIN) && (seq + plen == c->srv_seq) && !c->got_fin) {
        c->got_fin = 1;
        c->srv_seq++;
        ack = 1;
      }
    }
    pbuf_free(pkts);
    if (ack) {
      cl_input(c, NULL, 0, TCP_ACK);
    }
  }
}

static void
cl_connect(struct cors_client *c)
{
  if ((c->port != 0) && c->got_fin && !c->got_rst) {
    /* finish the previous connection closed by the server, so that its pcb
       moves to TIME_WAIT and can be reused */
    cl_input(c, NULL, 0, TCP_FIN | TCP_ACK);
    cors_pump(c);
  }
  memset(c, 0, sizeof(*c));
  c->port = next_port++;
  c->cli_seq = 0x1000;
  cl_input(c, NULL, 0, TCP_SYN);
  cors_pump(c); /* SYN-ACK */
  fail_unless(c->srv_seq != 0);
  cl_input(c, NULL, 0, TCP_ACK);
  cors_pump(c);
}

/* send data in segments of at most 'seg' bytes */
static void
cl_send_seg(struct cors_client *c, const char *data, u16_t seg)
{
  u16_t len = (u16_t)strlen(data);
  while (len > 0) {
    u16_t n = (u16_t)((len > seg) ? seg : len);
    cl_input(c, data, n, TCP_ACK | TCP_PSH);
    data += n;
    len = (u16_t)(len - n);
    cors_pump(c);
  }
}

static void
cl_send(struct cors_client *c, const char *data)
{
  cl_send_seg(c, data, 1000);
}

#if LWIP_HTTPD_SUPPORT_OPTIONS
/* send data in three segments, split at pos1 and pos2 */
static void
cl_send_split(struct cors_client *c, const char *data, u16_t pos1, u16_t pos2)
{
  u16_t len = (u16_t)strlen(data);
  LWIP_ASSERT("bad split", (pos1 > 0) && (pos1 < pos2) && (pos2 < len));
  cl_input(c, data, pos1, TCP_ACK | TCP_PSH);
  cors_pump(c);
  cl_input(c, data + pos1, (u16_t)(pos2 - pos1), TCP_ACK | TCP_PSH);
  cors_pump(c);
  cl_input(c, data + pos2, (u16_t)(len - pos2), TCP_ACK | TCP_PSH);
  cors_pump(c);
}

/* forget what has been received so far (next response on the same connection) */
static void
cl_clear(struct cors_client *c)
{
  c->rx_len = 0;
  c->rx[0] = 0;
}
#endif /* LWIP_HTTPD_SUPPORT_OPTIONS */

static int
cl_status(const struct cors_client *c, const char *status)
{
  return (c->rx_len >= strlen(status)) && (memcmp(c->rx, status, strlen(status)) == 0);
}

static int
count_str(const char *hay, const char *needle)
{
  int n = 0;
  const char *p = hay;
  while ((p = strstr(p, needle)) != NULL) {
    n++;
    p += strlen(needle);
  }
  return n;
}

/* number of ACAO headers in the response head */
static int
cl_acao_count(const struct cors_client *c)
{
  char head[CORS_RX_MAX + 1];
  const char *end = strstr(c->rx, "\r\n\r\n");
  size_t len = (end != NULL) ? (size_t)(end - c->rx) : c->rx_len;
  memcpy(head, c->rx, len);
  head[len] = 0;
  return count_str(head, ACAO);
}

/*---------------------------------------------------------------------------*/
/* setup / teardown */

static void
httpd_cors_setup(void)
{
  old_netif_list = netif_list;
  old_netif_default = netif_default;
  netif_list = NULL;
  netif_default = NULL;
  test_tcp_init_netif(&cors_netif, &cors_txc, &test_local_ip, &test_netmask);
  cors_txc.copy_tx_packets = 1;
  netif_set_default(&cors_netif);
  memset(&ev, 0, sizeof(ev));
  memset(&cl1, 0, sizeof(cl1));
  next_port = CORS_TEST_PORT_BASE;
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
  httpd_init();
#if LWIP_HTTPD_SUPPORT_OPTIONS
  httpd_set_options_hook(NULL);
#endif /* LWIP_HTTPD_SUPPORT_OPTIONS */
#if LWIP_HTTPD_CUSTOM_FILE_PROVIDERS
  if (cors_provider.open == NULL) {
    cors_provider.open = cors_fs_open;
    fail_unless(fs_custom_provider_register(&cors_provider, FS_CUSTOM_PROVIDER_BEFORE_FSDATA) == ERR_OK);
  }
#endif /* LWIP_HTTPD_CUSTOM_FILE_PROVIDERS */
#if LWIP_HTTPD_POST_DISPATCH
  fail_unless(httpd_post_sink_register(&cors_sink) == ERR_OK);
#endif /* LWIP_HTTPD_POST_DISPATCH */
}

static void
httpd_cors_teardown(void)
{
#if LWIP_HTTPD_SUPPORT_OPTIONS
  httpd_set_options_hook(NULL);
#endif /* LWIP_HTTPD_SUPPORT_OPTIONS */
  tcp_remove_all();
  if (cors_txc.tx_packets != NULL) {
    pbuf_free(cors_txc.tx_packets);
    cors_txc.tx_packets = NULL;
  }
  netif_list = old_netif_list;
  netif_default = old_netif_default;
  lwip_check_ensure_no_alloc(SKIP_POOL(MEMP_SYS_TIMEOUT));
}

/*---------------------------------------------------------------------------*/
/* tests */

static const char preflight[] =
  "OPTIONS /api/data?x=1 HTTP/1.1\r\n"
  "Host: test\r\n"
  "Origin: https://app.example.com\r\n"
  "Access-Control-Request-Method: PUT\r\n"
  "Access-Control-Request-Headers: authorization, content-type\r\n"
  "\r\n";

#if LWIP_HTTPD_SUPPORT_OPTIONS

static void
check_builtin_preflight(const struct cors_client *c)
{
  fail_unless(cl_status(c, "HTTP/1.0 204 No Content\r\n"));
  fail_unless(strstr(c->rx, "\r\nAllow: " LWIP_HTTPD_CORS_ALLOW_METHODS "\r\n") != NULL);
  fail_unless(strstr(c->rx, "\r\nContent-Length: 0\r\n") != NULL);
  fail_unless(strstr(c->rx, "\r\n\r\n") + 4 == c->rx + c->rx_len); /* no body */
#if LWIP_HTTPD_CORS
  fail_unless(cl_acao_count(c) == 1);
  fail_unless(strstr(c->rx, "\r\n" ACAO " " LWIP_HTTPD_CORS_ALLOW_ORIGIN "\r\n") != NULL);
  fail_unless(strstr(c->rx, "\r\nAccess-Control-Allow-Methods: " LWIP_HTTPD_CORS_ALLOW_METHODS "\r\n") != NULL);
  fail_unless(strstr(c->rx, "\r\nAccess-Control-Allow-Headers: " LWIP_HTTPD_CORS_ALLOW_HEADERS "\r\n") != NULL);
  fail_unless(strstr(c->rx, "\r\nAccess-Control-Max-Age: 86400\r\n") != NULL);
#else /* LWIP_HTTPD_CORS */
  fail_unless(strstr(c->rx, "Access-Control-") == NULL);
#endif /* LWIP_HTTPD_CORS */
}

/* OPTIONS -> 204 with the CORS headers, no file opened, no POST callback */
START_TEST(test_httpd_cors_preflight)
{
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  cl_send(&cl1, preflight);
  check_builtin_preflight(&cl1);
  fail_unless(strstr(cl1.rx, "\r\nConnection: close\r\n") != NULL);
  fail_unless(cl1.got_fin);
  fail_unless(ev.opens == 0);
  fail_unless(ev.post_begins == 0);
}
END_TEST

/* persistent connection: OPTIONS, then GET on the same connection */
START_TEST(test_httpd_cors_preflight_keepalive)
{
  static const char ka[] =
    "OPTIONS /api/data HTTP/1.1\r\n"
    "Host: test\r\n"
    "Connection: keep-alive\r\n"
    "Origin: https://app.example.com\r\n"
    "\r\n";
  static const char get[] =
    "GET /cors.txt HTTP/1.1\r\n"
    "Host: test\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  cl_send(&cl1, ka);
  check_builtin_preflight(&cl1);
  fail_unless(strstr(cl1.rx, "\r\nConnection: keep-alive\r\n") != NULL);
  fail_unless(!cl1.got_fin);
  cl_clear(&cl1);
  cl_send(&cl1, get);
  fail_unless(cl_status(&cl1, "HTTP/1.0 200 OK\r\n"));
  fail_unless(strstr(cl1.rx, "\r\n\r\nhello") != NULL);
  fail_unless(cl_acao_count(&cl1) == LWIP_HTTPD_CORS);
  fail_unless(!cl1.got_fin);
}
END_TEST

/* an OPTIONS body is ignored: the connection is closed after the answer */
START_TEST(test_httpd_cors_preflight_body)
{
  static const char req[] =
    "OPTIONS /api/data HTTP/1.1\r\n"
    "Host: test\r\n"
    "Connection: keep-alive\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "GET /";
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  cl_send(&cl1, req);
  check_builtin_preflight(&cl1);
  fail_unless(strstr(cl1.rx, "\r\nConnection: close\r\n") != NULL);
  fail_unless(cl1.got_fin);
}
END_TEST

/* request split over several TCP segments (at most LWIP_HTTPD_REQ_QUEUELEN,
   as for GET) */
START_TEST(test_httpd_cors_preflight_split)
{
  static const u16_t segs[] = { 40, 60, 100 };
  u16_t len = (u16_t)strlen(preflight);
  size_t i;
  u16_t pos;
  LWIP_UNUSED_ARG(_i);
  for (i = 0; i < LWIP_ARRAYSIZE(segs); i++) {
    cl_connect(&cl1);
    cl_send_seg(&cl1, preflight, segs[i]);
    check_builtin_preflight(&cl1);
    fail_unless(cl1.got_fin);
  }
  /* split inside the method, in the URI, in the headers and in the final
     CRLFCRLF */
  for (pos = 1; pos < len - 1; pos = (u16_t)(pos + 13)) {
    cl_connect(&cl1);
    cl_send_split(&cl1, preflight, pos, (u16_t)(len - 2));
    check_builtin_preflight(&cl1);
    fail_unless(cl1.got_fin);
  }
  cl_connect(&cl1);
  cl_send_split(&cl1, preflight, 3, (u16_t)(len - 1));
  check_builtin_preflight(&cl1);
  fail_unless(ev.opens == 0);
}
END_TEST

/* HTTP/0.9 has no OPTIONS */
START_TEST(test_httpd_cors_preflight_09)
{
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  cl_send(&cl1, "OPTIONS /api\r\n\r\n");
  fail_unless(cl_status(&cl1, "HTTP/1.0 400 Bad Request\r\n"));
  fail_unless(cl1.got_fin);
}
END_TEST

/* the hook echoes an allowed origin with credentials; other origins get the
   built-in answer */
START_TEST(test_httpd_cors_hook_echo)
{
  static const char other[] =
    "OPTIONS /api/data HTTP/1.1\r\n"
    "Host: test\r\n"
    "Origin: https://app.example.com.evil.test\r\n"
    "\r\n";
  static const char ka[] =
    "OPTIONS /api/data HTTP/1.1\r\n"
    "Host: test\r\n"
    "Connection: keep-alive\r\n"
    "Origin: https://app.example.com\r\n"
    "\r\n";
  LWIP_UNUSED_ARG(_i);
  httpd_set_options_hook(cors_hook);

  cl_connect(&cl1);
  cl_send(&cl1, preflight);
  fail_unless(ev.hook_calls == 1);
  fail_unless(!strcmp(ev.hook_uri, "/api/data?x=1"));
  fail_unless(ev.hook_rsp_max == LWIP_HTTPD_OPTIONS_RSP_LEN);
  fail_unless(cl_status(&cl1, "HTTP/1.1 204 No Content\r\n"));
  fail_unless(cl_acao_count(&cl1) == 1);
  fail_unless(strstr(cl1.rx, "\r\n" ACAO " https://app.example.com\r\n") != NULL);
  fail_unless(strstr(cl1.rx, "\r\nAccess-Control-Allow-Credentials: true\r\n") != NULL);
  fail_unless(cl1.got_fin);

  cl_connect(&cl1);
  cl_send(&cl1, other);
  fail_unless(ev.hook_calls == 2);
  check_builtin_preflight(&cl1);
  fail_unless(strstr(cl1.rx, "Credentials") == NULL);
  fail_unless(cl1.got_fin);

  /* hook answer with Content-Length keeps a persistent connection */
  cl_connect(&cl1);
  cl_send(&cl1, ka);
  fail_unless(cl_status(&cl1, "HTTP/1.1 204 No Content\r\n"));
  fail_unless(!cl1.got_fin);
  cl_clear(&cl1);
  cl_send(&cl1, ka);
  fail_unless(ev.hook_calls == 4);
  fail_unless(cl_status(&cl1, "HTTP/1.1 204 No Content\r\n"));
  fail_unless(!cl1.got_fin);
  fail_unless(ev.opens == 0);
  fail_unless(ev.post_begins == 0);
}
END_TEST

/* a hook answer without Content-Length closes a persistent connection */
START_TEST(test_httpd_cors_hook_no_length)
{
  static const char req[] =
    "OPTIONS /nolen HTTP/1.1\r\n"
    "Host: test\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";
  LWIP_UNUSED_ARG(_i);
  httpd_set_options_hook(cors_hook);
  cl_connect(&cl1);
  cl_send(&cl1, req);
  fail_unless(!strcmp(cl1.rx, "HTTP/1.1 404 Not Found\r\n\r\n"));
  fail_unless(cl1.got_fin);
}
END_TEST

#else /* LWIP_HTTPD_SUPPORT_OPTIONS */

/* option off: OPTIONS is not implemented, as before */
START_TEST(test_httpd_cors_options_off)
{
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  cl_send(&cl1, preflight);
  fail_unless(cl_status(&cl1, "HTTP/1.0 501 Not Implemented\r\n"));
  fail_unless(strstr(cl1.rx, "<html>error</html>") != NULL);
  fail_unless(cl_acao_count(&cl1) == LWIP_HTTPD_CORS);
  fail_unless(strstr(cl1.rx, "Access-Control-Allow-Methods") == NULL);
  fail_unless(cl1.got_fin);
  fail_unless(ev.post_begins == 0);
}
END_TEST

#endif /* LWIP_HTTPD_SUPPORT_OPTIONS */

/* GET of a file without headers: dynamic headers carry ACAO once */
START_TEST(test_httpd_cors_get)
{
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  cl_send(&cl1, "GET /cors.txt HTTP/1.0\r\n\r\n");
  fail_unless(cl_status(&cl1, "HTTP/1.0 200 OK\r\n"));
  fail_unless(strstr(cl1.rx, "\r\n\r\nhello") != NULL);
  fail_unless(cl_acao_count(&cl1) == LWIP_HTTPD_CORS);
#if LWIP_HTTPD_CORS
  fail_unless(strstr(cl1.rx, "\r\n" ACAO " " LWIP_HTTPD_CORS_ALLOW_ORIGIN "\r\n") != NULL);
#endif /* LWIP_HTTPD_CORS */
  fail_unless(cl1.got_fin);
}
END_TEST

/* a file with its own headers is sent unchanged (no second ACAO) */
START_TEST(test_httpd_cors_get_own_headers)
{
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  cl_send(&cl1, "GET /own.html HTTP/1.0\r\n\r\n");
  fail_unless(!strcmp(cl1.rx, file_own));
  fail_unless(cl_acao_count(&cl1) == 1);
  fail_unless(cl1.got_fin);
}
END_TEST

/* unsupported method: the 501 error page carries ACAO */
START_TEST(test_httpd_cors_error_page)
{
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  cl_send(&cl1, "PUT /api/data HTTP/1.1\r\nHost: test\r\n\r\n");
  fail_unless(cl_status(&cl1, "HTTP/1.0 501 Not Implemented\r\n"));
  fail_unless(strstr(cl1.rx, "\r\n\r\n<html>error</html>") != NULL);
  fail_unless(cl_acao_count(&cl1) == LWIP_HTTPD_CORS);
  fail_unless(cl1.got_fin);
}
END_TEST

/* POST: the response URI carries ACAO */
START_TEST(test_httpd_cors_post)
{
  LWIP_UNUSED_ARG(_i);
  cl_connect(&cl1);
  cl_send(&cl1, "POST /form HTTP/1.0\r\nContent-Length: 3\r\n\r\na=b");
  fail_unless(ev.post_begins == 1);
  fail_unless(cl_status(&cl1, "HTTP/1.0 200 OK\r\n"));
  fail_unless(strstr(cl1.rx, "\r\n\r\nposted") != NULL);
  fail_unless(cl_acao_count(&cl1) == LWIP_HTTPD_CORS);
  fail_unless(cl1.got_fin);
}
END_TEST

Suite *
httpd_cors_suite(void)
{
  testfunc tests[] = {
#if LWIP_HTTPD_SUPPORT_OPTIONS
    TESTFUNC(test_httpd_cors_preflight),
    TESTFUNC(test_httpd_cors_preflight_keepalive),
    TESTFUNC(test_httpd_cors_preflight_body),
    TESTFUNC(test_httpd_cors_preflight_split),
    TESTFUNC(test_httpd_cors_preflight_09),
    TESTFUNC(test_httpd_cors_hook_echo),
    TESTFUNC(test_httpd_cors_hook_no_length),
#else /* LWIP_HTTPD_SUPPORT_OPTIONS */
    TESTFUNC(test_httpd_cors_options_off),
#endif /* LWIP_HTTPD_SUPPORT_OPTIONS */
    TESTFUNC(test_httpd_cors_get),
    TESTFUNC(test_httpd_cors_get_own_headers),
    TESTFUNC(test_httpd_cors_error_page),
    TESTFUNC(test_httpd_cors_post)
  };
  return create_suite("HTTPD_CORS", tests, sizeof(tests) / sizeof(testfunc), httpd_cors_setup, httpd_cors_teardown);
}
