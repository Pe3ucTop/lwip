#include "test_httpd_post.h"

#include "lwip/def.h"
#include "lwip/pbuf.h"
#include "lwip/apps/fs.h"
#include "lwip/apps/httpd.h"
#include "lwip/apps/httpd_post_dispatch.h"
#include "lwip/apps/httpd_status_pages.h"
#include "lwip/apps/http_multipart.h"
#include "lwip/apps/httpd_upload.h"

#include <string.h>

#if !LWIP_HTTPD_POST_DISPATCH || !LWIP_HTTPD_STATUS_PAGES || !LWIP_HTTPD_UPLOAD
#error These tests need LWIP_HTTPD_POST_DISPATCH, LWIP_HTTPD_STATUS_PAGES and LWIP_HTTPD_UPLOAD
#endif

/* ------------------------------------------------------------------ */
/* multipart parser recorder */

#define MP_MAX_PARTS 4
struct mp_rec {
  int nparts;
  int ended[MP_MAX_PARTS];
  int data_calls[MP_MAX_PARTS];
  int len[MP_MAX_PARTS];
  char data[MP_MAX_PARTS][1200];
  struct http_multipart_part info[MP_MAX_PARTS];
};

static err_t
rec_begin(void *arg, const struct http_multipart_part *part)
{
  struct mp_rec *r = (struct mp_rec *)arg;
  fail_unless(r->nparts < MP_MAX_PARTS);
  r->info[r->nparts] = *part;
  r->len[r->nparts] = 0;
  r->data_calls[r->nparts] = 0;
  r->ended[r->nparts] = -1;
  return ERR_OK;
}

static err_t
rec_data(void *arg, const u8_t *data, u16_t len)
{
  struct mp_rec *r = (struct mp_rec *)arg;
  int n = r->nparts;
  fail_unless(len > 0);
  fail_unless(r->len[n] + len <= (int)sizeof(r->data[n]));
  memcpy(&r->data[n][r->len[n]], data, len);
  r->len[n] += len;
  r->data_calls[n]++;
  return ERR_OK;
}

static void
rec_end(void *arg, u8_t complete)
{
  struct mp_rec *r = (struct mp_rec *)arg;
  r->ended[r->nparts] = complete;
  r->nparts++;
}

static const struct http_multipart_callbacks rec_cb = { rec_begin, rec_data, rec_end };

/* parse 'body' split into up to three pieces at s1 and s2 */
static err_t
mp_run(struct mp_rec *r, const char *boundary, const char *body, size_t len, size_t s1, size_t s2)
{
  struct http_multipart_parser p;
  err_t err;
  memset(r, 0, sizeof(*r));
  fail_unless(http_multipart_init(&p, boundary, &rec_cb, r) == ERR_OK);
  err = http_multipart_parse(&p, (const u8_t *)body, (u16_t)s1);
  if (err == ERR_OK) {
    err = http_multipart_parse(&p, (const u8_t *)body + s1, (u16_t)(s2 - s1));
  }
  if (err == ERR_OK) {
    err = http_multipart_parse(&p, (const u8_t *)body + s2, (u16_t)(len - s2));
  }
  if (err == ERR_OK) {
    err = http_multipart_finish(&p);
  }
  return err;
}

START_TEST(test_multipart_boundary)
{
  char b[HTTP_MULTIPART_MAX_BOUNDARY + 1];
  const char *h1 = " HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=abc123\r\nContent-Length: 5";
  const char *h2 = " HTTP/1.1\r\ncontent-type:Multipart/Form-Data;BOUNDARY=\"a b;c\"";
  const char *h3 = " HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded";
  const char *h4 = " HTTP/1.1\r\nContent-Type: multipart/form-data; charset=utf-8";
  const char *h5 = " HTTP/1.1\r\nHost: x";
  const char *h6 = " HTTP/1.1\r\nContent-Type: multipart/form-data; boundary="
                   "12345678901234567890123456789012345678901234567890123456789012345678901";
  LWIP_UNUSED_ARG(_i);

  fail_unless(http_multipart_get_boundary(h1, (u16_t)strlen(h1), b, sizeof(b)) == ERR_OK);
  fail_unless(!strcmp(b, "abc123"));
  fail_unless(http_multipart_get_boundary(h2, (u16_t)strlen(h2), b, sizeof(b)) == ERR_OK);
  fail_unless(!strcmp(b, "a b;c"));
  fail_unless(http_multipart_get_boundary(h3, (u16_t)strlen(h3), b, sizeof(b)) == ERR_VAL);
  fail_unless(http_multipart_get_boundary(h4, (u16_t)strlen(h4), b, sizeof(b)) == ERR_ARG);
  fail_unless(http_multipart_get_boundary(h5, (u16_t)strlen(h5), b, sizeof(b)) == ERR_VAL);
  /* 71 characters: too long */
  fail_unless(http_multipart_get_boundary(h6, (u16_t)strlen(h6), b, sizeof(b)) == ERR_ARG);
}
END_TEST

/* The CRLF after the first delimiter must be consumed, so the headers of
   the first part (and its filename) are parsed */
START_TEST(test_multipart_first_part)
{
  struct mp_rec r;
  const char *body = "--XyZ\r\n"
                     "Content-Disposition: form-data; name=\"file\"; filename=\"fw.bin\"\r\n"
                     "Content-Type: application/octet-stream\r\n"
                     "\r\n"
                     "DATA\r\n"
                     "--XyZ--\r\n";
  size_t len = strlen(body);
  LWIP_UNUSED_ARG(_i);

  fail_unless(mp_run(&r, "XyZ", body, len, len, len) == ERR_OK);
  fail_unless(r.nparts == 1);
  fail_unless(!strcmp(r.info[0].name, "file"));
  fail_unless(!strcmp(r.info[0].filename, "fw.bin"));
  fail_unless(!strcmp(r.info[0].content_type, "application/octet-stream"));
  fail_unless(r.info[0].flags == HTTP_MULTIPART_FLAG_FILENAME);
  fail_unless((r.len[0] == 4) && !memcmp(r.data[0], "DATA", 4));
  fail_unless(r.data_calls[0] == 1);
  fail_unless(r.ended[0] == 1);
}
END_TEST

/* Several parts (text field first), data that looks like a delimiter
   start, preamble, transport padding and epilogue; split at many
   position pairs */
START_TEST(test_multipart_every_split)
{
  struct mp_rec r;
  static const char body[] =
    "preamble\r\n"
    "--XyZ \t\r\n"
    "content-disposition: form-data; name=title\r\n"
    "\r\n"
    "hello\r\n--Xy\r\n-\r\n-XyZ\r\n"
    "--XyZ\r\n"
    "CONTENT-DISPOSITION: form-data; NAME=\"f\"; FileName=\"a;b.txt\"\r\n"
    "\r\n"
    "\r\r\n\r\n-\r\n--X\r\n--XyY\r\n"
    "--XyZ--\r\n"
    "epilogue --XyZ garbage";
  size_t len = sizeof(body) - 1;
  size_t s1, s2;
  LWIP_UNUSED_ARG(_i);

  for (s1 = 0; s1 <= len; s1++) {
    /* second split close to the first (delimiters spanning three pieces)
       or at the end */
    for (s2 = s1; s2 <= len; s2 = (s2 < s1 + 20) ? s2 + 1 : len + (s2 == len)) {
      fail_unless(mp_run(&r, "XyZ", body, len, s1, s2) == ERR_OK);
      fail_unless(r.nparts == 2);
      fail_unless(!strcmp(r.info[0].name, "title"));
      fail_unless(r.info[0].flags == 0);
      fail_unless((r.len[0] == 20) && !memcmp(r.data[0], "hello\r\n--Xy\r\n-\r\n-XyZ", 20));
      fail_unless(!strcmp(r.info[1].name, "f"));
      fail_unless(!strcmp(r.info[1].filename, "a;b.txt"));
      fail_unless((r.len[1] == 18) && !memcmp(r.data[1], "\r\r\n\r\n-\r\n--X\r\n--XyY", 18));
      fail_unless((r.ended[0] == 1) && (r.ended[1] == 1));
      /* at most: one run per piece plus held bytes at each split */
      fail_unless(r.data_calls[1] <= 5);
    }
  }
}
END_TEST

/* A header line longer than the line buffer still ends at its CRLF */
START_TEST(test_multipart_long_header)
{
  struct mp_rec r;
  char body[1000];
  char longval[301];
  size_t len;
  LWIP_UNUSED_ARG(_i);

  memset(longval, 'v', sizeof(longval) - 1);
  longval[sizeof(longval) - 1] = 0;

  /* an unknown long header does not affect the part */
  strcpy(body, "--B\r\nX-Long: ");
  strcat(body, longval);
  strcat(body, "\r\nContent-Disposition: form-data; name=\"n\"; filename=\"x.bin\"\r\n\r\nD\r\n--B--");
  len = strlen(body);
  fail_unless(mp_run(&r, "B", body, len, len, len) == ERR_OK);
  fail_unless(r.nparts == 1);
  fail_unless(!strcmp(r.info[0].filename, "x.bin"));
  fail_unless(r.info[0].flags == HTTP_MULTIPART_FLAG_FILENAME);
  fail_unless((r.len[0] == 1) && (r.data[0][0] == 'D'));

  /* a long Content-Disposition is reported as truncated */
  strcpy(body, "--B\r\nContent-Disposition: form-data; name=\"n\"; filename=\"");
  strcat(body, longval);
  strcat(body, "\"\r\n\r\nD\r\n--B--");
  len = strlen(body);
  fail_unless(mp_run(&r, "B", body, len, len, len) == ERR_OK);
  fail_unless(r.nparts == 1);
  fail_unless((r.info[0].flags & HTTP_MULTIPART_FLAG_TRUNCATED) != 0);
}
END_TEST

START_TEST(test_multipart_errors)
{
  struct mp_rec r;
  const char *cut = "--B\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\nabc";
  const char *bad = "--B\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\nabc\r\n--Bx";
  const char *none = "no delimiter at all";
  LWIP_UNUSED_ARG(_i);

  /* body cut off: the open part ends incomplete */
  fail_unless(mp_run(&r, "B", cut, strlen(cut), 2, 7) == ERR_VAL);
  fail_unless((r.nparts == 1) && (r.ended[0] == 0));
  fail_unless((r.len[0] == 3) && !memcmp(r.data[0], "abc", 3));
  /* delimiter followed by garbage */
  fail_unless(mp_run(&r, "B", bad, strlen(bad), 0, 0) == ERR_VAL);
  fail_unless((r.nparts == 1) && (r.ended[0] == 1));
  /* no delimiter */
  fail_unless(mp_run(&r, "B", none, strlen(none), 0, 0) == ERR_VAL);
  fail_unless(r.nparts == 0);
}
END_TEST

/* ------------------------------------------------------------------ */
/* POST dispatcher */

static int sink_begin_calls, sink_finished_calls, sink_rx_bytes;
static err_t sink_begin_result;

static u8_t
tsink_match(const char *uri, const char *http_request, u16_t http_request_len)
{
  LWIP_UNUSED_ARG(http_request);
  LWIP_UNUSED_ARG(http_request_len);
  return (u8_t)!strncmp(uri, "/t/", 3);
}

static err_t
tsink_begin(void *connection, const char *uri, const char *http_request,
            u16_t http_request_len, int content_len, char *response_uri,
            u16_t response_uri_len, u8_t *post_auto_wnd)
{
  LWIP_UNUSED_ARG(connection);
  LWIP_UNUSED_ARG(uri);
  LWIP_UNUSED_ARG(http_request);
  LWIP_UNUSED_ARG(http_request_len);
  LWIP_UNUSED_ARG(content_len);
  LWIP_UNUSED_ARG(post_auto_wnd);
  sink_begin_calls++;
  if (sink_begin_result != ERR_OK) {
    strncpy(response_uri, "/rejected", response_uri_len);
  }
  return sink_begin_result;
}

static err_t
tsink_receive(void *connection, struct pbuf *p)
{
  LWIP_UNUSED_ARG(connection);
  sink_rx_bytes += p->tot_len;
  pbuf_free(p);
  return ERR_OK;
}

static void
tsink_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
  LWIP_UNUSED_ARG(connection);
  sink_finished_calls++;
  strncpy(response_uri, "/done", response_uri_len);
}

static const struct httpd_post_sink tsink = {
  "test", tsink_match, tsink_begin, tsink_receive, tsink_finished
};

static err_t
post_begin(void *conn, const char *uri, const char *hdrs, int content_len, char *resp)
{
  u8_t wnd = 1;
  resp[0] = 0;
  return httpd_post_begin(conn, uri, hdrs, (u16_t)strlen(hdrs), content_len, resp, 64, &wnd);
}

static struct pbuf *
make_pbuf(const char *data, size_t len)
{
  struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
  fail_unless(p != NULL);
  memcpy(p->payload, data, len);
  return p;
}

static void
httpd_post_setup(void)
{
  sink_begin_calls = 0;
  sink_finished_calls = 0;
  sink_rx_bytes = 0;
  sink_begin_result = ERR_OK;
  fail_unless(httpd_post_sink_register(&tsink) == ERR_OK);
}

static void
httpd_post_teardown(void)
{
}

START_TEST(test_post_dispatch_conns)
{
  char resp[64];
  int conns[HTTPD_POST_DISPATCH_MAX_CONNS + 1];
  int i;
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  /* registering again is a no-op */
  fail_unless(httpd_post_sink_register(&tsink) == ERR_OK);

  for (i = 0; i < HTTPD_POST_DISPATCH_MAX_CONNS; i++) {
    fail_unless(post_begin(&conns[i], "/t/x", "", 3, resp) == ERR_OK);
  }
  /* table full */
  fail_unless(post_begin(&conns[i], "/t/x", "", 3, resp) == ERR_MEM);
  fail_unless(!strcmp(resp, HTTPD_POST_DISPATCH_URI_BUSY));
  fail_unless(sink_begin_calls == HTTPD_POST_DISPATCH_MAX_CONNS);

  p = make_pbuf("abc", 3);
  fail_unless(httpd_post_receive_data(&conns[1], p) == ERR_OK);
  fail_unless(sink_rx_bytes == 3);

  httpd_post_finished(&conns[1], resp, sizeof(resp));
  fail_unless(!strcmp(resp, "/done"));
  fail_unless(sink_finished_calls == 1);
  /* entry free again */
  fail_unless(post_begin(&conns[i], "/t/x", "", 3, resp) == ERR_OK);

  for (i = 0; i <= HTTPD_POST_DISPATCH_MAX_CONNS; i++) {
    if (i != 1) {
      httpd_post_finished(&conns[i], resp, sizeof(resp));
    }
  }
  fail_unless(sink_finished_calls == HTTPD_POST_DISPATCH_MAX_CONNS + 1);
}
END_TEST

START_TEST(test_post_dispatch_reject_unknown)
{
  char resp[64];
  int conn;
  int i;
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  /* rejected requests do not keep an entry */
  sink_begin_result = ERR_VAL;
  for (i = 0; i < 2 * HTTPD_POST_DISPATCH_MAX_CONNS; i++) {
    fail_unless(post_begin(&conn, "/t/x", "", 0, resp) == ERR_VAL);
    fail_unless(!strcmp(resp, "/rejected"));
  }
  sink_begin_result = ERR_OK;
  fail_unless(post_begin(&conn, "/t/x", "", 0, resp) == ERR_OK);
  httpd_post_finished(&conn, resp, sizeof(resp));

  /* no sink */
  fail_unless(post_begin(&conn, "/nothing", "", 0, resp) == ERR_ARG);
  fail_unless(!strcmp(resp, HTTPD_POST_DISPATCH_URI_NO_SINK));

  /* unknown connection: pbuf is freed, error page */
  p = make_pbuf("abc", 3);
  pbuf_ref(p);
  fail_unless(httpd_post_receive_data(&conn, p) == ERR_VAL);
  fail_unless(p->ref == 1);
  pbuf_free(p);
  httpd_post_finished(&conn, resp, sizeof(resp));
  fail_unless(!strcmp(resp, HTTPD_POST_DISPATCH_URI_ERROR));
  fail_unless(sink_finished_calls == 1);
}
END_TEST

/* ------------------------------------------------------------------ */
/* upload sink */

struct up_file {
  int opened, closed, ok;
  char name[HTTP_MULTIPART_MAX_FILENAME + 1];
  u32_t len_max;
  char data[1200];
  int len;
  err_t write_result;
};
static struct up_file up;

static void *
up_open(const char *filename, u32_t body_len_max, void *arg)
{
  LWIP_UNUSED_ARG(arg);
  up.opened++;
  strcpy(up.name, filename);
  up.len_max = body_len_max;
  return (arg == NULL) ? &up : NULL;
}

static err_t
up_write(void *handle, const u8_t *data, u16_t len)
{
  fail_unless(handle == &up);
  fail_unless(up.len + len <= (int)sizeof(up.data));
  memcpy(&up.data[up.len], data, len);
  up.len += len;
  return up.write_result;
}

static void
up_close(void *handle, u8_t ok)
{
  fail_unless(handle == &up);
  up.closed++;
  up.ok = ok;
}

static const struct httpd_upload_route up_routes[] = {
  { "*.bin", up_open, up_write, up_close, NULL },
  { "fail.txt", up_open, up_write, up_close, &up }  /* open() fails */
};

static const char up_hdrs[] = " HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=----b0";

/* run one upload request; body is passed as a chain of two pbufs */
static void
upload_run(const char *uri, const char *hdrs, const char *body, size_t len, char *resp)
{
  int conn;
  err_t err;
  memset(&up, 0, sizeof(up));
  httpd_upload_set_routes(up_routes, (u16_t)LWIP_ARRAYSIZE(up_routes));
  fail_unless(httpd_upload_init() == ERR_OK);
  err = post_begin(&conn, uri, hdrs, (int)len, resp);
  if (err == ERR_OK) {
    size_t half = len / 2;
    struct pbuf *p = make_pbuf(body, half);
    pbuf_cat(p, make_pbuf(body + half, len - half));
    fail_unless(httpd_post_receive_data(&conn, p) == ERR_OK);
    httpd_post_finished(&conn, resp, 64);
  }
}

static const char up_body[] =
  "------b0\r\n"
  "Content-Disposition: form-data; name=\"comment\"\r\n"
  "\r\n"
  "text field\r\n"
  "------b0\r\n"
  "Content-Disposition: form-data; name=\"file\"; filename=\"C:\\\\dir\\\\fw.bin\"\r\n"
  "Content-Type: application/octet-stream\r\n"
  "\r\n"
  "\x01\x02\r\n------b\r\n\x03\r\n"
  "------b0--\r\n";

START_TEST(test_upload_ok)
{
  char resp[64];
  LWIP_UNUSED_ARG(_i);

  upload_run("/upload", up_hdrs, up_body, sizeof(up_body) - 1, resp);
  fail_unless(!strcmp(resp, HTTPD_UPLOAD_URI_OK));
  fail_unless((up.opened == 1) && (up.closed == 1) && (up.ok == 1));
  /* path stripped from the client's file name */
  fail_unless(!strcmp(up.name, "fw.bin"));
  fail_unless(up.len_max == sizeof(up_body) - 1);
  fail_unless((up.len == 14) && !memcmp(up.data, "\x01\x02\r\n------b\r\n\x03", 14));

  /* file name from the URI wins */
  upload_run("/upload/image.bin?x=1", up_hdrs, up_body, sizeof(up_body) - 1, resp);
  fail_unless(!strcmp(resp, HTTPD_UPLOAD_URI_OK));
  fail_unless(!strcmp(up.name, "image.bin"));
}
END_TEST

START_TEST(test_upload_errors)
{
  char resp[64];
  char body[sizeof(up_body)];
  const char *hdrs_form = " HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded";
  const char *hdrs_noboundary = " HTTP/1.1\r\nContent-Type: multipart/form-data";
  LWIP_UNUSED_ARG(_i);

  /* not our URI */
  upload_run("/uploadx", up_hdrs, up_body, sizeof(up_body) - 1, resp);
  fail_unless(!strcmp(resp, HTTPD_POST_DISPATCH_URI_NO_SINK));
  /* not multipart */
  upload_run("/upload", hdrs_form, up_body, sizeof(up_body) - 1, resp);
  fail_unless(!strcmp(resp, HTTPD_UPLOAD_URI_UNSUPPORTED));
  /* no boundary */
  upload_run("/upload", hdrs_noboundary, up_body, sizeof(up_body) - 1, resp);
  fail_unless(!strcmp(resp, HTTPD_UPLOAD_URI_BAD_REQUEST));
  /* no writer for this name */
  upload_run("/upload/x.cfg", up_hdrs, up_body, sizeof(up_body) - 1, resp);
  fail_unless(!strcmp(resp, HTTPD_UPLOAD_URI_UNSUPPORTED));
  fail_unless(up.opened == 0);
  /* writer cannot open */
  upload_run("/upload/fail.txt", up_hdrs, up_body, sizeof(up_body) - 1, resp);
  fail_unless(!strcmp(resp, HTTPD_UPLOAD_URI_ERROR));
  fail_unless((up.opened == 1) && (up.closed == 0));
  /* body cut off: file closed as not ok */
  memcpy(body, up_body, sizeof(up_body));
  upload_run("/upload", up_hdrs, body, sizeof(up_body) - 12, resp);
  fail_unless(!strcmp(resp, HTTPD_UPLOAD_URI_BAD_REQUEST));
  fail_unless((up.opened == 1) && (up.closed == 1) && (up.ok == 0));
}
END_TEST

START_TEST(test_upload_write_error)
{
  char resp[64];
  int conn;
  struct pbuf *p;
  LWIP_UNUSED_ARG(_i);

  memset(&up, 0, sizeof(up));
  up.write_result = ERR_MEM;
  httpd_upload_set_routes(up_routes, (u16_t)LWIP_ARRAYSIZE(up_routes));
  fail_unless(httpd_upload_init() == ERR_OK);
  fail_unless(post_begin(&conn, "/upload", up_hdrs, (int)sizeof(up_body) - 1, resp) == ERR_OK);
  p = make_pbuf(up_body, sizeof(up_body) - 1);
  /* the rest of the body is still accepted (and dropped) */
  fail_unless(httpd_post_receive_data(&conn, p) == ERR_OK);
  httpd_post_finished(&conn, resp, sizeof(resp));
  fail_unless(!strcmp(resp, HTTPD_UPLOAD_URI_ERROR));
  fail_unless((up.opened == 1) && (up.closed == 1) && (up.ok == 0));
}
END_TEST

/* ------------------------------------------------------------------ */
/* fs providers and status pages */

static int prov_open_calls, prov_close_calls;

static int
prov_open(struct fs_file *file, const char *name)
{
  static const char page[] = "HTTP/1.0 200 OK\r\n\r\nprov";
  prov_open_calls++;
  if (strcmp(name, "/index.html") && strcmp(name, "/prov")) {
    return 0;
  }
  memset(file, 0, sizeof(*file));
  file->data = page;
  file->len = (int)sizeof(page) - 1;
  file->index = file->len;
  file->flags = FS_FILE_FLAGS_HEADER_INCLUDED;
  return 1;
}

static void
prov_close(struct fs_file *file)
{
  LWIP_UNUSED_ARG(file);
  prov_close_calls++;
}

static const struct httpd_status_page app_pages[] = {
  HTTPD_STATUS_PAGE("/503.html", "503 Service Unavailable", "busy, try later")
};

START_TEST(test_fs_status_pages)
{
  struct fs_file f;
  static struct httpd_status_page_table app_table;
  LWIP_UNUSED_ARG(_i);

  httpd_status_pages_init();

  /* default page */
  fail_unless(fs_open(&f, "/413.html") == ERR_OK);
  fail_unless(!strncmp(f.data, "HTTP/1.0 413 Payload Too Large\r\n", 32));
  fail_unless((f.flags & (FS_FILE_FLAGS_HEADER_INCLUDED | FS_FILE_FLAGS_CUSTOM)) ==
              (FS_FILE_FLAGS_HEADER_INCLUDED | FS_FILE_FLAGS_CUSTOM));
  fail_unless(f.len == (int)strlen(f.data));
  /* with LWIP_HTTPD_CORS, the page carries Access-Control-Allow-Origin once */
  fail_unless((strstr(f.data, "\r\nAccess-Control-Allow-Origin: ") != NULL) == LWIP_HTTPD_CORS);
  fail_unless(strstr(f.data, "\r\n\r\n") > strstr(f.data, "Connection: close"));
  fs_close(&f);
  fail_unless(fs_open(&f, "/204.html") == ERR_OK);
  fail_unless(!strncmp(f.data, "HTTP/1.0 204 No Content\r\n", 25));
  fail_unless((strstr(f.data, "\r\nAccess-Control-Allow-Origin: ") != NULL) == LWIP_HTTPD_CORS);
  fail_unless(f.len == (int)strlen(f.data));
  fs_close(&f);

  /* fsdata has "/404.html": it wins over the default page */
  fail_unless(fs_open(&f, "/404.html") == ERR_OK);
  fail_unless((f.flags & FS_FILE_FLAGS_CUSTOM) == 0);
  fs_close(&f);

  fail_unless(fs_open(&f, "/nothing.html") == ERR_VAL);

  /* an application table replaces a default page */
  app_table.pages = app_pages;
  app_table.count = (u16_t)LWIP_ARRAYSIZE(app_pages);
  fail_unless(httpd_status_pages_add(&app_table) == ERR_OK);
  fail_unless(httpd_status_pages_add(&app_table) == ERR_VAL);
  fail_unless(fs_open(&f, "/503.html") == ERR_OK);
  fail_unless(strstr(f.data, "busy, try later") != NULL);
  fs_close(&f);
}
END_TEST

START_TEST(test_fs_provider_before)
{
  struct fs_file f;
  static struct fs_custom_provider prov;
  LWIP_UNUSED_ARG(_i);

  prov_open_calls = 0;
  prov_close_calls = 0;
  memset(&prov, 0, sizeof(prov));
  prov.open = prov_open;
  prov.close = prov_close;
  fail_unless(fs_custom_provider_register(&prov, FS_CUSTOM_PROVIDER_BEFORE_FSDATA) == ERR_OK);
  fail_unless(fs_custom_provider_register(&prov, FS_CUSTOM_PROVIDER_AFTER_FSDATA) == ERR_VAL);

  /* asked before fsdata: replaces "/index.html" */
  fail_unless(fs_open(&f, "/index.html") == ERR_OK);
  fail_unless((f.flags & FS_FILE_FLAGS_CUSTOM) != 0);
  fail_unless(!strcmp(f.data + f.len - 4, "prov"));
  fs_close(&f);
  fail_unless(prov_close_calls == 1);

  /* fsdata file: provider asked, close not called */
  fail_unless(fs_open(&f, "/404.html") == ERR_OK);
  fs_close(&f);
  fail_unless(prov_close_calls == 1);
  fail_unless(prov_open_calls == 2);
}
END_TEST

/** Create the suite including all tests for this module */
Suite *
httpd_post_suite(void)
{
  testfunc tests[] = {
    TESTFUNC(test_multipart_boundary),
    TESTFUNC(test_multipart_first_part),
    TESTFUNC(test_multipart_every_split),
    TESTFUNC(test_multipart_long_header),
    TESTFUNC(test_multipart_errors),
    TESTFUNC(test_post_dispatch_conns),
    TESTFUNC(test_post_dispatch_reject_unknown),
    TESTFUNC(test_upload_ok),
    TESTFUNC(test_upload_errors),
    TESTFUNC(test_upload_write_error),
    TESTFUNC(test_fs_status_pages),
    TESTFUNC(test_fs_provider_before)
  };
  return create_suite("HTTPD_POST", tests, sizeof(tests)/sizeof(testfunc), httpd_post_setup, httpd_post_teardown);
}
