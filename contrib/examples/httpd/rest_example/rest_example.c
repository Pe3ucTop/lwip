/*
 * Copyright (c) 2026 Maksims Matjakubovs
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Maksims Matjakubovs <maksims.matjakubovs@gmail.com>
 */

/**
 * @file
 * Example for the httpd REST router (contrib/addons/httpd_rest).
 *
 * Routes:
 *   GET  /api/status               {"uptime_ms":...,"requests":...}
 *   GET  /api/echo?name=x          echoes the query parameters as JSON
 *   POST /api/echo                 echoes query and form body parameters
 *   GET  /api/items/<id>           prefix route, returns the id
 *
 * This file also shows how an application integrates the router into its
 * own httpd hooks (HTTP_REST_DEFINE_HTTPD_HOOKS == 0): it defines
 * httpd_headers_before_file_open(), httpd_post_*() and fs_*_custom() and
 * passes the requests on to the router. Therefore it cannot be combined
 * with other examples that define these hooks
 * (LWIP_HTTPD_EXAMPLE_CUSTOMFILES, LWIP_HTTPD_EXAMPLE_SIMPLEPOST).
 *
 * Test with e.g.:
 *   curl 'http://<ip>/api/echo?name=hello%20world&flag'
 *   curl -d 'a=1&b=x+y' 'http://<ip>/api/echo?q=1'
 *
 * Cross-origin requests (LWIP_HTTPD_SUPPORT_OPTIONS and LWIP_HTTPD_CORS):
 * - OPTIONS (preflight) for a REST path is answered per route by an OPTIONS
 *   hook: "Allow" and "Access-Control-Allow-Methods" list the methods of the
 *   route (kept in the route's user_ctx), unknown REST paths get 404, other
 *   paths get httpd's built-in answer.
 * - A request "Origin" found in REST_EX_CORS_ORIGINS is echoed together with
 *   "Access-Control-Allow-Credentials: true" (browsers reject "*" for
 *   requests with credentials), in the preflight answer and in the response
 *   of the request itself. Other origins get LWIP_HTTPD_CORS_ALLOW_ORIGIN
 *   without credentials (added by the router, never twice).
 *   curl -i -X OPTIONS -H 'Origin: http://localhost:8080' 'http://<ip>/api/echo'
 */

#include "lwip/opt.h"
#include "lwip/apps/httpd_opts.h"

#include "rest_example.h"

/** define LWIP_HTTPD_EXAMPLE_REST to 1 to enable this example */
#ifndef LWIP_HTTPD_EXAMPLE_REST
#define LWIP_HTTPD_EXAMPLE_REST 0
#endif

#if LWIP_HTTPD_EXAMPLE_REST

#if !LWIP_HTTPD_CUSTOM_FILES || !LWIP_HTTPD_DYNAMIC_FILE_READ || \
    !LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN || !LWIP_HTTPD_SUPPORT_POST || LWIP_HTTPD_FS_ASYNC_READ
#error "This example needs LWIP_HTTPD_CUSTOM_FILES, LWIP_HTTPD_DYNAMIC_FILE_READ, LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN and LWIP_HTTPD_SUPPORT_POST (without LWIP_HTTPD_FS_ASYNC_READ)"
#endif

#include "addons/httpd_rest/http_rest.h"

#if HTTP_REST_DEFINE_HTTPD_HOOKS
#error "This example defines the httpd hooks itself, set HTTP_REST_DEFINE_HTTPD_HOOKS to 0"
#endif

#include "lwip/def.h"
#include "lwip/sys.h"
#if LWIP_HTTPD_POST_DISPATCH
#include "lwip/apps/httpd_post_dispatch.h"
#endif /* LWIP_HTTPD_POST_DISPATCH */

#include <string.h>

static u32_t rest_ex_requests;

/** Methods of a route, kept in its user_ctx to answer OPTIONS per route */
struct rest_ex_route_info {
  const char *methods;
};

static struct rest_ex_route_info rest_ex_get = { "GET" };
static struct rest_ex_route_info rest_ex_get_post = { "GET, POST" };

/** REST paths: OPTIONS for an unknown path below this prefix gets 404 */
#define REST_EX_PREFIX "/api/"

#if LWIP_HTTPD_CORS
/** Origins that may send requests with credentials (comma-separated string
 * literals) */
#ifndef REST_EX_CORS_ORIGINS
#define REST_EX_CORS_ORIGINS "http://localhost:8080", "http://127.0.0.1:8080"
#endif

static const char *const rest_ex_cors_origins[] = { REST_EX_CORS_ORIGINS };

/** Allowed origin of the request currently handled (NULL: none or not
 * allowed). Handlers run synchronously from the httpd hooks below. */
static const char *rest_ex_origin;

/** Return the allow-list entry equal to the request "Origin", or NULL */
static const char *
rest_ex_find_origin(const char *headers, u16_t headers_len)
{
  const char *hdr;
  const char *end;
  size_t i, len;

  if ((headers_len >= 7) && (lwip_strnicmp(headers, "Origin:", 7) == 0)) {
    hdr = headers;
  } else {
    hdr = lwip_strnistr(headers, "\r\nOrigin:", headers_len);
    if (hdr == NULL) {
      return NULL;
    }
    hdr += 2;
  }
  hdr += 7;
  while (*hdr == ' ') {
    hdr++;
  }
  /* the request headers end with an empty line */
  end = lwip_strnstr(hdr, "\r\n", headers_len - (u16_t)(hdr - headers));
  if (end == NULL) {
    return NULL;
  }
  len = (size_t)(end - hdr);
  for (i = 0; i < LWIP_ARRAYSIZE(rest_ex_cors_origins); i++) {
    if ((strlen(rest_ex_cors_origins[i]) == len) &&
        (memcmp(rest_ex_cors_origins[i], hdr, len) == 0)) {
      return rest_ex_cors_origins[i];
    }
  }
  return NULL;
}

/** Echo an allowed origin with credentials; otherwise the router adds
 * LWIP_HTTPD_CORS_ALLOW_ORIGIN */
static void
rest_ex_cors(http_rest_req_t *req)
{
  if (rest_ex_origin != NULL) {
    http_rest_resp_add_header(req, "Access-Control-Allow-Origin", rest_ex_origin);
    http_rest_resp_add_header(req, "Access-Control-Allow-Credentials", "true");
    http_rest_resp_add_header(req, "Vary", "Origin");
  }
}
#else /* LWIP_HTTPD_CORS */
#define rest_ex_cors(req) LWIP_UNUSED_ARG(req)
#endif /* LWIP_HTTPD_CORS */

/** Small helper to build a JSON body without snprintf */
struct rest_ex_buf {
  char data[256];
  size_t len;
  u8_t overflow;
};

static void
rest_ex_put(struct rest_ex_buf *b, const char *str, size_t len)
{
  if (len > sizeof(b->data) - b->len) {
    b->overflow = 1;
    return;
  }
  MEMCPY(&b->data[b->len], str, len);
  b->len += len;
}

static void
rest_ex_puts(struct rest_ex_buf *b, const char *str)
{
  rest_ex_put(b, str, strlen(str));
}

/** Append a JSON string literal (escapes '"', '\\' and control characters) */
static void
rest_ex_put_json_str(struct rest_ex_buf *b, const char *str, size_t len)
{
  static const char hex[] = "0123456789abcdef";
  size_t i;

  rest_ex_puts(b, "\"");
  for (i = 0; i < len; i++) {
    unsigned char c = (unsigned char)str[i];
    if ((c == '"') || (c == '\\')) {
      char esc[2];
      esc[0] = '\\';
      esc[1] = (char)c;
      rest_ex_put(b, esc, 2);
    } else if (c < 0x20) {
      char esc[6];
      esc[0] = '\\';
      esc[1] = 'u';
      esc[2] = '0';
      esc[3] = '0';
      esc[4] = hex[c >> 4];
      esc[5] = hex[c & 0x0f];
      rest_ex_put(b, esc, 6);
    } else {
      rest_ex_put(b, (const char *)&str[i], 1);
    }
  }
  rest_ex_puts(b, "\"");
}

static void
rest_ex_put_kv(struct rest_ex_buf *b, const http_rest_kv_t *kv, size_t count)
{
  size_t i;

  rest_ex_puts(b, "{");
  for (i = 0; i < count; i++) {
    if (i > 0) {
      rest_ex_puts(b, ",");
    }
    rest_ex_put_json_str(b, kv[i].key, strlen(kv[i].key));
    rest_ex_puts(b, ":");
    if (kv[i].value == NULL) {
      rest_ex_puts(b, "null");
    } else {
      rest_ex_put_json_str(b, kv[i].value, kv[i].value_len);
    }
  }
  rest_ex_puts(b, "}");
}

static void
rest_ex_send_json(http_rest_req_t *req, struct rest_ex_buf *b)
{
  if (b->overflow) {
    http_rest_resp_send_status(req, 500, NULL);
    return;
  }
  rest_ex_cors(req);
  http_rest_resp_add_header(req, "Cache-Control", "no-store");
  http_rest_resp_send(req, 200, "application/json", b->data, b->len);
}

/* GET /api/status */
static void
rest_ex_status(http_rest_req_t *req)
{
  struct rest_ex_buf b;
  char num[12];

  if (req->method != HTTP_REST_METHOD_GET) {
    rest_ex_cors(req);
    http_rest_resp_add_header(req, "Allow", "GET");
    http_rest_resp_send_status(req, 405, NULL);
    return;
  }
  b.len = 0;
  b.overflow = 0;
  rest_ex_puts(&b, "{\"uptime_ms\":");
  lwip_itoa(num, sizeof(num), (int)(sys_now() & 0x7fffffffUL));
  rest_ex_puts(&b, num);
  rest_ex_puts(&b, ",\"requests\":");
  lwip_itoa(num, sizeof(num), (int)(rest_ex_requests & 0x7fffffffUL));
  rest_ex_puts(&b, num);
  rest_ex_puts(&b, "}");
  rest_ex_send_json(req, &b);
}

/* GET or POST /api/echo */
static void
rest_ex_echo(http_rest_req_t *req)
{
  struct rest_ex_buf b;

  b.len = 0;
  b.overflow = 0;
  rest_ex_puts(&b, "{\"method\":");
  rest_ex_puts(&b, (req->method == HTTP_REST_METHOD_POST) ? "\"POST\"" : "\"GET\"");
  rest_ex_puts(&b, ",\"query\":");
  rest_ex_put_kv(&b, req->query, req->query_count);
  if (req->method == HTTP_REST_METHOD_POST) {
    http_rest_kv_t form[8];
    size_t count;
    if (http_rest_body_parse_form(req, form, LWIP_ARRAYSIZE(form), &count) != ERR_OK) {
      http_rest_resp_send_status(req, 400, NULL);
      return;
    }
    rest_ex_puts(&b, ",\"form\":");
    rest_ex_put_kv(&b, form, count);
  }
  rest_ex_puts(&b, "}");
  rest_ex_send_json(req, &b);
}

/* GET /api/items/<id>: chunked response */
static void
rest_ex_items(http_rest_req_t *req)
{
  const char *id = req->uri + strlen("/api/items/");

  rest_ex_cors(req);
  if (*id == '\0') {
    http_rest_resp_send_status(req, 404, NULL);
    return;
  }
  http_rest_resp_begin(req, 200, "text/plain");
  http_rest_resp_send_str(req, "item ");
  http_rest_resp_send_str(req, id);
  http_rest_resp_send_str(req, "\n");
  http_rest_resp_finish(req);
}

static const http_rest_route_t rest_ex_routes[] = {
  { "/api/status", HTTP_REST_MATCH_EXACT,  rest_ex_status, &rest_ex_get },
  { "/api/echo",   HTTP_REST_MATCH_EXACT,  rest_ex_echo,   &rest_ex_get_post },
  { "/api/items/", HTTP_REST_MATCH_PREFIX, rest_ex_items,  &rest_ex_get }
};

#if LWIP_HTTPD_SUPPORT_OPTIONS
/** Bounded string builder for the OPTIONS answer */
struct rest_ex_out {
  char *buf;
  u16_t len;
  u16_t max;
  u8_t overflow;
};

static void
rest_ex_out_puts(struct rest_ex_out *o, const char *str)
{
  size_t len = strlen(str);
  if (len > (size_t)(o->max - o->len)) {
    o->overflow = 1;
    return;
  }
  MEMCPY(&o->buf[o->len], str, len);
  o->len = (u16_t)(o->len + len);
}

/* OPTIONS hook (see httpd_set_options_hook()): answer per route */
static u16_t
rest_ex_options(const char *uri, const char *headers, u16_t headers_len,
                char *rsp, u16_t rsp_max)
{
  const http_rest_route_t *route;
  const char *methods = "GET, POST";
  struct rest_ex_out o;
#if LWIP_HTTPD_CORS
  const char *origin;
#else /* LWIP_HTTPD_CORS */
  LWIP_UNUSED_ARG(headers);
  LWIP_UNUSED_ARG(headers_len);
#endif /* LWIP_HTTPD_CORS */

  if (strncmp(uri, REST_EX_PREFIX, strlen(REST_EX_PREFIX)) != 0) {
    /* not a REST path: httpd's built-in answer */
    return 0;
  }
  o.buf = rsp;
  o.len = 0;
  o.max = rsp_max;
  o.overflow = 0;
  route = http_rest_route_find(uri);
  if (route == NULL) {
    rest_ex_out_puts(&o, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    return o.overflow ? 0 : o.len;
  }
  if (route->user_ctx != NULL) {
    methods = ((const struct rest_ex_route_info *)route->user_ctx)->methods;
  }
  rest_ex_out_puts(&o, "HTTP/1.1 204 No Content\r\nAllow: ");
  rest_ex_out_puts(&o, methods);
  rest_ex_out_puts(&o, ", OPTIONS\r\n");
#if LWIP_HTTPD_CORS
  origin = rest_ex_find_origin(headers, headers_len);
  rest_ex_out_puts(&o, "Access-Control-Allow-Origin: ");
  if (origin != NULL) {
    rest_ex_out_puts(&o, origin);
    rest_ex_out_puts(&o, "\r\nAccess-Control-Allow-Credentials: true\r\nVary: Origin\r\n");
  } else {
    rest_ex_out_puts(&o, LWIP_HTTPD_CORS_ALLOW_ORIGIN "\r\n");
  }
  rest_ex_out_puts(&o, "Access-Control-Allow-Methods: ");
  rest_ex_out_puts(&o, methods);
  rest_ex_out_puts(&o, ", OPTIONS\r\n"
                   "Access-Control-Allow-Headers: " LWIP_HTTPD_CORS_ALLOW_HEADERS "\r\n"
                   "Access-Control-Max-Age: 600\r\n");
#endif /* LWIP_HTTPD_CORS */
  rest_ex_out_puts(&o, "Content-Length: 0\r\n\r\n");
  /* answer too long for LWIP_HTTPD_OPTIONS_RSP_LEN: built-in answer */
  return o.overflow ? 0 : o.len;
}
#endif /* LWIP_HTTPD_SUPPORT_OPTIONS */

/* httpd hooks: an application with own hooks would try its own handlers
   first and pass the rest on to the router like this */

void *
httpd_headers_before_file_open(const char *headers, u16_t headers_len, const char *uri,
                               char *replace_uri, u16_t replace_uri_len)
{
#if LWIP_HTTPD_CORS
  rest_ex_origin = rest_ex_find_origin(headers, headers_len);
#else /* LWIP_HTTPD_CORS */
  LWIP_UNUSED_ARG(headers);
  LWIP_UNUSED_ARG(headers_len);
#endif /* LWIP_HTTPD_CORS */
  if (http_rest_headers_hook(uri, replace_uri, replace_uri_len)) {
    rest_ex_requests++;
  }
#if LWIP_HTTPD_CORS
  rest_ex_origin = NULL;
#endif /* LWIP_HTTPD_CORS */
  return NULL;
}

/* POST: the handler runs when the body is complete, so the allowed origin
   is remembered per connection */
#if LWIP_HTTPD_CORS
static struct {
  void *connection;
  const char *origin;
} rest_ex_post_origins[HTTP_REST_MAX_SESSIONS];
#endif /* LWIP_HTTPD_CORS */

static err_t
rest_ex_post_begin(void *connection, const char *uri, const char *http_request,
                   u16_t http_request_len, int content_len, char *response_uri,
                   u16_t response_uri_len)
{
  err_t err;
#if LWIP_HTTPD_CORS
  const char *origin = rest_ex_find_origin(http_request, http_request_len);
  size_t i;
#else /* LWIP_HTTPD_CORS */
  LWIP_UNUSED_ARG(http_request);
  LWIP_UNUSED_ARG(http_request_len);
#endif /* LWIP_HTTPD_CORS */

  rest_ex_requests++;
  err = http_rest_post_begin(connection, uri, content_len, response_uri, response_uri_len);
#if LWIP_HTTPD_CORS
  if ((err == ERR_OK) && (origin != NULL)) {
    for (i = 0; i < LWIP_ARRAYSIZE(rest_ex_post_origins); i++) {
      if (rest_ex_post_origins[i].connection == NULL) {
        rest_ex_post_origins[i].connection = connection;
        rest_ex_post_origins[i].origin = origin;
        break;
      }
    }
  }
#endif /* LWIP_HTTPD_CORS */
  return err;
}

static void
rest_ex_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
#if LWIP_HTTPD_CORS
  size_t i;
  for (i = 0; i < LWIP_ARRAYSIZE(rest_ex_post_origins); i++) {
    if (rest_ex_post_origins[i].connection == connection) {
      rest_ex_origin = rest_ex_post_origins[i].origin;
      rest_ex_post_origins[i].connection = NULL;
      break;
    }
  }
#endif /* LWIP_HTTPD_CORS */
  http_rest_post_finished(connection, response_uri, response_uri_len);
#if LWIP_HTTPD_CORS
  rest_ex_origin = NULL;
#endif /* LWIP_HTTPD_CORS */
}

#if LWIP_HTTPD_POST_DISPATCH
/* with LWIP_HTTPD_POST_DISPATCH, httpd owns httpd_post_*(): this sink is
   registered before http_rest_init() registers the router's own sink, so it
   is asked first and sees the request headers */
static u8_t
rest_ex_sink_match(const char *uri, const char *http_request, u16_t http_request_len)
{
  LWIP_UNUSED_ARG(http_request);
  LWIP_UNUSED_ARG(http_request_len);
  return http_rest_post_match(uri);
}

static err_t
rest_ex_sink_begin(void *connection, const char *uri, const char *http_request,
                   u16_t http_request_len, int content_len, char *response_uri,
                   u16_t response_uri_len, u8_t *post_auto_wnd)
{
  LWIP_UNUSED_ARG(post_auto_wnd);
  return rest_ex_post_begin(connection, uri, http_request, http_request_len, content_len,
                            response_uri, response_uri_len);
}

static const struct httpd_post_sink rest_ex_sink = {
  "rest_ex", rest_ex_sink_match, rest_ex_sink_begin, http_rest_post_receive, rest_ex_post_finished
};
#endif /* LWIP_HTTPD_POST_DISPATCH */

#if !LWIP_HTTPD_POST_DISPATCH
/* (with LWIP_HTTPD_POST_DISPATCH, httpd owns these, see rest_ex_sink) */
err_t
httpd_post_begin(void *connection, const char *uri, const char *http_request,
                 u16_t http_request_len, int content_len, char *response_uri,
                 u16_t response_uri_len, u8_t *post_auto_wnd)
{
  LWIP_UNUSED_ARG(post_auto_wnd);
  return rest_ex_post_begin(connection, uri, http_request, http_request_len, content_len,
                            response_uri, response_uri_len);
}

err_t
httpd_post_receive_data(void *connection, struct pbuf *p)
{
  return http_rest_post_receive(connection, p);
}

void
httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
  rest_ex_post_finished(connection, response_uri, response_uri_len);
}
#endif /* !LWIP_HTTPD_POST_DISPATCH */

#if !LWIP_HTTPD_CUSTOM_FILE_PROVIDERS
/* (with LWIP_HTTPD_CUSTOM_FILE_PROVIDERS, fs.c owns these and
   http_rest_init() registers the router as file provider) */
int
fs_open_custom(struct fs_file *file, const char *name)
{
  return http_rest_fs_open(file, name);
}

int
fs_read_custom(struct fs_file *file, char *buffer, int count)
{
  if (http_rest_fs_is_own(file)) {
    return http_rest_fs_read(file, buffer, count);
  }
  return FS_READ_EOF;
}

void
fs_close_custom(struct fs_file *file)
{
  (void)http_rest_fs_close(file);
}
#endif /* !LWIP_HTTPD_CUSTOM_FILE_PROVIDERS */

/** Initialize the example: call after httpd_init() */
void
rest_ex_init(void)
{
  err_t err;

#if LWIP_HTTPD_POST_DISPATCH
  err = httpd_post_sink_register(&rest_ex_sink);
  LWIP_ASSERT("POST sink not registered", err == ERR_OK);
#endif /* LWIP_HTTPD_POST_DISPATCH */
  http_rest_init();
  err = http_rest_register_routes(rest_ex_routes, LWIP_ARRAYSIZE(rest_ex_routes));
  LWIP_ASSERT("invalid route table", err == ERR_OK);
  LWIP_UNUSED_ARG(err);
#if LWIP_HTTPD_SUPPORT_OPTIONS
  httpd_set_options_hook(rest_ex_options);
#endif /* LWIP_HTTPD_SUPPORT_OPTIONS */
}

#endif /* LWIP_HTTPD_EXAMPLE_REST */
