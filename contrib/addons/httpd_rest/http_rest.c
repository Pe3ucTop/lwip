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
 * REST router for the lwIP httpd.
 *
 * Request flow (all in the httpd thread):
 * - GET: http_rest_headers_hook() allocates a session, matches the route,
 *   runs the handler and replaces the URI by
 *   HTTP_REST_VIRTUAL_PREFIX "<slot>-<generation>". httpd then opens that
 *   name: http_rest_fs_open() checks slot and generation,
 *   http_rest_fs_read() hands out the buffered response and
 *   http_rest_fs_close() frees the session.
 * - POST: http_rest_post_begin() allocates the session, the body is
 *   collected by http_rest_post_receive(), http_rest_post_finished() runs the
 *   handler and returns the virtual file name; then as for GET.
 *   If the connection is closed before the body is complete, httpd calls
 *   httpd_post_finished() anyway: the router then frees the session without
 *   calling the handler.
 *
 * The response is read through fs_read_custom() (file->data == NULL), so
 * httpd copies it into its own buffer before it is sent and the session can
 * be reused as soon as the file is closed.
 */

#include "http_rest.h"

#include "lwip/def.h"
#include "lwip/debug.h"
#include "lwip/sys.h"

#include <stddef.h>
#include <string.h>

/* compiled only if httpd provides what the router needs */
#if LWIP_HTTPD_CUSTOM_FILES && LWIP_HTTPD_DYNAMIC_FILE_READ && \
    (LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN || LWIP_HTTPD_SUPPORT_POST)

#if HTTP_REST_MAX_SESSIONS < 1 || HTTP_REST_MAX_SESSIONS > 99
#error "HTTP_REST_MAX_SESSIONS must be 1..99"
#endif

/** Name of the virtual file that answers "503 Service Unavailable" when no
 * session is free */
#define HTTP_REST_BUSY_NAME   HTTP_REST_VIRTUAL_PREFIX "busy"
/** Name that is never opened by the router: httpd serves its 404 page */
#define HTTP_REST_NONE_NAME   HTTP_REST_VIRTUAL_PREFIX "none"
#define HTTP_REST_PREFIX_LEN  (sizeof(HTTP_REST_VIRTUAL_PREFIX) - 1)
/* prefix + "99-65535" + NUL */
#define HTTP_REST_VNAME_LEN   (HTTP_REST_PREFIX_LEN + 9)

static const char http_rest_busy_response[] =
  "HTTP/1.1 503 Service Unavailable\r\n"
  "Content-Type: text/plain\r\n"
  "Content-Length: 5\r\n"
  "Retry-After: 1\r\n"
  "Connection: close\r\n"
  "\r\n"
  "busy\n";

typedef enum {
  HTTP_REST_SESS_FREE = 0,
  /** POST: waiting for the body */
  HTTP_REST_SESS_BODY,
  /** response complete, waiting for httpd to open it */
  HTTP_REST_SESS_READY,
  /** response opened by httpd, freed by fs_close */
  HTTP_REST_SESS_OPEN
} http_rest_sess_state_t;

typedef struct http_rest_session {
  http_rest_sess_state_t state;
  /** incremented on every allocation, part of the virtual file name */
  u16_t generation;
  /** sys_now() of the last state change (for reclaiming stale sessions) */
  u32_t time;
  /** POST: httpd connection handle */
  void *connection;
  /** fs_file handle while open */
  struct fs_file *file;
  /** POST: Content-Length and bytes received so far */
  size_t body_expected;
  size_t body_received;
  /** set by http_rest_body_parse_form() (the body is decoded in place) */
  u8_t body_parsed;
  /** response state */
  u8_t resp_chunked;
  u8_t resp_done;
  u8_t resp_overflow;
  size_t resp_len;
  size_t extra_hdr_len;
  http_rest_req_t req;
  /** path and query, split by a NUL */
  char uri_buf[HTTP_REST_MAX_URI_LEN + 1];
  /** +1: NUL after the body (and room for the parser's terminator) */
  u8_t body_buf[HTTP_REST_MAX_BODY_SIZE + 1];
  char extra_hdr[HTTP_REST_EXTRA_HDR_SIZE];
  char resp_buf[HTTP_REST_RESP_BUF_SIZE];
} http_rest_session_t;

static http_rest_session_t http_rest_sessions[HTTP_REST_MAX_SESSIONS];
static u16_t http_rest_generation;

static const http_rest_route_t *http_rest_routes;
static size_t http_rest_route_count;

/*-------------------------------------------------------------------------*/
/* Sessions                                                                */
/*-------------------------------------------------------------------------*/

static void
http_rest_sess_free(http_rest_session_t *s)
{
  s->state = HTTP_REST_SESS_FREE;
  s->connection = NULL;
  s->file = NULL;
}

/** Free sessions that wait for a body or for fs_open for too long */
static void
http_rest_sess_reclaim(void)
{
  u32_t now = sys_now();
  size_t i;

  for (i = 0; i < HTTP_REST_MAX_SESSIONS; i++) {
    http_rest_session_t *s = &http_rest_sessions[i];
    if (((s->state == HTTP_REST_SESS_BODY) || (s->state == HTTP_REST_SESS_READY)) &&
        ((u32_t)(now - s->time) > (u32_t)HTTP_REST_STALE_MS)) {
      LWIP_DEBUGF(HTTP_REST_DEBUG | LWIP_DBG_LEVEL_WARNING,
                  ("http_rest: reclaiming stale session %d\n", (int)i));
      http_rest_sess_free(s);
    }
  }
}

static http_rest_session_t *
http_rest_sess_alloc(void)
{
  size_t i;

  http_rest_sess_reclaim();
  for (i = 0; i < HTTP_REST_MAX_SESSIONS; i++) {
    http_rest_session_t *s = &http_rest_sessions[i];
    if (s->state == HTTP_REST_SESS_FREE) {
      /* the buffers need no clearing */
      memset(s, 0, offsetof(http_rest_session_t, uri_buf));
      s->state = HTTP_REST_SESS_BODY;
      s->generation = ++http_rest_generation;
      s->time = sys_now();
      s->req.session = s;
      return s;
    }
  }
  LWIP_DEBUGF(HTTP_REST_DEBUG | LWIP_DBG_LEVEL_WARNING, ("http_rest: no free session\n"));
  return NULL;
}

static http_rest_session_t *
http_rest_sess_from_req(const http_rest_req_t *req)
{
  if (req == NULL) {
    return NULL;
  }
  return (http_rest_session_t *)req->session;
}

/** Copy a NUL-terminated string, returns 0 if it does not fit */
static u8_t
http_rest_strcpy(char *dst, size_t dst_size, const char *src)
{
  size_t len = strlen(src);
  if (len >= dst_size) {
    return 0;
  }
  MEMCPY(dst, src, len + 1);
  return 1;
}

/** Write the virtual file name of a session to buf */
static u8_t
http_rest_sess_name(const http_rest_session_t *s, char *buf, size_t buf_size)
{
  char num[6];
  size_t len;

  if (buf_size < HTTP_REST_VNAME_LEN) {
    return 0;
  }
  MEMCPY(buf, HTTP_REST_VIRTUAL_PREFIX, HTTP_REST_PREFIX_LEN);
  len = HTTP_REST_PREFIX_LEN;
  lwip_itoa(num, sizeof(num), (int)(s - http_rest_sessions));
  MEMCPY(&buf[len], num, strlen(num));
  len += strlen(num);
  buf[len++] = '-';
  lwip_itoa(num, sizeof(num), (int)s->generation);
  MEMCPY(&buf[len], num, strlen(num) + 1);
  return 1;
}

/** Parse a decimal number of at most 5 digits, returns -1 on error */
static long
http_rest_parse_num(const char *str, const char **end)
{
  long val = 0;
  int digits = 0;

  while ((*str >= '0') && (*str <= '9') && (digits < 5)) {
    val = val * 10 + (*str - '0');
    str++;
    digits++;
  }
  *end = str;
  return (digits > 0) ? val : -1;
}

/** Find the session that belongs to a virtual file name */
static http_rest_session_t *
http_rest_sess_by_name(const char *name)
{
  const char *p = name + HTTP_REST_PREFIX_LEN;
  long slot, generation;

  slot = http_rest_parse_num(p, &p);
  if ((slot < 0) || (slot >= HTTP_REST_MAX_SESSIONS) || (*p != '-')) {
    return NULL;
  }
  generation = http_rest_parse_num(p + 1, &p);
  if ((generation < 0) || (*p != '\0')) {
    return NULL;
  }
  if ((http_rest_sessions[slot].state != HTTP_REST_SESS_READY) ||
      (http_rest_sessions[slot].generation != (u16_t)generation)) {
    return NULL;
  }
  return &http_rest_sessions[slot];
}

/*-------------------------------------------------------------------------*/
/* Routing                                                                 */
/*-------------------------------------------------------------------------*/

/** Length of the path part of a URI (up to '?' or the end) */
static size_t
http_rest_path_len(const char *uri)
{
  const char *q = strchr(uri, '?');
  return (q != NULL) ? (size_t)(q - uri) : strlen(uri);
}

static const http_rest_route_t *
http_rest_route_match(const char *path, size_t path_len)
{
  size_t i;

  for (i = 0; i < http_rest_route_count; i++) {
    const http_rest_route_t *r = &http_rest_routes[i];
    size_t len = strlen(r->path);
    if (r->match == HTTP_REST_MATCH_PREFIX) {
      if ((len <= path_len) && (memcmp(r->path, path, len) == 0)) {
        return r;
      }
    } else if ((len == path_len) && (memcmp(r->path, path, len) == 0)) {
      return r;
    }
  }
  return NULL;
}

/** Answer a request with an empty-bodied error response (status line,
 * standard headers, no custom headers) */
static void
http_rest_resp_error(http_rest_session_t *s, u16_t status)
{
  s->extra_hdr_len = 0;
  if (http_rest_resp_send_status(&s->req, status, NULL) != ERR_OK) {
    /* cannot happen with a sane HTTP_REST_RESP_BUF_SIZE */
    LWIP_ASSERT("http_rest: error response does not fit", 0);
  }
}

/**
 * Prepare a session for a request whose path matched route: copy the URI,
 * split off and parse the query.
 * @return 1 on success, 0 if an error response was set instead
 */
static u8_t
http_rest_sess_setup(http_rest_session_t *s, const http_rest_route_t *route,
                     http_rest_method_t method, const char *uri)
{
  size_t path_len;
  char *query;
  err_t err;

  s->req.method = method;
  s->req.uri = s->uri_buf;
  s->req.user_ctx = route->user_ctx;
  if (!http_rest_strcpy(s->uri_buf, sizeof(s->uri_buf), uri)) {
    s->uri_buf[0] = '\0';
    http_rest_resp_error(s, 414);
    return 0;
  }
  path_len = http_rest_path_len(s->uri_buf);
  if (s->uri_buf[path_len] == '?') {
    s->uri_buf[path_len] = '\0';
    query = &s->uri_buf[path_len + 1];
    /* the query ends with the NUL of uri_buf: len + 1 bytes are writable */
    err = http_rest_query_parse(query, strlen(query), s->req.query,
                                HTTP_REST_MAX_KV_PAIRS, &s->req.query_count);
    if (err != ERR_OK) {
      LWIP_DEBUGF(HTTP_REST_DEBUG, ("http_rest: bad query (%d)\n", (int)err));
      s->req.query_count = 0;
      http_rest_resp_error(s, 400);
      return 0;
    }
  }
  return 1;
}

/** Run the handler and turn a missing or truncated response into a 500 */
static void
http_rest_sess_dispatch(http_rest_session_t *s, const http_rest_route_t *route)
{
  route->handler(&s->req);
  if (!s->resp_done || s->resp_overflow) {
    LWIP_DEBUGF(HTTP_REST_DEBUG | LWIP_DBG_LEVEL_WARNING,
                ("http_rest: handler for %s left no complete response\n", s->uri_buf));
    http_rest_resp_error(s, 500);
  }
}

/** Mark the session's response as ready and return its virtual file name */
static void
http_rest_sess_ready(http_rest_session_t *s, char *uri, u16_t uri_len)
{
  s->state = HTTP_REST_SESS_READY;
  s->time = sys_now();
  if (!http_rest_sess_name(s, uri, uri_len)) {
    /* prevented by the compile-time checks of the URI buffer sizes */
    http_rest_sess_free(s);
    uri[0] = '\0';
  }
}

/*-------------------------------------------------------------------------*/
/* Setup                                                                   */
/*-------------------------------------------------------------------------*/

/**
 * Initialize the REST router (call once, before httpd receives requests).
 */
void
http_rest_init(void)
{
  size_t i;

  for (i = 0; i < HTTP_REST_MAX_SESSIONS; i++) {
    http_rest_sess_free(&http_rest_sessions[i]);
  }
}

/**
 * Set the route table. The table is used by reference and must stay valid.
 *
 * @param routes route table (NULL to remove all routes)
 * @param count number of entries in routes
 * @return ERR_OK, or ERR_ARG if an entry has no path or no handler
 *         (the previous table stays active then)
 */
err_t
http_rest_register_routes(const http_rest_route_t *routes, size_t count)
{
  size_t i;

  if ((routes == NULL) && (count != 0)) {
    return ERR_ARG;
  }
  for (i = 0; i < count; i++) {
    if ((routes[i].path == NULL) || (routes[i].handler == NULL) ||
        ((routes[i].match != HTTP_REST_MATCH_EXACT) &&
         (routes[i].match != HTTP_REST_MATCH_PREFIX))) {
      return ERR_ARG;
    }
  }
  http_rest_routes = routes;
  http_rest_route_count = count;
  return ERR_OK;
}

/*-------------------------------------------------------------------------*/
/* Request access                                                          */
/*-------------------------------------------------------------------------*/

/**
 * Get the decoded value of a query parameter (first match, case-sensitive).
 * @return the value, or NULL if the key is not present or has no value
 *         ("?flag"); use http_rest_query_has() to tell these apart
 */
const char *
http_rest_query_get(const http_rest_req_t *req, const char *key)
{
  const http_rest_kv_t *kv;

  if (req == NULL) {
    return NULL;
  }
  kv = http_rest_kv_find(req->query, req->query_count, key);
  return (kv != NULL) ? kv->value : NULL;
}

/**
 * Check whether a query parameter is present (with or without value).
 * @return 1 if present, 0 if not
 */
u8_t
http_rest_query_has(const http_rest_req_t *req, const char *key)
{
  if (req == NULL) {
    return 0;
  }
  return (http_rest_kv_find(req->query, req->query_count, key) != NULL) ? 1 : 0;
}

/**
 * Parse a POST body of type application/x-www-form-urlencoded.
 * The body is decoded in place (req->body is modified), so this can be
 * called only once per request.
 *
 * @param req request
 * @param kv storage for the pairs (pointers point into the body)
 * @param kv_max number of elements in kv
 * @param kv_count returns the number of pairs
 * @return see http_rest_query_parse(); ERR_ARG without a body,
 *         ERR_ALREADY if the body was parsed before
 */
err_t
http_rest_body_parse_form(http_rest_req_t *req, http_rest_kv_t *kv,
                          size_t kv_max, size_t *kv_count)
{
  http_rest_session_t *s = http_rest_sess_from_req(req);

  if (kv_count != NULL) {
    *kv_count = 0;
  }
  if ((s == NULL) || (req->body == NULL) || (kv_count == NULL)) {
    return ERR_ARG;
  }
  if (s->body_parsed) {
    return ERR_ALREADY;
  }
  s->body_parsed = 1;
  /* body_buf has one byte more than the body */
  return http_rest_query_parse((char *)s->body_buf, s->body_received,
                               kv, kv_max, kv_count);
}

/*-------------------------------------------------------------------------*/
/* Response                                                                */
/*-------------------------------------------------------------------------*/

static const char *
http_rest_reason(u16_t status)
{
  switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 415: return "Unsupported Media Type";
    case 422: return "Unprocessable Content";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return ""; /* the reason phrase may be empty (RFC 9112) */
  }
}

/** Check that a string contains no CR, LF or other control characters */
static u8_t
http_rest_is_text(const char *str)
{
  for (; *str != '\0'; str++) {
    if ((((unsigned char)*str < 0x20) && (*str != '\t')) || (*str == 0x7f)) {
      return 0;
    }
  }
  return 1;
}

/** Check that a string is a valid header field name (RFC 9110 token) */
static u8_t
http_rest_is_token(const char *str)
{
  if (*str == '\0') {
    return 0;
  }
  for (; *str != '\0'; str++) {
    if (((unsigned char)*str <= 0x20) || ((unsigned char)*str >= 0x7f) ||
        (strchr("\"(),/:;<=>?@[\\]{}", *str) != NULL)) {
      return 0;
    }
  }
  return 1;
}

/** Append data to the response, sets resp_overflow if it does not fit */
static err_t
http_rest_resp_append(http_rest_session_t *s, const void *data, size_t len)
{
  if (s->resp_overflow || (len > sizeof(s->resp_buf) - s->resp_len)) {
    s->resp_overflow = 1;
    return ERR_BUF;
  }
  if (len > 0) {
    MEMCPY(&s->resp_buf[s->resp_len], data, len);
    s->resp_len += len;
  }
  return ERR_OK;
}

static err_t
http_rest_resp_append_str(http_rest_session_t *s, const char *str)
{
  return http_rest_resp_append(s, str, strlen(str));
}

/** Append a non-negative number in decimal (base 10) or hex (base 16) */
static err_t
http_rest_resp_append_num(http_rest_session_t *s, size_t num, unsigned base)
{
  char buf[sizeof(size_t) * 3 + 1];
  size_t pos = sizeof(buf);

  do {
    buf[--pos] = "0123456789ABCDEF"[num % base];
    num /= base;
  } while (num != 0);
  return http_rest_resp_append(s, &buf[pos], sizeof(buf) - pos);
}

/**
 * Start a new response: status line, Content-Type, custom headers.
 * Discards anything produced before for this request.
 */
static err_t
http_rest_resp_start(http_rest_session_t *s, u16_t status, const char *reason,
                     const char *content_type)
{
  if ((status < 100) || (status > 999)) {
    return ERR_ARG;
  }
  if (reason == NULL) {
    reason = http_rest_reason(status);
  }
  if (content_type == NULL) {
    content_type = "text/plain";
  }
  if (!http_rest_is_text(reason) || !http_rest_is_text(content_type)) {
    return ERR_ARG;
  }
  s->resp_len = 0;
  s->resp_overflow = 0;
  s->resp_done = 0;
  s->resp_chunked = 0;
  http_rest_resp_append_str(s, "HTTP/1.1 ");
  http_rest_resp_append_num(s, status, 10);
  http_rest_resp_append_str(s, " ");
  http_rest_resp_append_str(s, reason);
  http_rest_resp_append_str(s, "\r\nContent-Type: ");
  http_rest_resp_append_str(s, content_type);
  http_rest_resp_append_str(s, "\r\nConnection: close\r\n");
  http_rest_resp_append(s, s->extra_hdr, s->extra_hdr_len);
  return s->resp_overflow ? ERR_BUF : ERR_OK;
}

/**
 * Add a response header, e.g. "Cache-Control: no-cache". Call before
 * http_rest_resp_send() or http_rest_resp_begin(). Do not add
 * Content-Type, Content-Length, Transfer-Encoding or Connection: these are
 * set by the router.
 *
 * @return ERR_OK, ERR_ARG for an invalid name or a value containing control
 *         characters (CR/LF), ERR_BUF if HTTP_REST_EXTRA_HDR_SIZE is exceeded
 */
err_t
http_rest_resp_add_header(http_rest_req_t *req, const char *name, const char *value)
{
  http_rest_session_t *s = http_rest_sess_from_req(req);
  size_t name_len, value_len;
  char *p;

  if ((s == NULL) || (name == NULL) || (value == NULL) ||
      !http_rest_is_token(name) || !http_rest_is_text(value)) {
    return ERR_ARG;
  }
  name_len = strlen(name);
  value_len = strlen(value);
  if (name_len + value_len + 4 > sizeof(s->extra_hdr) - s->extra_hdr_len) {
    return ERR_BUF;
  }
  p = &s->extra_hdr[s->extra_hdr_len];
  MEMCPY(p, name, name_len);
  p += name_len;
  *p++ = ':';
  *p++ = ' ';
  MEMCPY(p, value, value_len);
  p += value_len;
  *p++ = '\r';
  *p = '\n';
  s->extra_hdr_len += name_len + value_len + 4;
  return ERR_OK;
}

/** Remove all headers added with http_rest_resp_add_header() */
void
http_rest_resp_clear_headers(http_rest_req_t *req)
{
  http_rest_session_t *s = http_rest_sess_from_req(req);

  if (s != NULL) {
    s->extra_hdr_len = 0;
  }
}

/**
 * Send a complete response with Content-Length. Replaces anything produced
 * before for this request.
 *
 * @param req request
 * @param status HTTP status code (100..999)
 * @param content_type Content-Type (NULL: "text/plain")
 * @param body body data (may be NULL if body_len is 0)
 * @param body_len length of body
 * @return ERR_OK, ERR_ARG on invalid arguments, ERR_BUF if the response
 *         does not fit into HTTP_REST_RESP_BUF_SIZE (if the handler does not
 *         send another response, the client gets a 500)
 */
err_t
http_rest_resp_send(http_rest_req_t *req, u16_t status, const char *content_type,
                    const void *body, size_t body_len)
{
  http_rest_session_t *s = http_rest_sess_from_req(req);
  err_t err;

  if ((s == NULL) || ((body == NULL) && (body_len != 0))) {
    return ERR_ARG;
  }
  err = http_rest_resp_start(s, status, NULL, content_type);
  if (err != ERR_OK) {
    return err;
  }
  http_rest_resp_append_str(s, "Content-Length: ");
  http_rest_resp_append_num(s, body_len, 10);
  http_rest_resp_append_str(s, "\r\n\r\n");
  http_rest_resp_append(s, body, body_len);
  if (s->resp_overflow) {
    return ERR_BUF;
  }
  s->resp_done = 1;
  return ERR_OK;
}

/**
 * Send a response without body.
 * @param req request
 * @param status HTTP status code
 * @param reason reason phrase for the status line, NULL for the default one
 */
err_t
http_rest_resp_send_status(http_rest_req_t *req, u16_t status, const char *reason)
{
  http_rest_session_t *s = http_rest_sess_from_req(req);
  err_t err;

  if (s == NULL) {
    return ERR_ARG;
  }
  err = http_rest_resp_start(s, status, reason, NULL);
  if (err != ERR_OK) {
    return err;
  }
  http_rest_resp_append_str(s, "Content-Length: 0\r\n\r\n");
  if (s->resp_overflow) {
    return ERR_BUF;
  }
  s->resp_done = 1;
  return ERR_OK;
}

/**
 * Begin a response with Transfer-Encoding: chunked. Continue with
 * http_rest_resp_send_chunk() and end with http_rest_resp_finish().
 * The response is still buffered completely (HTTP_REST_RESP_BUF_SIZE).
 */
err_t
http_rest_resp_begin(http_rest_req_t *req, u16_t status, const char *content_type)
{
  http_rest_session_t *s = http_rest_sess_from_req(req);
  err_t err;

  if (s == NULL) {
    return ERR_ARG;
  }
  err = http_rest_resp_start(s, status, NULL, content_type);
  if (err != ERR_OK) {
    return err;
  }
  http_rest_resp_append_str(s, "Transfer-Encoding: chunked\r\n\r\n");
  if (s->resp_overflow) {
    return ERR_BUF;
  }
  s->resp_chunked = 1;
  return ERR_OK;
}

/**
 * Append one chunk to a response started with http_rest_resp_begin().
 * A zero-length chunk is ignored (it would end the response).
 */
err_t
http_rest_resp_send_chunk(http_rest_req_t *req, const void *data, size_t len)
{
  http_rest_session_t *s = http_rest_sess_from_req(req);

  if ((s == NULL) || !s->resp_chunked || s->resp_done || ((data == NULL) && (len != 0))) {
    return ERR_ARG;
  }
  if (len == 0) {
    return ERR_OK;
  }
  http_rest_resp_append_num(s, len, 16);
  http_rest_resp_append_str(s, "\r\n");
  http_rest_resp_append(s, data, len);
  http_rest_resp_append_str(s, "\r\n");
  return s->resp_overflow ? ERR_BUF : ERR_OK;
}

/** Append a NUL-terminated string as one chunk */
err_t
http_rest_resp_send_str(http_rest_req_t *req, const char *str)
{
  if (str == NULL) {
    return ERR_ARG;
  }
  return http_rest_resp_send_chunk(req, str, strlen(str));
}

/** Finish a chunked response (appends the terminating zero-length chunk) */
err_t
http_rest_resp_finish(http_rest_req_t *req)
{
  http_rest_session_t *s = http_rest_sess_from_req(req);

  if ((s == NULL) || !s->resp_chunked || s->resp_done) {
    return ERR_ARG;
  }
  http_rest_resp_append_str(s, "0\r\n\r\n");
  if (s->resp_overflow) {
    return ERR_BUF;
  }
  s->resp_done = 1;
  return ERR_OK;
}

/*-------------------------------------------------------------------------*/
/* httpd integration                                                       */
/*-------------------------------------------------------------------------*/

/** Check whether a name is in the router's internal namespace */
static u8_t
http_rest_is_internal(const char *uri)
{
  return (strncmp(uri, HTTP_REST_VIRTUAL_PREFIX, HTTP_REST_PREFIX_LEN) == 0) ? 1 : 0;
}

#if LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN
/* compile-time check: LWIP_HTTPD_HEADERS_URI_REPLACE_LEN is too small for
   HTTP_REST_VIRTUAL_PREFIX if this fails */
typedef char http_rest_check_replace_len[(LWIP_HTTPD_HEADERS_URI_REPLACE_LEN >= HTTP_REST_VNAME_LEN) ? 1 : -1];
/**
 * GET dispatch, to be called from httpd_headers_before_file_open().
 * If the path matches a route, the handler is run and replace_uri is set to
 * the virtual file that carries the response.
 *
 * @param uri request URI including the query string
 * @param replace_uri buffer for the replacement URI
 * @param replace_uri_len size of replace_uri
 * @return 1 if the request was handled (replace_uri is set), 0 if no route
 *         matched (replace_uri is untouched)
 */
u8_t
http_rest_headers_hook(const char *uri, char *replace_uri, u16_t replace_uri_len)
{
  const http_rest_route_t *route;
  http_rest_session_t *s;

  if ((uri == NULL) || (replace_uri == NULL)) {
    return 0;
  }
  if (http_rest_is_internal(uri)) {
    /* clients must not open other requests' responses: serve 404 */
    return http_rest_strcpy(replace_uri, replace_uri_len, HTTP_REST_NONE_NAME);
  }
  route = http_rest_route_match(uri, http_rest_path_len(uri));
  if (route == NULL) {
    return 0;
  }
  s = http_rest_sess_alloc();
  if (s == NULL) {
    return http_rest_strcpy(replace_uri, replace_uri_len, HTTP_REST_BUSY_NAME);
  }
  if (http_rest_sess_setup(s, route, HTTP_REST_METHOD_GET, uri)) {
    http_rest_sess_dispatch(s, route);
  }
  http_rest_sess_ready(s, replace_uri, replace_uri_len);
  return 1;
}
#endif /* LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN */

#if LWIP_HTTPD_SUPPORT_POST
/* compile-time check: LWIP_HTTPD_POST_MAX_RESPONSE_URI_LEN is too small for
   HTTP_REST_VIRTUAL_PREFIX if this fails */
typedef char http_rest_check_response_uri_len[(LWIP_HTTPD_POST_MAX_RESPONSE_URI_LEN >= HTTP_REST_VNAME_LEN) ? 1 : -1];

static http_rest_session_t *
http_rest_sess_by_conn(void *connection)
{
  size_t i;

  for (i = 0; i < HTTP_REST_MAX_SESSIONS; i++) {
    if ((http_rest_sessions[i].state == HTTP_REST_SESS_BODY) &&
        (http_rest_sessions[i].connection == connection)) {
      return &http_rest_sessions[i];
    }
  }
  return NULL;
}

/**
 * Check whether a POST request URI belongs to the router.
 * @param uri request URI including the query string
 * @return 1 if the path matches a route
 */
u8_t
http_rest_post_match(const char *uri)
{
  if (uri == NULL) {
    return 0;
  }
  return (http_rest_route_match(uri, http_rest_path_len(uri)) != NULL) ? 1 : 0;
}

/**
 * POST dispatch, to be called from httpd_post_begin() (parameters as there).
 * @return ERR_OK if the body is to be received; any other value means the
 *         request was answered right away (response_uri is set: an error
 *         response such as 413, or httpd's 404 page if no route matched)
 */
err_t
http_rest_post_begin(void *connection, const char *uri, int content_len,
                     char *response_uri, u16_t response_uri_len)
{
  const http_rest_route_t *route;
  http_rest_session_t *s;

  if ((uri == NULL) || (response_uri == NULL)) {
    return ERR_ARG;
  }
  route = http_rest_route_match(uri, http_rest_path_len(uri));
  if (route == NULL) {
    http_rest_strcpy(response_uri, response_uri_len, HTTP_REST_NONE_NAME);
    return ERR_ARG;
  }
  s = http_rest_sess_alloc();
  if (s == NULL) {
    http_rest_strcpy(response_uri, response_uri_len, HTTP_REST_BUSY_NAME);
    return ERR_MEM;
  }
  if (http_rest_sess_setup(s, route, HTTP_REST_METHOD_POST, uri)) {
    if ((content_len < 0) || ((size_t)content_len > HTTP_REST_MAX_BODY_SIZE)) {
      http_rest_resp_error(s, 413);
    } else {
      s->connection = connection;
      s->body_expected = (size_t)content_len;
      return ERR_OK;
    }
  }
  /* answered with an error response, the body is not received */
  http_rest_sess_ready(s, response_uri, response_uri_len);
  return ERR_VAL;
}

/**
 * POST body data, to be called from httpd_post_receive_data().
 * Always takes ownership of p (frees it).
 * @return ERR_OK, or ERR_VAL if the connection has no REST session
 */
err_t
http_rest_post_receive(void *connection, struct pbuf *p)
{
  http_rest_session_t *s = http_rest_sess_by_conn(connection);
  u16_t len;

  if (p == NULL) {
    return ERR_ARG;
  }
  if (s == NULL) {
    pbuf_free(p);
    return ERR_VAL;
  }
  /* never more than Content-Length (pipelined data is dropped) */
  len = (u16_t)LWIP_MIN(p->tot_len, s->body_expected - s->body_received);
  if (len > 0) {
    s->body_received += pbuf_copy_partial(p, &s->body_buf[s->body_received], len, 0);
  }
  s->time = sys_now();
  pbuf_free(p);
  return ERR_OK;
}

/**
 * End of a POST request, to be called from httpd_post_finished().
 * httpd also calls httpd_post_finished() when the connection is closed
 * before the body is complete: the session is then freed without running
 * the handler.
 *
 * @return 1 if the connection had a REST session (response_uri is set if
 *         the body was complete), 0 otherwise
 */
u8_t
http_rest_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
  http_rest_session_t *s = http_rest_sess_by_conn(connection);
  const http_rest_route_t *route;

  if (s == NULL) {
    return 0;
  }
  if (s->body_received != s->body_expected) {
    LWIP_DEBUGF(HTTP_REST_DEBUG, ("http_rest: POST aborted after %d of %d bytes\n",
                                  (int)s->body_received, (int)s->body_expected));
    http_rest_sess_free(s);
    if ((response_uri != NULL) && (response_uri_len > 0)) {
      response_uri[0] = '\0';
    }
    return 1;
  }
  s->body_buf[s->body_received] = 0;
  s->req.body = s->body_buf;
  s->req.body_len = s->body_received;
  route = http_rest_route_match(s->uri_buf, strlen(s->uri_buf));
  if (route == NULL) {
    /* route table changed while the body was received */
    http_rest_resp_error(s, 404);
  } else {
    http_rest_sess_dispatch(s, route);
  }
  http_rest_sess_ready(s, response_uri, response_uri_len);
  return 1;
}
#endif /* LWIP_HTTPD_SUPPORT_POST */

/**
 * To be called from fs_open_custom().
 * @return 1 if name is a response of the router (file is set up), 0 if not
 */
int
http_rest_fs_open(struct fs_file *file, const char *name)
{
  http_rest_session_t *s;

  if ((file == NULL) || (name == NULL) || !http_rest_is_internal(name)) {
    return 0;
  }
  if (strcmp(name, HTTP_REST_BUSY_NAME) == 0) {
    /* constant data, sent from ROM like an fsdata file */
    memset(file, 0, sizeof(*file));
    file->data = http_rest_busy_response;
    file->len = (int)(sizeof(http_rest_busy_response) - 1);
    file->index = file->len;
    file->flags = FS_FILE_FLAGS_HEADER_INCLUDED;
    return 1;
  }
  s = http_rest_sess_by_name(name);
  if (s == NULL) {
    return 0;
  }
  memset(file, 0, sizeof(*file));
  /* data == NULL: httpd reads the response through fs_read_custom() into
     its own buffer, so the session buffer is not referenced after close */
  file->data = NULL;
  file->len = (int)s->resp_len;
  file->index = 0;
  /* not HEADER_PERSISTENT: httpd closes the connection afterwards,
     matching "Connection: close" */
  file->flags = FS_FILE_FLAGS_HEADER_INCLUDED;
  s->file = file;
  s->state = HTTP_REST_SESS_OPEN;
  s->time = sys_now();
  return 1;
}

static http_rest_session_t *
http_rest_sess_by_file(const struct fs_file *file)
{
  size_t i;

  for (i = 0; i < HTTP_REST_MAX_SESSIONS; i++) {
    if ((http_rest_sessions[i].state == HTTP_REST_SESS_OPEN) &&
        (http_rest_sessions[i].file == file)) {
      return &http_rest_sessions[i];
    }
  }
  return NULL;
}

/**
 * Check whether an open file belongs to the router (for applications that
 * chain fs_read_custom() / fs_close_custom() to several modules).
 */
u8_t
http_rest_fs_is_own(const struct fs_file *file)
{
  if (file == NULL) {
    return 0;
  }
  return ((file->data == http_rest_busy_response) ||
          (http_rest_sess_by_file(file) != NULL)) ? 1 : 0;
}

/**
 * To be called from fs_read_custom() for files of the router.
 * @return number of bytes copied to buffer, or FS_READ_EOF
 */
int
http_rest_fs_read(struct fs_file *file, char *buffer, int count)
{
  http_rest_session_t *s = http_rest_sess_by_file(file);
  int len;

  if ((s == NULL) || (buffer == NULL) || (count <= 0) || (file->index >= file->len)) {
    return FS_READ_EOF;
  }
  len = LWIP_MIN(count, file->len - file->index);
  MEMCPY(buffer, &s->resp_buf[file->index], (size_t)len);
  file->index += len;
  return len;
}

/**
 * To be called from fs_close_custom().
 * @return 1 if the file belonged to the router (its session is freed), 0 if not
 */
u8_t
http_rest_fs_close(struct fs_file *file)
{
  http_rest_session_t *s;

  if (file == NULL) {
    return 0;
  }
  if (file->data == http_rest_busy_response) {
    return 1;
  }
  s = http_rest_sess_by_file(file);
  if (s == NULL) {
    return 0;
  }
  http_rest_sess_free(s);
  return 1;
}

/*-------------------------------------------------------------------------*/
/* Optional definitions of the httpd hooks                                 */
/*-------------------------------------------------------------------------*/

#if HTTP_REST_DEFINE_HTTPD_HOOKS
#if LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN
void *
httpd_headers_before_file_open(const char *headers, u16_t headers_len, const char *uri,
                               char *replace_uri, u16_t replace_uri_len)
{
  LWIP_UNUSED_ARG(headers);
  LWIP_UNUSED_ARG(headers_len);
  http_rest_headers_hook(uri, replace_uri, replace_uri_len);
  return NULL;
}
#endif /* LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN */

#if LWIP_HTTPD_SUPPORT_POST
err_t
httpd_post_begin(void *connection, const char *uri, const char *http_request,
                 u16_t http_request_len, int content_len, char *response_uri,
                 u16_t response_uri_len, u8_t *post_auto_wnd)
{
  LWIP_UNUSED_ARG(http_request);
  LWIP_UNUSED_ARG(http_request_len);
  LWIP_UNUSED_ARG(post_auto_wnd);
  return http_rest_post_begin(connection, uri, content_len, response_uri, response_uri_len);
}

err_t
httpd_post_receive_data(void *connection, struct pbuf *p)
{
  return http_rest_post_receive(connection, p);
}

void
httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
  http_rest_post_finished(connection, response_uri, response_uri_len);
}
#endif /* LWIP_HTTPD_SUPPORT_POST */

int
fs_open_custom(struct fs_file *file, const char *name)
{
  return http_rest_fs_open(file, name);
}

#if LWIP_HTTPD_FS_ASYNC_READ
u8_t
fs_wait_read_custom(struct fs_file *file, fs_wait_cb callback_fn, void *callback_arg)
{
  /* responses are always complete when the file is opened */
  LWIP_UNUSED_ARG(file);
  LWIP_UNUSED_ARG(callback_fn);
  LWIP_UNUSED_ARG(callback_arg);
  return 1;
}

int
fs_read_async_custom(struct fs_file *file, char *buffer, int count,
                     fs_wait_cb callback_fn, void *callback_arg)
{
  LWIP_UNUSED_ARG(callback_fn);
  LWIP_UNUSED_ARG(callback_arg);
  return http_rest_fs_read(file, buffer, count);
}
#else /* LWIP_HTTPD_FS_ASYNC_READ */
int
fs_read_custom(struct fs_file *file, char *buffer, int count)
{
  return http_rest_fs_read(file, buffer, count);
}
#endif /* LWIP_HTTPD_FS_ASYNC_READ */

void
fs_close_custom(struct fs_file *file)
{
  http_rest_fs_close(file);
}
#endif /* HTTP_REST_DEFINE_HTTPD_HOOKS */

#endif /* LWIP_HTTPD_CUSTOM_FILES && LWIP_HTTPD_DYNAMIC_FILE_READ && ... */
