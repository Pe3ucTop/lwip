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
 * REST router for the lwIP httpd (contrib/addons/httpd_rest).
 *
 * Routes map a URI path (exact or prefix match) to a handler. The handler
 * gets the method (GET or POST), the path, the decoded query parameters and,
 * for POST, the complete body, and builds the whole response (status,
 * headers, body) into a per-request buffer. httpd then delivers that
 * response as a virtual file.
 *
 * Integration with httpd:
 * - GET: httpd_headers_before_file_open() calls http_rest_headers_hook(),
 *   which runs the handler and replaces the URI by a virtual file name.
 * - POST: httpd_post_begin(), httpd_post_receive_data() and
 *   httpd_post_finished() call http_rest_post_begin(),
 *   http_rest_post_receive() and http_rest_post_finished().
 * - fs_open_custom(), fs_read_custom() and fs_close_custom() call
 *   http_rest_fs_open(), http_rest_fs_read() and http_rest_fs_close().
 * With HTTP_REST_DEFINE_HTTPD_HOOKS == 1 the router defines these httpd
 * hooks itself; otherwise the application calls the functions above from
 * its own hooks (e.g. after its own handlers declined a request).
 *
 * Required httpd options: LWIP_HTTPD_CUSTOM_FILES, LWIP_HTTPD_DYNAMIC_FILE_READ,
 * LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN (for GET) and LWIP_HTTPD_SUPPORT_POST
 * (for POST).
 *
 * Everything runs in the httpd (tcpip) thread: handlers must not block.
 */

#ifndef LWIP_HDR_CONTRIB_ADDONS_HTTP_REST_H
#define LWIP_HDR_CONTRIB_ADDONS_HTTP_REST_H

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/apps/httpd.h"
#include "lwip/apps/fs.h"

#include "http_rest_opts.h"
#include "http_rest_query.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Request method (stock httpd only parses GET and POST) */
typedef enum {
  HTTP_REST_METHOD_GET  = 0,
  HTTP_REST_METHOD_POST = 1
} http_rest_method_t;

/** Request passed to a handler. Valid only during the handler call. */
typedef struct http_rest_req {
  /** GET or POST */
  http_rest_method_t method;
  /** Request path without the query string, as received (not decoded) */
  const char *uri;
  /** Decoded query parameters (see http_rest_query_parse()) */
  http_rest_kv_t query[HTTP_REST_MAX_KV_PAIRS];
  /** Number of valid entries in query */
  size_t query_count;
  /** POST body, NULL for GET. Followed by a NUL byte that is not counted
   * in body_len. */
  const u8_t *body;
  /** Length of the POST body */
  size_t body_len;
  /** user_ctx of the matched route */
  void *user_ctx;
  /** Internal, do not use */
  void *session;
} http_rest_req_t;

/** Request handler. It must produce a response with http_rest_resp_send(),
 * http_rest_resp_send_status() or http_rest_resp_begin() / ..._send_chunk()
 * / ..._finish(). Returning without a complete response results in
 * "500 Internal Server Error". */
typedef void (*http_rest_handler_fn)(http_rest_req_t *req);

/** Route matching mode */
typedef enum {
  /** path must be equal to the request path */
  HTTP_REST_MATCH_EXACT  = 0,
  /** path must be a prefix of the request path */
  HTTP_REST_MATCH_PREFIX = 1
} http_rest_match_t;

/** Route table entry. Routes are tried in table order, the first match wins. */
typedef struct http_rest_route {
  /** Path to match, e.g. "/api/status"; matched against the raw request path */
  const char *path;
  /** Matching mode */
  http_rest_match_t match;
  /** Handler for GET and POST; it checks req->method itself */
  http_rest_handler_fn handler;
  /** Passed to the handler in req->user_ctx */
  void *user_ctx;
} http_rest_route_t;

/* Setup */
void  http_rest_init(void);
err_t http_rest_register_routes(const http_rest_route_t *routes, size_t count);

/* Request access */
const char *http_rest_query_get(const http_rest_req_t *req, const char *key);
u8_t  http_rest_query_has(const http_rest_req_t *req, const char *key);
err_t http_rest_body_parse_form(http_rest_req_t *req, http_rest_kv_t *kv,
                                size_t kv_max, size_t *kv_count);

/* Response */
err_t http_rest_resp_add_header(http_rest_req_t *req, const char *name, const char *value);
void  http_rest_resp_clear_headers(http_rest_req_t *req);
err_t http_rest_resp_send(http_rest_req_t *req, u16_t status, const char *content_type,
                          const void *body, size_t body_len);
err_t http_rest_resp_send_status(http_rest_req_t *req, u16_t status, const char *reason);
err_t http_rest_resp_begin(http_rest_req_t *req, u16_t status, const char *content_type);
err_t http_rest_resp_send_chunk(http_rest_req_t *req, const void *data, size_t len);
err_t http_rest_resp_send_str(http_rest_req_t *req, const char *str);
err_t http_rest_resp_finish(http_rest_req_t *req);

/* httpd integration (see file description) */
#if LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN
u8_t  http_rest_headers_hook(const char *uri, char *replace_uri, u16_t replace_uri_len);
#endif /* LWIP_HTTPD_HEADERS_BEFORE_FILE_OPEN */
#if LWIP_HTTPD_SUPPORT_POST
u8_t  http_rest_post_match(const char *uri);
err_t http_rest_post_begin(void *connection, const char *uri, int content_len,
                           char *response_uri, u16_t response_uri_len);
err_t http_rest_post_receive(void *connection, struct pbuf *p);
u8_t  http_rest_post_finished(void *connection, char *response_uri, u16_t response_uri_len);
#endif /* LWIP_HTTPD_SUPPORT_POST */
int   http_rest_fs_open(struct fs_file *file, const char *name);
u8_t  http_rest_fs_is_own(const struct fs_file *file);
int   http_rest_fs_read(struct fs_file *file, char *buffer, int count);
u8_t  http_rest_fs_close(struct fs_file *file);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_CONTRIB_ADDONS_HTTP_REST_H */
