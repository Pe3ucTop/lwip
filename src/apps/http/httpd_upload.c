/**
 * @file
 * HTTP server: file upload by POST with multipart/form-data.
 *
 * Registers a POST sink (LWIP_HTTPD_POST_DISPATCH) for HTTPD_UPLOAD_URI
 * (or the URI set with httpd_upload_set_uri()) and streams the files of
 * the request body to writer callbacks selected by file name:
 *
 * - POST /upload           file name from the multipart part
 * - POST /upload/name.bin  file name from the URI (takes precedence; only
 *                          the first file part of the body is stored)
 *
 * Form fields without a file name are skipped. The response URI tells
 * the result; see the HTTPD_UPLOAD_URI_* options and LWIP_HTTPD_STATUS_PAGES.
 */

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
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Maksims Matjakubovs <maksims.matjakubovs@gmail.com>
 *
 */

#include "lwip/apps/httpd_opts.h"

#if LWIP_HTTPD_UPLOAD

#include "lwip/apps/httpd_upload.h"
#include "lwip/apps/httpd_post_dispatch.h"
#include "lwip/apps/http_multipart.h"
#include "lwip/pbuf.h"
#include "lwip/def.h"
#include "lwip/debug.h"

#include <string.h>

#if !LWIP_HTTPD_POST_DISPATCH || !LWIP_HTTPD_MULTIPART
#error LWIP_HTTPD_UPLOAD needs LWIP_HTTPD_POST_DISPATCH and LWIP_HTTPD_MULTIPART
#endif

struct httpd_upload_session {
  /** NULL: free */
  void *connection;
  struct http_multipart_parser parser;
  void *handle;
  const struct httpd_upload_route *route;
  /** response URI of the first error, NULL while everything is fine */
  const char *error_uri;
  u32_t body_len_max;
  /** number of files received completely */
  u16_t files_ok;
  /** file name taken from the URI (empty if none) */
  char uri_name[HTTP_MULTIPART_MAX_FILENAME + 1];
};

static struct httpd_upload_session httpd_upload_sessions[HTTPD_UPLOAD_MAX_SESSIONS];
static const struct httpd_upload_route *httpd_upload_routes;
static u16_t httpd_upload_routes_count;
static const char *httpd_upload_uri = HTTPD_UPLOAD_URI;

static void
httpd_upload_set_response(char *response_uri, u16_t response_uri_len, const char *uri)
{
  size_t len;
  if ((response_uri == NULL) || (response_uri_len == 0)) {
    return;
  }
  len = strlen(uri);
  if (len >= response_uri_len) {
    len = (size_t)(response_uri_len - 1);
  }
  MEMCPY(response_uri, uri, len);
  response_uri[len] = 0;
}

static struct httpd_upload_session *
httpd_upload_find(void *connection)
{
  u16_t i;
  for (i = 0; i < HTTPD_UPLOAD_MAX_SESSIONS; i++) {
    if (httpd_upload_sessions[i].connection == connection) {
      return &httpd_upload_sessions[i];
    }
  }
  return NULL;
}

/* "*" matches everything, "*suffix" matches the end, anything else is exact */
static u8_t
httpd_upload_pattern_match(const char *pattern, const char *name)
{
  if (pattern == NULL) {
    return 0;
  }
  if (pattern[0] == '*') {
    size_t slen = strlen(pattern + 1);
    size_t nlen = strlen(name);
    return (u8_t)((nlen >= slen) && !strcmp(name + nlen - slen, pattern + 1));
  }
  return (u8_t)!strcmp(pattern, name);
}

static const struct httpd_upload_route *
httpd_upload_find_route(const char *filename)
{
  u16_t i;
  for (i = 0; i < httpd_upload_routes_count; i++) {
    if (httpd_upload_pattern_match(httpd_upload_routes[i].pattern, filename)) {
      return &httpd_upload_routes[i];
    }
  }
  return NULL;
}

/* Return the part after the upload URI ("" for the URI itself), or NULL
   if the URI is not ours. "/upload" matches "/upload", "/upload/x" and
   "/upload?x" but not "/uploadx". */
static const char *
httpd_upload_uri_rest(const char *uri)
{
  size_t plen = strlen(httpd_upload_uri);
  if (strncmp(uri, httpd_upload_uri, plen) != 0) {
    return NULL;
  }
  if ((uri[plen] != 0) && (uri[plen] != '/') && (uri[plen] != '?')) {
    return NULL;
  }
  return uri + plen;
}

/* Copy the last path element of src into dst (for a URI only up to '?').
   Returns 0 if it does not fit. */
static u8_t
httpd_upload_basename(const char *src, u8_t is_uri, char *dst, size_t dst_size)
{
  const char *start = src;
  const char *p;
  size_t len;
  for (p = src; (*p != 0) && (!is_uri || (*p != '?')); p++) {
    if ((*p == '/') || (*p == '\\')) {
      start = p + 1;
    }
  }
  len = (size_t)(p - start);
  if (len >= dst_size) {
    dst[0] = 0;
    return 0;
  }
  MEMCPY(dst, start, len);
  dst[len] = 0;
  return 1;
}

static err_t
httpd_upload_part_begin(void *arg, const struct http_multipart_part *part)
{
  struct httpd_upload_session *s = (struct httpd_upload_session *)arg;
  char name[HTTP_MULTIPART_MAX_FILENAME + 1];

  if ((part->flags & HTTP_MULTIPART_FLAG_FILENAME) == 0) {
    /* a form field, not a file: skip */
    return ERR_OK;
  }
  if (s->uri_name[0] != 0) {
    if (s->files_ok > 0) {
      /* the URI names one file: later file parts are skipped */
      return ERR_OK;
    }
    MEMCPY(name, s->uri_name, sizeof(name));
  } else {
    if (part->flags & HTTP_MULTIPART_FLAG_TRUNCATED) {
      s->error_uri = HTTPD_UPLOAD_URI_BAD_REQUEST;
      return ERR_VAL;
    }
    httpd_upload_basename(part->filename, 0, name, sizeof(name));
    if (name[0] == 0) {
      /* browsers send filename="" if no file was selected: skip */
      return ERR_OK;
    }
  }
  s->route = httpd_upload_find_route(name);
  if (s->route == NULL) {
    LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_upload: no writer for %s\n", name));
    s->error_uri = HTTPD_UPLOAD_URI_UNSUPPORTED;
    return ERR_VAL;
  }
  s->handle = s->route->open(name, s->body_len_max, s->route->arg);
  if (s->handle == NULL) {
    LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_upload: open %s failed\n", name));
    s->error_uri = HTTPD_UPLOAD_URI_ERROR;
    return ERR_VAL;
  }
  return ERR_OK;
}

static err_t
httpd_upload_part_data(void *arg, const u8_t *data, u16_t len)
{
  struct httpd_upload_session *s = (struct httpd_upload_session *)arg;
  if (s->handle != NULL) {
    err_t err = s->route->write(s->handle, data, len);
    if (err != ERR_OK) {
      s->error_uri = HTTPD_UPLOAD_URI_ERROR;
      return err;
    }
  }
  return ERR_OK;
}

static void
httpd_upload_part_end(void *arg, u8_t complete)
{
  struct httpd_upload_session *s = (struct httpd_upload_session *)arg;
  if (s->handle != NULL) {
    s->route->close(s->handle, complete);
    s->handle = NULL;
    if (complete) {
      s->files_ok++;
    }
  }
}

static const struct http_multipart_callbacks httpd_upload_mp_callbacks = {
  httpd_upload_part_begin,
  httpd_upload_part_data,
  httpd_upload_part_end
};

static u8_t
httpd_upload_match(const char *uri, const char *http_request, u16_t http_request_len)
{
  LWIP_UNUSED_ARG(http_request);
  LWIP_UNUSED_ARG(http_request_len);
  return (u8_t)(httpd_upload_uri_rest(uri) != NULL);
}

static err_t
httpd_upload_begin(void *connection, const char *uri, const char *http_request,
                   u16_t http_request_len, int content_len, char *response_uri,
                   u16_t response_uri_len, u8_t *post_auto_wnd)
{
  struct httpd_upload_session *s;
  char boundary[HTTP_MULTIPART_MAX_BOUNDARY + 1];
  const char *rest;
  err_t err;

  LWIP_UNUSED_ARG(post_auto_wnd);

#if HTTPD_UPLOAD_MAX_LEN
  if ((content_len < 0) || ((u32_t)content_len > (u32_t)HTTPD_UPLOAD_MAX_LEN)) {
    httpd_upload_set_response(response_uri, response_uri_len, HTTPD_UPLOAD_URI_TOO_LARGE);
    return ERR_VAL;
  }
#endif /* HTTPD_UPLOAD_MAX_LEN */

  err = http_multipart_get_boundary(http_request, http_request_len, boundary, sizeof(boundary));
  if (err != ERR_OK) {
    httpd_upload_set_response(response_uri, response_uri_len,
                              (err == ERR_VAL) ? HTTPD_UPLOAD_URI_UNSUPPORTED : HTTPD_UPLOAD_URI_BAD_REQUEST);
    return ERR_VAL;
  }

  s = httpd_upload_find(NULL);
  if (s == NULL) {
    httpd_upload_set_response(response_uri, response_uri_len, HTTPD_UPLOAD_URI_BUSY);
    return ERR_MEM;
  }
  memset(s, 0, sizeof(*s));
  if (http_multipart_init(&s->parser, boundary, &httpd_upload_mp_callbacks, s) != ERR_OK) {
    httpd_upload_set_response(response_uri, response_uri_len, HTTPD_UPLOAD_URI_BAD_REQUEST);
    return ERR_VAL;
  }
  rest = httpd_upload_uri_rest(uri);
  if ((rest != NULL) && (rest[0] == '/')) {
    if (!httpd_upload_basename(rest + 1, 1, s->uri_name, sizeof(s->uri_name))) {
      httpd_upload_set_response(response_uri, response_uri_len, HTTPD_UPLOAD_URI_BAD_REQUEST);
      return ERR_VAL;
    }
  }
  s->body_len_max = (content_len > 0) ? (u32_t)content_len : 0;
  s->connection = connection;
  return ERR_OK;
}

static err_t
httpd_upload_receive(void *connection, struct pbuf *p)
{
  struct httpd_upload_session *s = httpd_upload_find(connection);
  struct pbuf *q;

  if ((s == NULL) || (connection == NULL)) {
    if (p != NULL) {
      pbuf_free(p);
    }
    return ERR_VAL;
  }
  /* after an error the rest of the body is read and dropped, so the
     connection stays in sync and the error page can be sent */
  for (q = p; (q != NULL) && (s->error_uri == NULL); q = q->next) {
    if (http_multipart_parse(&s->parser, (const u8_t *)q->payload, q->len) != ERR_OK) {
      if (s->error_uri == NULL) {
        s->error_uri = HTTPD_UPLOAD_URI_BAD_REQUEST;
      }
    }
  }
  pbuf_free(p);
  return ERR_OK;
}

static void
httpd_upload_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
  struct httpd_upload_session *s = httpd_upload_find(connection);
  const char *result;

  if ((s == NULL) || (connection == NULL)) {
    httpd_upload_set_response(response_uri, response_uri_len, HTTPD_UPLOAD_URI_ERROR);
    return;
  }
  /* ends an open part with complete == 0 if the body was cut off */
  if ((http_multipart_finish(&s->parser) != ERR_OK) && (s->error_uri == NULL)) {
    s->error_uri = HTTPD_UPLOAD_URI_BAD_REQUEST;
  }
  if (s->handle != NULL) {
    s->route->close(s->handle, 0);
    s->handle = NULL;
  }
  if (s->error_uri != NULL) {
    result = s->error_uri;
  } else if (s->files_ok == 0) {
    result = HTTPD_UPLOAD_URI_BAD_REQUEST;
  } else {
    result = HTTPD_UPLOAD_URI_OK;
  }
  httpd_upload_set_response(response_uri, response_uri_len, result);
  s->connection = NULL;
}

static const struct httpd_post_sink httpd_upload_sink = {
  "upload",
  httpd_upload_match,
  httpd_upload_begin,
  httpd_upload_receive,
  httpd_upload_finished
};

/**
 * @ingroup httpd
 * Register the upload POST sink with the POST dispatcher. Call after
 * httpd_init(), and before sinks with a less specific URI (e.g. a sink that
 * matches "/").
 */
err_t
httpd_upload_init(void)
{
  return httpd_post_sink_register(&httpd_upload_sink);
}

/**
 * @ingroup httpd
 * Set the writers for uploaded files. The first route whose pattern matches
 * the file name is used. The table is stored by reference.
 */
void
httpd_upload_set_routes(const struct httpd_upload_route *routes, u16_t count)
{
  httpd_upload_routes = routes;
  httpd_upload_routes_count = (routes != NULL) ? count : 0;
}

/**
 * @ingroup httpd
 * Set the upload URI (default HTTPD_UPLOAD_URI). The string is stored by
 * reference.
 */
void
httpd_upload_set_uri(const char *uri)
{
  httpd_upload_uri = (uri != NULL) ? uri : HTTPD_UPLOAD_URI;
}

#endif /* LWIP_HTTPD_UPLOAD */
