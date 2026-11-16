/**
 * @file
 * HTTP server: dispatch POST requests to several registered handlers.
 *
 * httpd calls exactly one set of httpd_post_begin(), httpd_post_receive_data()
 * and httpd_post_finished(). With LWIP_HTTPD_POST_DISPATCH these functions
 * are implemented here and forward each request to one of several
 * registered struct httpd_post_sink, so independent modules (e.g. a form
 * handler and a file upload) can be used together.
 *
 * Sinks are asked in registration order; the first one whose match()
 * returns != 0 owns the request until finished(). Register more specific
 * sinks first.
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

#if LWIP_HTTPD_POST_DISPATCH

#include "lwip/apps/httpd.h"
#include "lwip/apps/httpd_post_dispatch.h"
#include "lwip/debug.h"
#include "lwip/def.h"

#include <string.h>

#if !LWIP_HTTPD_SUPPORT_POST
#error LWIP_HTTPD_POST_DISPATCH needs LWIP_HTTPD_SUPPORT_POST
#endif

/** registered sinks, in registration order */
static const struct httpd_post_sink *httpd_post_sinks[HTTPD_POST_DISPATCH_MAX_SINKS];

/** connection -> sink, one entry per request between begin and finished */
struct httpd_post_dispatch_conn {
  void *connection;
  const struct httpd_post_sink *sink;
};
static struct httpd_post_dispatch_conn httpd_post_dispatch_conns[HTTPD_POST_DISPATCH_MAX_CONNS];

/* Copy a (possibly too long) URI into httpd's response buffer */
static void
httpd_post_dispatch_set_uri(char *response_uri, u16_t response_uri_len, const char *uri)
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

static struct httpd_post_dispatch_conn *
httpd_post_dispatch_find(void *connection)
{
  u16_t i;
  for (i = 0; i < HTTPD_POST_DISPATCH_MAX_CONNS; i++) {
    if (httpd_post_dispatch_conns[i].connection == connection) {
      return &httpd_post_dispatch_conns[i];
    }
  }
  return NULL;
}

/**
 * @ingroup httpd
 * Register a POST sink (LWIP_HTTPD_POST_DISPATCH). The sink is stored by
 * reference and must stay valid. Sinks are asked in registration order.
 *
 * @param sink the sink; match, begin, receive and finished must be set
 * @return ERR_OK (also if already registered), ERR_ARG for an incomplete
 *         sink, ERR_MEM if HTTPD_POST_DISPATCH_MAX_SINKS sinks are registered
 */
err_t
httpd_post_sink_register(const struct httpd_post_sink *sink)
{
  u16_t i;

  LWIP_ERROR("httpd_post_sink_register: invalid sink",
             (sink != NULL) && (sink->match != NULL) && (sink->begin != NULL) &&
             (sink->receive != NULL) && (sink->finished != NULL), return ERR_ARG;);

  for (i = 0; i < HTTPD_POST_DISPATCH_MAX_SINKS; i++) {
    if (httpd_post_sinks[i] == sink) {
      return ERR_OK;
    }
    if (httpd_post_sinks[i] == NULL) {
      httpd_post_sinks[i] = sink;
      return ERR_OK;
    }
  }
  return ERR_MEM;
}

err_t
httpd_post_begin(void *connection, const char *uri, const char *http_request,
                 u16_t http_request_len, int content_len, char *response_uri,
                 u16_t response_uri_len, u8_t *post_auto_wnd)
{
  const struct httpd_post_sink *sink = NULL;
  struct httpd_post_dispatch_conn *conn;
  err_t err;
  u16_t i;

  LWIP_ASSERT("httpd_post_begin: connection != NULL", connection != NULL);

  for (i = 0; (i < HTTPD_POST_DISPATCH_MAX_SINKS) && (httpd_post_sinks[i] != NULL); i++) {
    if (httpd_post_sinks[i]->match(uri, http_request, http_request_len)) {
      sink = httpd_post_sinks[i];
      break;
    }
  }
  if (sink == NULL) {
    LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_post_begin: no sink for %s\n", uri));
    httpd_post_dispatch_set_uri(response_uri, response_uri_len, HTTPD_POST_DISPATCH_URI_NO_SINK);
    return ERR_ARG;
  }

  /* reserve the entry before calling the sink, so that the connection is
     known even if the sink calls back into httpd from begin() */
  conn = httpd_post_dispatch_find(NULL);
  if (conn == NULL) {
    LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_post_begin: too many POST requests\n"));
    httpd_post_dispatch_set_uri(response_uri, response_uri_len, HTTPD_POST_DISPATCH_URI_BUSY);
    return ERR_MEM;
  }
  conn->connection = connection;
  conn->sink = sink;

  err = sink->begin(connection, uri, http_request, http_request_len, content_len,
                    response_uri, response_uri_len, post_auto_wnd);
  if (err != ERR_OK) {
    /* rejected: httpd does not call httpd_post_finished() for this request */
    LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_post_begin: %s rejected %s\n",
                              (sink->name != NULL) ? sink->name : "sink", uri));
    conn->connection = NULL;
    conn->sink = NULL;
  }
  return err;
}

err_t
httpd_post_receive_data(void *connection, struct pbuf *p)
{
  struct httpd_post_dispatch_conn *conn = httpd_post_dispatch_find(connection);
  if ((conn == NULL) || (connection == NULL)) {
    /* not ours: this function owns p and must free it */
    if (p != NULL) {
      pbuf_free(p);
    }
    return ERR_VAL;
  }
  return conn->sink->receive(connection, p);
}

void
httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
{
  const struct httpd_post_sink *sink;
  struct httpd_post_dispatch_conn *conn = httpd_post_dispatch_find(connection);
  if ((conn == NULL) || (connection == NULL)) {
    httpd_post_dispatch_set_uri(response_uri, response_uri_len, HTTPD_POST_DISPATCH_URI_ERROR);
    return;
  }
  sink = conn->sink;
  /* free the entry first: the connection pointer may be reused as soon as
     the sink is done */
  conn->connection = NULL;
  conn->sink = NULL;
  sink->finished(connection, response_uri, response_uri_len);
}

#endif /* LWIP_HTTPD_POST_DISPATCH */
