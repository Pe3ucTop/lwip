/**
 * @file
 * HTTP server: dispatch POST requests to several registered handlers
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

#ifndef LWIP_HDR_APPS_HTTPD_POST_DISPATCH_H
#define LWIP_HDR_APPS_HTTPD_POST_DISPATCH_H

#include "lwip/apps/httpd_opts.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_HTTPD_POST_DISPATCH

/**
 * @ingroup httpd
 * A POST handler ("sink") registered with httpd_post_sink_register().
 *
 * match() selects the sink for a request; begin(), receive() and finished()
 * have the same contract as httpd_post_begin(), httpd_post_receive_data()
 * and httpd_post_finished():
 * - begin() returns ERR_OK to accept the request; any other value rejects it
 *   and httpd sends response_uri (finished() is not called then).
 * - receive() owns the pbuf and must free it. Returning an error makes httpd
 *   ignore the rest of the body and call finished().
 * - finished() is called exactly once for every accepted request, also when
 *   the connection is closed before the body was received completely.
 *
 * All functions run in the httpd (tcpip) context.
 */
struct httpd_post_sink {
  /** name for debug output, may be NULL */
  const char *name;
  /** return != 0 if this sink handles the request; http_request contains
      the request headers (see httpd_post_begin()) */
  u8_t (*match)(const char *uri, const char *http_request, u16_t http_request_len);
  err_t (*begin)(void *connection, const char *uri, const char *http_request,
                 u16_t http_request_len, int content_len, char *response_uri,
                 u16_t response_uri_len, u8_t *post_auto_wnd);
  err_t (*receive)(void *connection, struct pbuf *p);
  void (*finished)(void *connection, char *response_uri, u16_t response_uri_len);
};

err_t httpd_post_sink_register(const struct httpd_post_sink *sink);

#endif /* LWIP_HTTPD_POST_DISPATCH */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_APPS_HTTPD_POST_DISPATCH_H */
