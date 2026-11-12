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
 * Options for the httpd REST router (contrib/addons/httpd_rest).
 * Override them in lwipopts.h.
 */

#ifndef LWIP_HDR_CONTRIB_ADDONS_HTTP_REST_OPTS_H
#define LWIP_HDR_CONTRIB_ADDONS_HTTP_REST_OPTS_H

#include "lwip/opt.h"

/** Number of requests that can be in flight at the same time (one session
 * each). A session holds the request URI, the POST body and the complete
 * response, see the buffer sizes below. */
#if !defined HTTP_REST_MAX_SESSIONS || defined __DOXYGEN__
#define HTTP_REST_MAX_SESSIONS      2
#endif

/** Maximum length of a request URI (path and query) handled by the router.
 * Longer URIs are answered with "414 URI Too Long". */
#if !defined HTTP_REST_MAX_URI_LEN || defined __DOXYGEN__
#define HTTP_REST_MAX_URI_LEN       128
#endif

/** Maximum number of query parameters. More parameters are answered with
 * "400 Bad Request". */
#if !defined HTTP_REST_MAX_KV_PAIRS || defined __DOXYGEN__
#define HTTP_REST_MAX_KV_PAIRS      8
#endif

/** Maximum size of a POST body. Larger bodies (by Content-Length) are
 * answered with "413 Content Too Large" without being received. */
#if !defined HTTP_REST_MAX_BODY_SIZE || defined __DOXYGEN__
#define HTTP_REST_MAX_BODY_SIZE     1024
#endif

/** Size of the response buffer per session. The whole response (status
 * line, headers and body, including chunked framing) must fit. A response
 * that does not fit is replaced by "500 Internal Server Error". */
#if !defined HTTP_REST_RESP_BUF_SIZE || defined __DOXYGEN__
#define HTTP_REST_RESP_BUF_SIZE     2048
#endif

/** Size of the buffer for headers added with http_rest_resp_add_header() */
#if !defined HTTP_REST_EXTRA_HDR_SIZE || defined __DOXYGEN__
#define HTTP_REST_EXTRA_HDR_SIZE    256
#endif

/** A session that waits for a POST body or for httpd to open its response
 * for longer than this many milliseconds is reclaimed on the next session
 * allocation (protects against connections that disappear without httpd
 * telling the router). */
#if !defined HTTP_REST_STALE_MS || defined __DOXYGEN__
#define HTTP_REST_STALE_MS          10000
#endif

/** URI prefix of the internal (virtual) files that carry the responses.
 * Must not collide with a real file. Requests from clients for this prefix
 * are answered with 404. */
#if !defined HTTP_REST_VIRTUAL_PREFIX || defined __DOXYGEN__
#define HTTP_REST_VIRTUAL_PREFIX    "/__rest__/"
#endif

/** Set to 1 to let the router define the global httpd hooks
 * httpd_headers_before_file_open(), httpd_post_begin(),
 * httpd_post_receive_data(), httpd_post_finished() and fs_open_custom(),
 * fs_read_custom(), fs_close_custom() as thin wrappers around the
 * http_rest_*() integration functions.
 * Leave at 0 if the application (or another module) already implements
 * these hooks; it must then call the http_rest_*() functions itself. */
#if !defined HTTP_REST_DEFINE_HTTPD_HOOKS || defined __DOXYGEN__
#define HTTP_REST_DEFINE_HTTPD_HOOKS 0
#endif

/** Debug output for the REST router */
#if !defined HTTP_REST_DEBUG || defined __DOXYGEN__
#define HTTP_REST_DEBUG             LWIP_DBG_OFF
#endif

#endif /* LWIP_HDR_CONTRIB_ADDONS_HTTP_REST_OPTS_H */
