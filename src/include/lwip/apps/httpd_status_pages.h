/**
 * @file
 * HTTP server: built-in status pages (header included, served from memory)
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

#ifndef LWIP_HDR_APPS_HTTPD_STATUS_PAGES_H
#define LWIP_HDR_APPS_HTTPD_STATUS_PAGES_H

#include "lwip/apps/httpd_opts.h"
#include "lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_HTTPD_STATUS_PAGES

/** Header line added to the status pages: with LWIP_HTTPD_CORS, the pages
 * carry "Access-Control-Allow-Origin" like the headers httpd generates
 * itself (they include their own headers, so httpd does not add it). */
#if LWIP_HTTPD_CORS
#define HTTPD_STATUS_PAGE_CORS_HDR "Access-Control-Allow-Origin: " LWIP_HTTPD_CORS_ALLOW_ORIGIN "\r\n"
#else /* LWIP_HTTPD_CORS */
#define HTTPD_STATUS_PAGE_CORS_HDR ""
#endif /* LWIP_HTTPD_CORS */

/** Complete response text (status line, headers, body) of a status page.
 * @param status status code and reason phrase, e.g. "413 Payload Too Large"
 * @param body HTML body (string literal)
 */
#define HTTPD_STATUS_PAGE_TEXT(status, body) \
  "HTTP/1.0 " status "\r\n" \
  "Content-Type: text/html\r\n" \
  HTTPD_STATUS_PAGE_CORS_HDR \
  "Connection: close\r\n" \
  "\r\n" body

/** Initializer for one struct httpd_status_page.
 * Example: HTTPD_STATUS_PAGE("/413.html", "413 Payload Too Large",
 *                            "<html><body>Too large</body></html>")
 */
#define HTTPD_STATUS_PAGE(uri, status, body) \
  { (uri), HTTPD_STATUS_PAGE_TEXT(status, body), \
    (u16_t)(sizeof(HTTPD_STATUS_PAGE_TEXT(status, body)) - 1) }

/**
 * @ingroup httpd
 * One page served for an exact URI. @p page contains the complete HTTP
 * response (status line, headers and body), so pages can carry any status
 * code. Pages without Content-Length must contain "Connection: close".
 */
struct httpd_status_page {
  const char *uri;
  const char *page;
  u16_t len;
};

/**
 * @ingroup httpd
 * A table of pages; linked into a list by httpd_status_pages_add() and must
 * stay valid while registered. Tables added later are searched first.
 */
struct httpd_status_page_table {
  const struct httpd_status_page *pages;
  u16_t count;
  /** internal, do not touch */
  struct httpd_status_page_table *next;
};

void httpd_status_pages_init(void);
err_t httpd_status_pages_add(struct httpd_status_page_table *table);

#endif /* LWIP_HTTPD_STATUS_PAGES */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_APPS_HTTPD_STATUS_PAGES_H */
