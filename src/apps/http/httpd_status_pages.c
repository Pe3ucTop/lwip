/**
 * @file
 * HTTP server: built-in status pages.
 *
 * Serves short, complete HTTP responses (status line + headers + body) from
 * memory for exact URIs such as "/404.html" or "/503.html". These are the
 * URIs httpd itself looks for on errors and that POST handlers return as
 * response_uri, so an application without a file system still sends a
 * proper status code instead of an empty 404.
 *
 * The pages are provided through a custom file provider asked AFTER the
 * files in fsdata, so a real "/404.html" in fsdata still wins.
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

#if LWIP_HTTPD_STATUS_PAGES

#include "lwip/apps/httpd_status_pages.h"
#include "lwip/apps/fs.h"
#include "lwip/def.h"
#include "lwip/debug.h"

#include <string.h>

#if !LWIP_HTTPD_CUSTOM_FILES || !LWIP_HTTPD_CUSTOM_FILE_PROVIDERS
#error LWIP_HTTPD_STATUS_PAGES needs LWIP_HTTPD_CUSTOM_FILES and LWIP_HTTPD_CUSTOM_FILE_PROVIDERS
#endif

static struct httpd_status_page_table *httpd_status_page_tables;

#if LWIP_HTTPD_STATUS_PAGES_DEFAULTS
static const struct httpd_status_page httpd_status_pages_default[] = {
  { "/204.html", "HTTP/1.0 204 No Content\r\nConnection: close\r\n\r\n",
    (u16_t)(sizeof("HTTP/1.0 204 No Content\r\nConnection: close\r\n\r\n") - 1) },
  HTTPD_STATUS_PAGE("/400.html", "400 Bad Request",
                    "<html><body><h1>400 Bad Request</h1></body></html>"),
  HTTPD_STATUS_PAGE("/404.html", "404 Not Found",
                    "<html><body><h1>404 Not Found</h1></body></html>"),
  HTTPD_STATUS_PAGE("/413.html", "413 Payload Too Large",
                    "<html><body><h1>413 Payload Too Large</h1></body></html>"),
  HTTPD_STATUS_PAGE("/415.html", "415 Unsupported Media Type",
                    "<html><body><h1>415 Unsupported Media Type</h1></body></html>"),
  HTTPD_STATUS_PAGE("/500.html", "500 Internal Server Error",
                    "<html><body><h1>500 Internal Server Error</h1></body></html>"),
  HTTPD_STATUS_PAGE("/501.html", "501 Not Implemented",
                    "<html><body><h1>501 Not Implemented</h1></body></html>"),
  HTTPD_STATUS_PAGE("/503.html", "503 Service Unavailable",
                    "<html><body><h1>503 Service Unavailable</h1></body></html>")
};

static struct httpd_status_page_table httpd_status_pages_default_table = {
  httpd_status_pages_default,
  (u16_t)LWIP_ARRAYSIZE(httpd_status_pages_default),
  NULL
};
#endif /* LWIP_HTTPD_STATUS_PAGES_DEFAULTS */

static int
httpd_status_pages_open(struct fs_file *file, const char *name)
{
  const struct httpd_status_page_table *t;
  u16_t i;

  for (t = httpd_status_page_tables; t != NULL; t = t->next) {
    for (i = 0; i < t->count; i++) {
      const struct httpd_status_page *pg = &t->pages[i];
      if ((pg->uri != NULL) && !strcmp(name, pg->uri)) {
        file->data = pg->page;
        file->len = pg->len;
        file->index = pg->len;
        file->flags = FS_FILE_FLAGS_HEADER_INCLUDED;
#if HTTPD_PRECALCULATED_CHECKSUM
        file->chksum_count = 0;
        file->chksum = NULL;
#endif /* HTTPD_PRECALCULATED_CHECKSUM */
#if LWIP_HTTPD_FILE_EXTENSION
        file->pextension = NULL;
#endif /* LWIP_HTTPD_FILE_EXTENSION */
#if LWIP_HTTPD_FILE_STATE
        file->state = NULL;
#endif /* LWIP_HTTPD_FILE_STATE */
        return 1;
      }
    }
  }
  return 0;
}

static struct fs_custom_provider httpd_status_pages_provider;

/**
 * @ingroup httpd
 * Register the status page provider (after fsdata) and, with
 * LWIP_HTTPD_STATUS_PAGES_DEFAULTS, the default pages. Call once,
 * e.g. right after httpd_init().
 */
void
httpd_status_pages_init(void)
{
  memset(&httpd_status_pages_provider, 0, sizeof(httpd_status_pages_provider));
  httpd_status_pages_provider.open = httpd_status_pages_open;
  /* no read/close functions: the whole page is in file->data and
     file->index == file->len, so fs_read() never asks the provider */
  if (fs_custom_provider_register(&httpd_status_pages_provider, FS_CUSTOM_PROVIDER_AFTER_FSDATA) != ERR_OK) {
    LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_status_pages_init: already initialized\n"));
    return;
  }
#if LWIP_HTTPD_STATUS_PAGES_DEFAULTS
  httpd_status_pages_add(&httpd_status_pages_default_table);
#endif /* LWIP_HTTPD_STATUS_PAGES_DEFAULTS */
}

/**
 * @ingroup httpd
 * Add a table of pages. Tables added later are searched first, so an
 * application table can replace single default pages.
 *
 * @param table the table, must stay valid (it is linked into a list)
 * @return ERR_OK, ERR_ARG on invalid table, ERR_VAL if already added
 */
err_t
httpd_status_pages_add(struct httpd_status_page_table *table)
{
  struct httpd_status_page_table *t;

  LWIP_ERROR("httpd_status_pages_add: invalid table",
             (table != NULL) && ((table->pages != NULL) || (table->count == 0)), return ERR_ARG;);
  for (t = httpd_status_page_tables; t != NULL; t = t->next) {
    if (t == table) {
      return ERR_VAL;
    }
  }
  table->next = httpd_status_page_tables;
  httpd_status_page_tables = table;
  return ERR_OK;
}

#endif /* LWIP_HTTPD_STATUS_PAGES */
