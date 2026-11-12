/**
 * @file
 * HTTPD example for file upload (LWIP_HTTPD_UPLOAD).
 *
 * Accepts "*.bin" and "*.txt" files at "/upload" (or "/upload/name.bin")
 * and prints their size and a simple checksum instead of storing them.
 * Try: curl -F "file=@test.bin" http://<address>/upload
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

#include "lwip/opt.h"
#include "upload_example.h"

#include "lwip/apps/httpd.h"
#include "lwip/apps/httpd_upload.h"
#include "lwip/apps/httpd_status_pages.h"
#include "lwip/def.h"

#include <string.h>

/** define LWIP_HTTPD_EXAMPLE_UPLOAD to 1 to enable this example */
#ifndef LWIP_HTTPD_EXAMPLE_UPLOAD
#define LWIP_HTTPD_EXAMPLE_UPLOAD 0
#endif

#if LWIP_HTTPD_EXAMPLE_UPLOAD

#if !LWIP_HTTPD_UPLOAD
#error This needs LWIP_HTTPD_UPLOAD
#endif

struct upload_ex_file {
  u8_t in_use;
  char name[HTTP_MULTIPART_MAX_FILENAME + 1];
  u32_t size;
  u32_t sum;
};

/* HTTPD_UPLOAD_MAX_SESSIONS files can be open at the same time */
static struct upload_ex_file upload_ex_files[HTTPD_UPLOAD_MAX_SESSIONS];

static void *
upload_ex_open(const char *filename, u32_t body_len_max, void *arg)
{
  u16_t i;
  LWIP_UNUSED_ARG(arg);
  for (i = 0; i < HTTPD_UPLOAD_MAX_SESSIONS; i++) {
    struct upload_ex_file *f = &upload_ex_files[i];
    if (!f->in_use) {
      memset(f, 0, sizeof(*f));
      f->in_use = 1;
      strncpy(f->name, filename, sizeof(f->name) - 1);
      LWIP_PLATFORM_DIAG(("upload: %s started (request size %"U32_F")\n", filename, body_len_max));
      return f;
    }
  }
  return NULL;
}

static err_t
upload_ex_write(void *handle, const u8_t *data, u16_t len)
{
  struct upload_ex_file *f = (struct upload_ex_file *)handle;
  u16_t i;
  for (i = 0; i < len; i++) {
    f->sum += data[i];
  }
  f->size += len;
  return ERR_OK;
}

static void
upload_ex_close(void *handle, u8_t ok)
{
  struct upload_ex_file *f = (struct upload_ex_file *)handle;
  LWIP_PLATFORM_DIAG(("upload: %s %s, %"U32_F" bytes, sum 0x%08"X32_F"\n",
                      f->name, ok ? "complete" : "aborted", f->size, f->sum));
  f->in_use = 0;
}

static const struct httpd_upload_route upload_ex_routes[] = {
  { "*.bin", upload_ex_open, upload_ex_write, upload_ex_close, NULL },
  { "*.txt", upload_ex_open, upload_ex_write, upload_ex_close, NULL }
};

#if LWIP_HTTPD_STATUS_PAGES
/* a visible page for browsers instead of the default "204 No Content" */
static const struct httpd_status_page upload_ex_pages[] = {
  HTTPD_STATUS_PAGE("/204.html", "200 OK",
                    "<html><body><h1>Upload complete</h1></body></html>")
};
static struct httpd_status_page_table upload_ex_page_table = {
  upload_ex_pages, (u16_t)LWIP_ARRAYSIZE(upload_ex_pages), NULL
};
#endif /* LWIP_HTTPD_STATUS_PAGES */

/** Call after httpd_init() */
void
upload_ex_init(void)
{
#if LWIP_HTTPD_STATUS_PAGES
  httpd_status_pages_init();
  httpd_status_pages_add(&upload_ex_page_table);
#endif /* LWIP_HTTPD_STATUS_PAGES */
  httpd_upload_set_routes(upload_ex_routes, (u16_t)LWIP_ARRAYSIZE(upload_ex_routes));
  httpd_upload_init();
}

#endif /* LWIP_HTTPD_EXAMPLE_UPLOAD */
