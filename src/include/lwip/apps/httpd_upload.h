/**
 * @file
 * HTTP server: file upload by POST with multipart/form-data
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

#ifndef LWIP_HDR_APPS_HTTPD_UPLOAD_H
#define LWIP_HDR_APPS_HTTPD_UPLOAD_H

#include "lwip/apps/httpd_opts.h"
#include "lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_HTTPD_UPLOAD

/**
 * @ingroup httpd
 * Writer for uploaded files whose name matches @p pattern.
 *
 * - open(): a file part starts. @p body_len_max is the Content-Length of the
 *   whole request, i.e. an upper bound of the file size (the exact size is
 *   only known at close()). Return a handle or NULL to reject the file
 *   (HTTPD_UPLOAD_URI_ERROR).
 * - write(): file data in pieces of any size; return ERR_OK or an error to
 *   abort the upload (HTTPD_UPLOAD_URI_ERROR).
 * - close(): called once per successful open(); @p ok is 1 if the file was
 *   received completely, 0 if the upload was aborted.
 *
 * All functions run in the httpd (tcpip) context and must not block for long.
 */
struct httpd_upload_route {
  /** "*" (any name), "*suffix" (e.g. "*.bin") or an exact file name */
  const char *pattern;
  void *(*open)(const char *filename, u32_t body_len_max, void *arg);
  err_t (*write)(void *handle, const u8_t *data, u16_t len);
  void (*close)(void *handle, u8_t ok);
  /** passed to open() */
  void *arg;
};

err_t httpd_upload_init(void);
void httpd_upload_set_routes(const struct httpd_upload_route *routes, u16_t count);
void httpd_upload_set_uri(const char *uri);

#endif /* LWIP_HTTPD_UPLOAD */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_APPS_HTTPD_UPLOAD_H */
