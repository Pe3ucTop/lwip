/**
 * @file
 * Streaming multipart/form-data parser (RFC 7578, RFC 2046)
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

#ifndef LWIP_HDR_APPS_HTTP_MULTIPART_H
#define LWIP_HDR_APPS_HTTP_MULTIPART_H

#include "lwip/apps/httpd_opts.h"
#include "lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_HTTPD_MULTIPART

/** Maximum length of a boundary (RFC 2046) */
#define HTTP_MULTIPART_MAX_BOUNDARY  70

/** http_multipart_part.flags: the part has a filename parameter */
#define HTTP_MULTIPART_FLAG_FILENAME   0x01
/** http_multipart_part.flags: a header line or value did not fit and was cut */
#define HTTP_MULTIPART_FLAG_TRUNCATED  0x02

/**
 * @ingroup httpd
 * Information about one part, taken from its headers.
 * Strings are NUL-terminated and empty if not present.
 */
struct http_multipart_part {
  /** "name" parameter of Content-Disposition (form field name) */
  char name[HTTP_MULTIPART_MAX_NAME + 1];
  /** "filename" parameter of Content-Disposition, as sent by the client */
  char filename[HTTP_MULTIPART_MAX_FILENAME + 1];
  /** value of the part's Content-Type header */
  char content_type[HTTP_MULTIPART_MAX_CONTENT_TYPE + 1];
  /** HTTP_MULTIPART_FLAG_* */
  u8_t flags;
};

/**
 * @ingroup httpd
 * Parser callbacks. All are optional (may be NULL).
 */
struct http_multipart_callbacks {
  /** headers of a part are complete; return != ERR_OK to stop parsing */
  err_t (*part_begin)(void *arg, const struct http_multipart_part *part);
  /** body data of the current part; return != ERR_OK to stop parsing */
  err_t (*part_data)(void *arg, const u8_t *data, u16_t len);
  /** end of the current part; complete is 0 if the body was cut off
      or parsing was stopped */
  void (*part_end)(void *arg, u8_t complete);
};

/**
 * @ingroup httpd
 * Parser state; treat as opaque.
 */
struct http_multipart_parser {
  const struct http_multipart_callbacks *cb;
  void *cb_arg;
  /* "\r\n--" boundary */
  char delim[4 + HTTP_MULTIPART_MAX_BOUNDARY];
  u8_t delim_len;
  /* number of bytes of delim matched so far */
  u8_t match;
  u8_t state;
  u8_t part_open;
  u8_t line_cr;
  u8_t line_trunc;
  u16_t line_len;
  char line[HTTP_MULTIPART_MAX_HDR_LINE + 1];
  struct http_multipart_part part;
};

err_t http_multipart_get_boundary(const char *headers, u16_t headers_len,
                                  char *boundary, u16_t boundary_size);
err_t http_multipart_init(struct http_multipart_parser *parser, const char *boundary,
                          const struct http_multipart_callbacks *cb, void *cb_arg);
err_t http_multipart_parse(struct http_multipart_parser *parser, const u8_t *data, u16_t len);
err_t http_multipart_finish(struct http_multipart_parser *parser);

#endif /* LWIP_HTTPD_MULTIPART */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_APPS_HTTP_MULTIPART_H */
