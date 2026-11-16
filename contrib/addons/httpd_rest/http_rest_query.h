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
 * Parser for URL query strings and application/x-www-form-urlencoded bodies
 * ("key=value&key=value"), used by the httpd REST router.
 *
 * Parsing works in place: '=' and '&' are replaced by NUL bytes and keys and
 * values are percent-decoded ("%XX" -> byte 0xXX, '+' -> ' ') inside the
 * caller's buffer. The resulting key and value pointers point into that
 * buffer.
 */

#ifndef LWIP_HDR_CONTRIB_ADDONS_HTTP_REST_QUERY_H
#define LWIP_HDR_CONTRIB_ADDONS_HTTP_REST_QUERY_H

#include "lwip/opt.h"
#include "lwip/err.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** One decoded key/value pair */
typedef struct http_rest_kv {
  /** NUL-terminated, decoded key; never contains a NUL byte itself */
  const char *key;
  /** NUL-terminated, decoded value, or NULL if the pair had no '='
   * ("flag" vs. "flag="). May contain NUL bytes (from "%00"): use
   * value_len for the real length. */
  const char *value;
  /** Length of the decoded value in bytes (0 if value is NULL) */
  size_t value_len;
} http_rest_kv_t;

size_t http_rest_url_decode(char *buf, size_t len);
err_t http_rest_query_parse(char *buf, size_t len,
                            http_rest_kv_t *kv, size_t kv_max, size_t *kv_count);
const http_rest_kv_t *http_rest_kv_find(const http_rest_kv_t *kv, size_t kv_count,
                                        const char *key);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_CONTRIB_ADDONS_HTTP_REST_QUERY_H */
