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
 * Parser for URL query strings and application/x-www-form-urlencoded bodies.
 */

#include "http_rest_query.h"

#include "lwip/def.h"

#include <string.h>

/** Convert one hex digit to its value, returns -1 for a non-hex character */
static int
http_rest_hex_digit(char c)
{
  if ((c >= '0') && (c <= '9')) {
    return c - '0';
  }
  if ((c >= 'a') && (c <= 'f')) {
    return c - 'a' + 10;
  }
  if ((c >= 'A') && (c <= 'F')) {
    return c - 'A' + 10;
  }
  return -1;
}

/**
 * Percent-decode exactly len bytes of buf in place: "%XX" becomes the byte
 * 0xXX (including "%00"), '+' becomes ' '. A '%' that is not followed by
 * two hex digits within len is kept as it is.
 * The buffer is not NUL-terminated by this function.
 *
 * @param buf data to decode (may be NULL if len is 0)
 * @param len number of bytes in buf; buf[len] is never accessed
 * @return length of the decoded data (always <= len)
 */
size_t
http_rest_url_decode(char *buf, size_t len)
{
  size_t in, out;
  int hi, lo;

  for (in = 0, out = 0; in < len; in++, out++) {
    if (buf[in] == '+') {
      buf[out] = ' ';
    } else if ((buf[in] == '%') && (len - in > 2)) {
      hi = http_rest_hex_digit(buf[in + 1]);
      lo = http_rest_hex_digit(buf[in + 2]);
      if ((hi >= 0) && (lo >= 0)) {
        buf[out] = (char)((hi << 4) | lo);
        in += 2;
      } else {
        buf[out] = buf[in];
      }
    } else {
      buf[out] = buf[in];
    }
  }
  return out;
}

/**
 * Parse "key=value&key=value..." in place.
 *
 * Exactly len bytes of buf are parsed. buf does not need to be
 * NUL-terminated, but it must provide len + 1 writable bytes: the
 * terminator of the last key or value may be written to buf[len].
 *
 * Empty pairs ("&&", leading or trailing '&') and pairs with an empty key
 * ("=x") are skipped. Pairs are split at '&' and '=' before decoding, so
 * "%26" and "%3D" are part of a key or value.
 *
 * @param buf writable input buffer, modified in place
 * @param len number of input bytes in buf
 * @param kv storage for the parsed pairs (pointers point into buf)
 * @param kv_max number of elements in kv
 * @param kv_count returns the number of pairs stored in kv
 * @return ERR_OK on success,
 *         ERR_BUF if there were more than kv_max pairs (the first kv_max
 *                 pairs are stored, the rest of buf is left unparsed),
 *         ERR_VAL if a key contained "%00" (*kv_count pairs before it are valid),
 *         ERR_ARG on invalid arguments
 */
err_t
http_rest_query_parse(char *buf, size_t len,
                      http_rest_kv_t *kv, size_t kv_max, size_t *kv_count)
{
  size_t pos = 0;
  size_t count = 0;

  if (kv_count == NULL) {
    return ERR_ARG;
  }
  *kv_count = 0;
  if (((buf == NULL) && (len != 0)) || ((kv == NULL) && (kv_max != 0))) {
    return ERR_ARG;
  }

  while (pos < len) {
    size_t start = pos;
    size_t end;
    size_t eq = len;
    size_t key_len, value_len;
    char *key, *value;

    /* find the end of this pair and the first '=' in it */
    for (end = start; (end < len) && (buf[end] != '&'); end++) {
      if ((buf[end] == '=') && (eq == len)) {
        eq = end;
      }
    }
    pos = end + 1;
    if (eq > end) {
      eq = end;
    }
    if (eq == start) {
      /* empty pair or empty key: skip */
      continue;
    }
    if (count == kv_max) {
      *kv_count = count;
      return ERR_BUF;
    }

    key = &buf[start];
    key_len = http_rest_url_decode(key, eq - start);
    if (memchr(key, 0, key_len) != NULL) {
      *kv_count = count;
      return ERR_VAL;
    }
    if (eq < end) {
      value = &buf[eq + 1];
      value_len = http_rest_url_decode(value, end - (eq + 1));
      /* end <= len, so this writes at most buf[len] */
      value[value_len] = '\0';
    } else {
      value = NULL;
      value_len = 0;
    }
    /* key ends at or before eq (or end), so this is at most buf[len] and
       never touches the value */
    key[key_len] = '\0';

    kv[count].key = key;
    kv[count].value = value;
    kv[count].value_len = value_len;
    count++;
  }

  *kv_count = count;
  return ERR_OK;
}

/**
 * Look up a key in a parsed array (case-sensitive, first match wins).
 *
 * @param kv parsed pairs
 * @param kv_count number of pairs in kv
 * @param key NUL-terminated key to look for
 * @return the matching pair, or NULL if the key is not present
 */
const http_rest_kv_t *
http_rest_kv_find(const http_rest_kv_t *kv, size_t kv_count, const char *key)
{
  size_t i;

  if ((kv == NULL) || (key == NULL)) {
    return NULL;
  }
  for (i = 0; i < kv_count; i++) {
    if ((kv[i].key != NULL) && (strcmp(kv[i].key, key) == 0)) {
      return &kv[i];
    }
  }
  return NULL;
}
