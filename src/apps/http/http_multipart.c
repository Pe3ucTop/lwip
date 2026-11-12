/**
 * @file
 * Streaming multipart/form-data parser (RFC 7578, RFC 2046).
 *
 * The parser is fed with arbitrary pieces of a request body (e.g. the
 * pbufs passed to httpd_post_receive_data()) and reports the parts through
 * callbacks. It does not depend on httpd and keeps no copy of the body:
 * part data is passed on as slices of the input. Bytes that might be the
 * start of a delimiter are held back until the delimiter is confirmed or
 * ruled out; since they always equal a prefix of the delimiter, they are
 * not copied either.
 *
 * Usage:
 * - http_multipart_get_boundary() on the request headers,
 * - http_multipart_init() with the boundary and the callbacks,
 * - http_multipart_parse() for every piece of the body,
 * - http_multipart_finish() at the end of the body.
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

#if LWIP_HTTPD_MULTIPART

#include "lwip/apps/http_multipart.h"
#include "lwip/def.h"
#include "lwip/debug.h"

#include <string.h>

#define HTTP_MULTIPART_STATE_PREAMBLE    0
#define HTTP_MULTIPART_STATE_DELIM_TAIL  1
#define HTTP_MULTIPART_STATE_DELIM_DASH  2
#define HTTP_MULTIPART_STATE_DELIM_LF    3
#define HTTP_MULTIPART_STATE_HEADERS     4
#define HTTP_MULTIPART_STATE_BODY        5
#define HTTP_MULTIPART_STATE_DONE        6
#define HTTP_MULTIPART_STATE_ERROR       7

#define HTTP_MULTIPART_HDR_CD      "Content-Disposition:"
#define HTTP_MULTIPART_HDR_CD_LEN  20
#define HTTP_MULTIPART_HDR_CT      "Content-Type:"
#define HTTP_MULTIPART_HDR_CT_LEN  13

static const char *
mp_skip_ws(const char *s, const char *end)
{
  while ((s < end) && ((*s == ' ') || (*s == '\t'))) {
    s++;
  }
  return s;
}

/* Return the position after the next ';' outside a quoted string, or NULL */
static const char *
mp_next_param(const char *s, const char *end)
{
  u8_t in_quote = 0;
  while (s < end) {
    if (in_quote) {
      if ((*s == '\\') && (s + 1 < end)) {
        s++;
      } else if (*s == '"') {
        in_quote = 0;
      }
    } else if (*s == '"') {
      in_quote = 1;
    } else if (*s == ';') {
      return s + 1;
    }
    s++;
  }
  return NULL;
}

/* Find parameter 'pname' (case-insensitive) in "value; a=b; c="d"" and
   return the start of its value, or NULL */
static const char *
mp_find_param(const char *s, const char *end, const char *pname)
{
  size_t nlen = strlen(pname);
  while ((s = mp_next_param(s, end)) != NULL) {
    s = mp_skip_ws(s, end);
    if (((size_t)(end - s) > nlen) && !lwip_strnicmp(s, pname, nlen)) {
      const char *v = mp_skip_ws(s + nlen, end);
      if ((v < end) && (*v == '=')) {
        return mp_skip_ws(v + 1, end);
      }
    }
  }
  return NULL;
}

/* Copy a token or quoted-string into out (NUL-terminated).
   Returns the length; *truncated is set if it did not fit. */
static u16_t
mp_copy_value(const char *s, const char *end, char *out, u16_t out_size, u8_t *truncated)
{
  u16_t n = 0;
  u8_t quoted = 0;

  if ((s < end) && (*s == '"')) {
    quoted = 1;
    s++;
  }
  while (s < end) {
    char c = *s;
    if (quoted) {
      if (c == '"') {
        break;
      }
      if ((c == '\\') && (s + 1 < end)) {
        s++;
        c = *s;
      }
    } else if ((c == ';') || (c == ' ') || (c == '\t')) {
      break;
    }
    if (n + 1 < out_size) {
      out[n++] = c;
    } else {
      *truncated = 1;
    }
    s++;
  }
  if (out_size > 0) {
    out[n] = 0;
  }
  return n;
}

/**
 * @ingroup httpd
 * Get the boundary from the Content-Type header of a request.
 * The header name, the media type and the parameter name are compared
 * case-insensitively; quoted and unquoted boundaries are accepted.
 *
 * @param headers request headers, e.g. the http_request passed to
 *        httpd_post_begin() (need not be NUL-terminated)
 * @param headers_len length of headers
 * @param boundary receives the NUL-terminated boundary
 * @param boundary_size size of boundary (HTTP_MULTIPART_MAX_BOUNDARY + 1 is enough)
 * @return ERR_OK; ERR_VAL if there is no multipart Content-Type;
 *         ERR_ARG if the boundary is missing, empty or too long
 */
err_t
http_multipart_get_boundary(const char *headers, u16_t headers_len,
                            char *boundary, u16_t boundary_size)
{
  const char *p = headers;
  const char *end = headers + headers_len;

  LWIP_ERROR("http_multipart_get_boundary: invalid args",
             (headers != NULL) && (boundary != NULL) && (boundary_size > 0), return ERR_ARG;);

  while (p < end) {
    const char *line_end = p;
    while ((line_end < end) && (*line_end != '\r') && (*line_end != '\n') && (*line_end != 0)) {
      line_end++;
    }
    if ((line_end - p >= HTTP_MULTIPART_HDR_CT_LEN) &&
        !lwip_strnicmp(p, HTTP_MULTIPART_HDR_CT, HTTP_MULTIPART_HDR_CT_LEN)) {
      const char *v = mp_skip_ws(p + HTTP_MULTIPART_HDR_CT_LEN, line_end);
      const char *b;
      u8_t truncated = 0;
      u16_t n;
      if ((line_end - v < 10) || lwip_strnicmp(v, "multipart/", 10)) {
        return ERR_VAL;
      }
      b = mp_find_param(v, line_end, "boundary");
      if (b == NULL) {
        return ERR_ARG;
      }
      n = mp_copy_value(b, line_end, boundary, boundary_size, &truncated);
      if (truncated || (n == 0) || (n > HTTP_MULTIPART_MAX_BOUNDARY)) {
        boundary[0] = 0;
        return ERR_ARG;
      }
      return ERR_OK;
    }
    p = line_end;
    if ((p < end) && (*p == 0)) {
      break;
    }
    while ((p < end) && ((*p == '\r') || (*p == '\n'))) {
      p++;
    }
  }
  return ERR_VAL;
}

/**
 * @ingroup httpd
 * Initialize a parser.
 *
 * @param parser parser state
 * @param boundary boundary (see http_multipart_get_boundary())
 * @param cb callbacks, must stay valid while parsing
 * @param cb_arg argument passed to the callbacks
 * @return ERR_OK, ERR_ARG for an empty or too long boundary
 */
err_t
http_multipart_init(struct http_multipart_parser *parser, const char *boundary,
                    const struct http_multipart_callbacks *cb, void *cb_arg)
{
  size_t len;

  LWIP_ERROR("http_multipart_init: invalid args",
             (parser != NULL) && (boundary != NULL) && (cb != NULL), return ERR_ARG;);
  len = strlen(boundary);
  if ((len == 0) || (len > HTTP_MULTIPART_MAX_BOUNDARY)) {
    return ERR_ARG;
  }
  memset(parser, 0, sizeof(*parser));
  parser->cb = cb;
  parser->cb_arg = cb_arg;
  parser->delim[0] = '\r';
  parser->delim[1] = '\n';
  parser->delim[2] = '-';
  parser->delim[3] = '-';
  MEMCPY(&parser->delim[4], boundary, len);
  parser->delim_len = (u8_t)(4 + len);
  parser->state = HTTP_MULTIPART_STATE_PREAMBLE;
  /* the body may start with "--boundary" without a preceding CRLF */
  parser->match = 2;
  return ERR_OK;
}

static err_t
mp_fail(struct http_multipart_parser *parser, err_t err)
{
  parser->state = HTTP_MULTIPART_STATE_ERROR;
  if (parser->part_open) {
    parser->part_open = 0;
    if (parser->cb->part_end != NULL) {
      parser->cb->part_end(parser->cb_arg, 0);
    }
  }
  return err;
}

static err_t
mp_data(struct http_multipart_parser *parser, const u8_t *data, u16_t len)
{
  if ((len > 0) && (parser->cb->part_data != NULL)) {
    return parser->cb->part_data(parser->cb_arg, data, len);
  }
  return ERR_OK;
}

static void
mp_line_append(struct http_multipart_parser *parser, char c)
{
  if (parser->line_len < HTTP_MULTIPART_MAX_HDR_LINE) {
    parser->line[parser->line_len++] = c;
  } else {
    /* keep the start of overlong lines, still wait for the line end */
    parser->line_trunc = 1;
  }
}

static void
mp_header_line(struct http_multipart_parser *parser)
{
  const char *l = parser->line;
  const char *end = l + parser->line_len;
  struct http_multipart_part *part = &parser->part;
  u8_t truncated = 0;

  if ((parser->line_len >= HTTP_MULTIPART_HDR_CD_LEN) &&
      !lwip_strnicmp(l, HTTP_MULTIPART_HDR_CD, HTTP_MULTIPART_HDR_CD_LEN)) {
    const char *v = mp_find_param(l + HTTP_MULTIPART_HDR_CD_LEN, end, "name");
    if (v != NULL) {
      mp_copy_value(v, end, part->name, sizeof(part->name), &truncated);
    }
    v = mp_find_param(l + HTTP_MULTIPART_HDR_CD_LEN, end, "filename");
    if (v != NULL) {
      part->flags |= HTTP_MULTIPART_FLAG_FILENAME;
      mp_copy_value(v, end, part->filename, sizeof(part->filename), &truncated);
    }
  } else if ((parser->line_len >= HTTP_MULTIPART_HDR_CT_LEN) &&
             !lwip_strnicmp(l, HTTP_MULTIPART_HDR_CT, HTTP_MULTIPART_HDR_CT_LEN)) {
    const char *v = mp_skip_ws(l + HTTP_MULTIPART_HDR_CT_LEN, end);
    size_t n;
    while ((end > v) && ((end[-1] == ' ') || (end[-1] == '\t'))) {
      end--;
    }
    n = (size_t)(end - v);
    if (n >= sizeof(part->content_type)) {
      n = sizeof(part->content_type) - 1;
      truncated = 1;
    }
    MEMCPY(part->content_type, v, n);
    part->content_type[n] = 0;
  } else {
    /* other part headers are ignored, also if they were cut */
    return;
  }
  if (truncated || parser->line_trunc) {
    part->flags |= HTTP_MULTIPART_FLAG_TRUNCATED;
  }
}

/**
 * @ingroup httpd
 * Feed the next piece of the body. Pieces may be split anywhere.
 * Data after the closing delimiter is ignored.
 *
 * @param parser parser state
 * @param data body data
 * @param len length of data
 * @return ERR_OK; ERR_VAL for a malformed body or after an earlier error;
 *         an error returned by a callback
 */
err_t
http_multipart_parse(struct http_multipart_parser *parser, const u8_t *data, u16_t len)
{
  u16_t i;
  /* first byte of data not yet passed to part_data() (state BODY) */
  u16_t start = 0;
  /* number of matched delimiter bytes that are not in 'data' */
  u8_t held;
  err_t err;

  LWIP_ERROR("http_multipart_parse: invalid args",
             (parser != NULL) && ((data != NULL) || (len == 0)), return ERR_ARG;);

  held = parser->match;
  for (i = 0; i < len; i++) {
    u8_t b = data[i];
    switch (parser->state) {
      case HTTP_MULTIPART_STATE_PREAMBLE:
        if (b == (u8_t)parser->delim[parser->match]) {
          parser->match++;
          if (parser->match == parser->delim_len) {
            parser->match = 0;
            parser->state = HTTP_MULTIPART_STATE_DELIM_TAIL;
          }
        } else {
          /* the delimiter contains '\r' only at its start, so a failed
             match can only restart at the current byte */
          parser->match = (b == (u8_t)parser->delim[0]) ? 1 : 0;
        }
        break;

      case HTTP_MULTIPART_STATE_DELIM_TAIL:
        if (b == '-') {
          parser->state = HTTP_MULTIPART_STATE_DELIM_DASH;
        } else if (b == '\r') {
          parser->state = HTTP_MULTIPART_STATE_DELIM_LF;
        } else if ((b != ' ') && (b != '\t')) {
          /* only transport padding may follow a delimiter */
          return mp_fail(parser, ERR_VAL);
        }
        break;

      case HTTP_MULTIPART_STATE_DELIM_DASH:
        if (b != '-') {
          return mp_fail(parser, ERR_VAL);
        }
        /* close delimiter: the rest (epilogue) is ignored */
        parser->state = HTTP_MULTIPART_STATE_DONE;
        return ERR_OK;

      case HTTP_MULTIPART_STATE_DELIM_LF:
        if (b != '\n') {
          return mp_fail(parser, ERR_VAL);
        }
        memset(&parser->part, 0, sizeof(parser->part));
        parser->line_len = 0;
        parser->line_cr = 0;
        parser->line_trunc = 0;
        parser->state = HTTP_MULTIPART_STATE_HEADERS;
        break;

      case HTTP_MULTIPART_STATE_HEADERS: {
        u8_t eol = 0;
        if (parser->line_cr) {
          parser->line_cr = 0;
          if (b == '\n') {
            eol = 1;
          } else {
            /* lone CR inside a header line */
            mp_line_append(parser, '\r');
          }
        }
        if (!eol) {
          if (b == '\r') {
            parser->line_cr = 1;
            break;
          } else if (b == '\n') {
            /* tolerate a bare LF as line end */
            eol = 1;
          } else {
            mp_line_append(parser, (char)b);
            break;
          }
        }
        if (parser->line_len == 0) {
          /* empty line: end of the part headers */
          parser->part_open = 1;
          if (parser->cb->part_begin != NULL) {
            err = parser->cb->part_begin(parser->cb_arg, &parser->part);
            if (err != ERR_OK) {
              return mp_fail(parser, err);
            }
          }
          parser->state = HTTP_MULTIPART_STATE_BODY;
          parser->match = 0;
          held = 0;
          start = (u16_t)(i + 1);
        } else {
          parser->line[parser->line_len] = 0;
          mp_header_line(parser);
          parser->line_len = 0;
          parser->line_trunc = 0;
        }
        break;
      }

      case HTTP_MULTIPART_STATE_BODY:
        if (b == (u8_t)parser->delim[parser->match]) {
          parser->match++;
          if (parser->match == parser->delim_len) {
            /* data before the delimiter belongs to the part */
            u16_t run_end = (u16_t)(i + 1 - (parser->match - held));
            err = mp_data(parser, &data[start], (u16_t)(run_end - start));
            if (err != ERR_OK) {
              return mp_fail(parser, err);
            }
            parser->match = 0;
            held = 0;
            parser->part_open = 0;
            if (parser->cb->part_end != NULL) {
              parser->cb->part_end(parser->cb_arg, 1);
            }
            parser->state = HTTP_MULTIPART_STATE_DELIM_TAIL;
          }
        } else if (parser->match > 0) {
          /* not a delimiter: the held bytes are data */
          if (held > 0) {
            /* held bytes from an earlier call precede data[start] */
            err = mp_data(parser, (const u8_t *)parser->delim, held);
            if (err != ERR_OK) {
              return mp_fail(parser, err);
            }
            held = 0;
          }
          /* matched bytes in 'data' stay in the pending run */
          parser->match = (b == (u8_t)parser->delim[0]) ? 1 : 0;
        }
        break;

      case HTTP_MULTIPART_STATE_DONE:
        return ERR_OK;

      default:
        return ERR_VAL;
    }
  }

  if (parser->state == HTTP_MULTIPART_STATE_BODY) {
    /* pass on everything except a possible delimiter start at the end */
    u16_t run_end = (u16_t)(len - (parser->match - held));
    err = mp_data(parser, &data[start], (u16_t)(run_end - start));
    if (err != ERR_OK) {
      return mp_fail(parser, err);
    }
  } else if (parser->state == HTTP_MULTIPART_STATE_ERROR) {
    return ERR_VAL;
  }
  return ERR_OK;
}

/**
 * @ingroup httpd
 * Call at the end of the body. If the close delimiter was not seen, an
 * open part is ended with complete == 0.
 *
 * @param parser parser state
 * @return ERR_OK if the body was complete, ERR_VAL otherwise
 */
err_t
http_multipart_finish(struct http_multipart_parser *parser)
{
  LWIP_ERROR("http_multipart_finish: invalid args", parser != NULL, return ERR_ARG;);
  if (parser->state == HTTP_MULTIPART_STATE_DONE) {
    return ERR_OK;
  }
  return mp_fail(parser, ERR_VAL);
}

#endif /* LWIP_HTTPD_MULTIPART */
