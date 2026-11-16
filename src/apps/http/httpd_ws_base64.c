/**
 * @file
 * Base64 encoder (RFC 4648) for the httpd WebSocket handshake.
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
 * Author: Maksims Matjakubovs
 */

#include "lwip/apps/httpd_opts.h"

#if LWIP_HTTPD_SUPPORT_WEBSOCKET && LWIP_TCP && LWIP_CALLBACK_API

#include "lwip/apps/httpd_ws_priv.h"

static const char ws_base64_alphabet[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Base64-encode a buffer (with '=' padding, no line breaks, no NUL).
 *
 * @param input data to encode
 * @param len length of input in bytes
 * @param output destination, must hold HTTPD_WS_BASE64_LEN(len) bytes
 * @return number of characters written
 */
u16_t
httpd_ws_base64_encode(const u8_t *input, u16_t len, char *output)
{
  u16_t i = 0;
  u16_t o = 0;
  u32_t v;

  LWIP_ASSERT("input != NULL || len == 0", (input != NULL) || (len == 0));
  LWIP_ASSERT("output != NULL", output != NULL);

  while ((u16_t)(len - i) >= 3) {
    v = ((u32_t)input[i] << 16) | ((u32_t)input[i + 1] << 8) | (u32_t)input[i + 2];
    output[o++] = ws_base64_alphabet[(v >> 18) & 0x3F];
    output[o++] = ws_base64_alphabet[(v >> 12) & 0x3F];
    output[o++] = ws_base64_alphabet[(v >> 6) & 0x3F];
    output[o++] = ws_base64_alphabet[v & 0x3F];
    i = (u16_t)(i + 3);
  }
  if ((u16_t)(len - i) == 1) {
    v = (u32_t)input[i] << 16;
    output[o++] = ws_base64_alphabet[(v >> 18) & 0x3F];
    output[o++] = ws_base64_alphabet[(v >> 12) & 0x3F];
    output[o++] = '=';
    output[o++] = '=';
  } else if ((u16_t)(len - i) == 2) {
    v = ((u32_t)input[i] << 16) | ((u32_t)input[i + 1] << 8);
    output[o++] = ws_base64_alphabet[(v >> 18) & 0x3F];
    output[o++] = ws_base64_alphabet[(v >> 12) & 0x3F];
    output[o++] = ws_base64_alphabet[(v >> 6) & 0x3F];
    output[o++] = '=';
  }
  return o;
}

#endif /* LWIP_HTTPD_SUPPORT_WEBSOCKET && LWIP_TCP && LWIP_CALLBACK_API */
