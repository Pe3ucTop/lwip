/**
 * @file
 * SHA-1 (FIPS 180-4) one-shot digest for the httpd WebSocket handshake.
 *
 * Only used to compute the Sec-WebSocket-Accept value (RFC 6455 4.2.2).
 * SHA-1 is not used for any security purpose here. A port that already has a
 * SHA-1 implementation can redirect @ref LWIP_HTTPD_WS_SHA1 to it.
 *
 * The algorithm follows the public domain implementation by Brad Conte
 * (crypto-algorithms), reduced to a one-shot function with a 16-word
 * rolling message schedule.
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

#include <string.h>

#define WS_SHA1_ROTL(x, n)  ((u32_t)(((x) << (n)) | ((x) >> (32 - (n)))))

struct ws_sha1_ctx {
  u32_t state[5];
  u32_t bytes;     /* total input length in bytes (< 2^29 supported) */
  u8_t  block[64];
  u8_t  fill;      /* bytes currently in block[] */
};

static void
ws_sha1_transform(struct ws_sha1_ctx *ctx)
{
  u32_t w[16];
  u32_t a, b, c, d, e, f, k, t;
  u8_t i;

  for (i = 0; i < 16; i++) {
    w[i] = ((u32_t)ctx->block[4 * i] << 24) |
           ((u32_t)ctx->block[4 * i + 1] << 16) |
           ((u32_t)ctx->block[4 * i + 2] << 8) |
           ((u32_t)ctx->block[4 * i + 3]);
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  for (i = 0; i < 80; i++) {
    if (i >= 16) {
      t = w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15];
      w[i & 15] = WS_SHA1_ROTL(t, 1);
    }
    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999UL;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1UL;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDCUL;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6UL;
    }
    t = WS_SHA1_ROTL(a, 5) + f + e + k + w[i & 15];
    e = d;
    d = c;
    c = WS_SHA1_ROTL(b, 30);
    b = a;
    a = t;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
}

/**
 * Compute the SHA-1 digest of a buffer.
 *
 * @param input data to hash
 * @param len length of input in bytes
 * @param digest output, HTTPD_WS_SHA1_DIGEST_LEN (20) bytes
 */
void
httpd_ws_sha1(const u8_t *input, u16_t len, u8_t *digest)
{
  struct ws_sha1_ctx ctx;
  u32_t bits;
  u16_t i;

  LWIP_ASSERT("input != NULL || len == 0", (input != NULL) || (len == 0));
  LWIP_ASSERT("digest != NULL", digest != NULL);

  ctx.state[0] = 0x67452301UL;
  ctx.state[1] = 0xEFCDAB89UL;
  ctx.state[2] = 0x98BADCFEUL;
  ctx.state[3] = 0x10325476UL;
  ctx.state[4] = 0xC3D2E1F0UL;
  ctx.bytes = len;
  ctx.fill = 0;

  for (i = 0; i < len; i++) {
    ctx.block[ctx.fill++] = input[i];
    if (ctx.fill == 64) {
      ws_sha1_transform(&ctx);
      ctx.fill = 0;
    }
  }

  /* padding: 0x80, zeros, 64-bit big-endian bit length */
  ctx.block[ctx.fill++] = 0x80;
  if (ctx.fill > 56) {
    memset(&ctx.block[ctx.fill], 0, (size_t)(64 - ctx.fill));
    ws_sha1_transform(&ctx);
    ctx.fill = 0;
  }
  memset(&ctx.block[ctx.fill], 0, (size_t)(56 - ctx.fill));
  bits = ctx.bytes << 3;
  ctx.block[56] = 0;
  ctx.block[57] = 0;
  ctx.block[58] = 0;
  ctx.block[59] = (u8_t)(ctx.bytes >> 29);
  ctx.block[60] = (u8_t)(bits >> 24);
  ctx.block[61] = (u8_t)(bits >> 16);
  ctx.block[62] = (u8_t)(bits >> 8);
  ctx.block[63] = (u8_t)bits;
  ws_sha1_transform(&ctx);

  for (i = 0; i < 5; i++) {
    digest[4 * i]     = (u8_t)(ctx.state[i] >> 24);
    digest[4 * i + 1] = (u8_t)(ctx.state[i] >> 16);
    digest[4 * i + 2] = (u8_t)(ctx.state[i] >> 8);
    digest[4 * i + 3] = (u8_t)(ctx.state[i]);
  }
}

#endif /* LWIP_HTTPD_SUPPORT_WEBSOCKET && LWIP_TCP && LWIP_CALLBACK_API */
