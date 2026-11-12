/**
 * @file
 * HTTP server WebSocket extension (private interface between httpd.c,
 * httpd_ws.c and the unit tests; not for applications)
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
#ifndef LWIP_HDR_APPS_HTTPD_WS_PRIV_H
#define LWIP_HDR_APPS_HTTPD_WS_PRIV_H

#include "lwip/apps/httpd_opts.h"

#if LWIP_HTTPD_SUPPORT_WEBSOCKET && LWIP_TCP && LWIP_CALLBACK_API

#include "lwip/arch.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Length of a SHA-1 digest in bytes */
#define HTTPD_WS_SHA1_DIGEST_LEN  20
/** Number of characters produced by base64-encoding n bytes */
#define HTTPD_WS_BASE64_LEN(n)    ((((n) + 2) / 3) * 4)

void  httpd_ws_sha1(const u8_t *input, u16_t len, u8_t *digest);
u16_t httpd_ws_base64_encode(const u8_t *input, u16_t len, char *output);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HTTPD_SUPPORT_WEBSOCKET && LWIP_TCP && LWIP_CALLBACK_API */

#endif /* LWIP_HDR_APPS_HTTPD_WS_PRIV_H */
