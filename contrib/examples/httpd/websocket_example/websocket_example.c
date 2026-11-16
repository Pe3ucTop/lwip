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

/*
 * WebSocket example for the lwIP httpd (LWIP_HTTPD_SUPPORT_WEBSOCKET).
 *
 * "/echo": every message is sent back; text "count" answers the number of
 *          open connections, text "bye" closes the connection from the
 *          server side.
 * "/tick": the server pushes a text message with a counter every second to
 *          all clients of this URI (httpd_ws_broadcast_uri()).
 *
 * Try it from a browser console:
 *   ws = new WebSocket("ws://<address>/echo");
 *   ws.onmessage = function (e) { console.log(e.data); };
 *   ws.send("hello");
 */

#include "lwip/opt.h"
#include "websocket_example.h"

#include "lwip/apps/httpd.h"

/** define LWIP_HTTPD_EXAMPLE_WEBSOCKET to 1 to enable this example */
#ifndef LWIP_HTTPD_EXAMPLE_WEBSOCKET
#define LWIP_HTTPD_EXAMPLE_WEBSOCKET 0
#endif

#if LWIP_HTTPD_EXAMPLE_WEBSOCKET

#if !LWIP_HTTPD_SUPPORT_WEBSOCKET
#error LWIP_HTTPD_EXAMPLE_WEBSOCKET needs LWIP_HTTPD_SUPPORT_WEBSOCKET
#endif

#include "lwip/apps/httpd_ws.h"
#include "lwip/timeouts.h"

#include <stdio.h>
#include <string.h>

static int ws_ex_open_count;
static u32_t ws_ex_ticks;

static void
ws_ex_open(const httpd_ws_req_t *req)
{
  LWIP_UNUSED_ARG(req);
  ws_ex_open_count++;
}

static void
ws_ex_close(struct altcp_pcb *pcb, void *user_ctx, u16_t code,
            const u8_t *reason, u16_t reason_len)
{
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(user_ctx);
  LWIP_UNUSED_ARG(reason);
  LWIP_UNUSED_ARG(reason_len);
  LWIP_UNUSED_ARG(code);
  ws_ex_open_count--;
}

static void
ws_ex_echo_msg(struct altcp_pcb *pcb, void *user_ctx, const u8_t *data,
               u16_t len, u8_t opcode)
{
  LWIP_UNUSED_ARG(user_ctx);
  if ((opcode == WS_OPCODE_TEXT) && (len == 5) && (memcmp(data, "count", 5) == 0)) {
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d open", ws_ex_open_count);
    if (n > 0) {
      httpd_ws_write(pcb, (const u8_t *)buf, (u32_t)n, WS_OPCODE_TEXT);
    }
  } else if ((opcode == WS_OPCODE_TEXT) && (len == 3) && (memcmp(data, "bye", 3) == 0)) {
    static const char reason[] = "goodbye";
    httpd_ws_close(pcb, WS_CLOSE_NORMAL, (const u8_t *)reason, sizeof(reason) - 1);
  } else {
    /* ERR_MEM (send buffer full) is ignored in this simple example */
    httpd_ws_write(pcb, data, len, opcode);
  }
}

static const httpd_ws_handler_t ws_ex_handlers[] = {
  /* uri,    open_cb,     msg_cb,         msg_pbuf_cb, close_cb,    ping, pong, auth, user_ctx, sent_cb */
  { "/echo", ws_ex_open,  ws_ex_echo_msg, NULL,        ws_ex_close, NULL, NULL, NULL, NULL,     NULL },
  { "/tick", ws_ex_open,  NULL,           NULL,        ws_ex_close, NULL, NULL, NULL, NULL,     NULL }
};

/* runs in the tcpip thread (sys_timeout), so httpd_ws_* may be called */
static void
ws_ex_tick(void *arg)
{
  char buf[32];
  int n;
  LWIP_UNUSED_ARG(arg);
  ws_ex_ticks++;
  n = snprintf(buf, sizeof(buf), "tick %lu", (unsigned long)ws_ex_ticks);
  if (n > 0) {
    httpd_ws_broadcast_uri("/tick", (const u8_t *)buf, (u32_t)n, WS_OPCODE_TEXT);
  }
  sys_timeout(1000, ws_ex_tick, NULL);
}

void
websocket_ex_init(void)
{
  httpd_ws_register_handlers(ws_ex_handlers, LWIP_ARRAYSIZE(ws_ex_handlers));
  sys_timeout(1000, ws_ex_tick, NULL);
}

#endif /* LWIP_HTTPD_EXAMPLE_WEBSOCKET */
