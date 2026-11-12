/**
 * @file
 * HTTP server WebSocket extension (RFC 6455)
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
#ifndef LWIP_HDR_APPS_HTTPD_WS_H
#define LWIP_HDR_APPS_HTTPD_WS_H

#include "lwip/apps/httpd_opts.h"

#if LWIP_HTTPD_SUPPORT_WEBSOCKET && LWIP_TCP && LWIP_CALLBACK_API

#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/altcp.h"

#include <stddef.h> /* size_t */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup httpd_ws WebSocket server
 * @ingroup httpd
 * WebSocket (RFC 6455) server extension for the lwIP httpd.
 *
 * A GET request with "Upgrade: websocket" for a URI registered with
 * httpd_ws_register_handlers() is answered with "101 Switching Protocols"
 * and the TCP connection is handed over to this module. All other requests
 * are served by httpd as before.
 *
 * Features: frame reassembly across TCP segments and pbuf chains,
 * automatic PONG,
 * optional server keep-alive PING, close handshake with timeout, per-URI
 * authentication callback or HTTP Basic authentication, flat-buffer or
 * pbuf-chain receive callbacks.
 *
 * Not supported: fragmented messages (continuation frames), extensions (e.g. permessage-deflate), subprotocol
 * negotiation (Sec-WebSocket-Protocol is ignored), client role.
 *
 * Thread context: all functions of this API must be called from the tcpip
 * thread (e.g. from a callback of this module or via tcpip_callback()) or
 * with the core lock held (LOCK_TCPIP_CORE()). Callbacks are called from
 * the tcpip thread. A callback must not call httpd_ws_* functions for the
 * connection that is being closed from inside its own close_cb.
 * @{
 */

/** WebSocket frame opcodes (RFC 6455, 5.2) */
#define WS_OPCODE_CONT              0x00
#define WS_OPCODE_TEXT              0x01
#define WS_OPCODE_BIN               0x02
#define WS_OPCODE_CLOSE             0x08
#define WS_OPCODE_PING              0x09
#define WS_OPCODE_PONG              0x0A

/** Close status codes (RFC 6455, 7.4.1) */
#define WS_CLOSE_NORMAL             1000
#define WS_CLOSE_GOING_AWAY         1001
#define WS_CLOSE_PROTOCOL_ERROR     1002
#define WS_CLOSE_UNSUPPORTED_DATA   1003
#define WS_CLOSE_NO_STATUS          1005
#define WS_CLOSE_ABNORMAL           1006
#define WS_CLOSE_INVALID_PAYLOAD    1007
#define WS_CLOSE_POLICY_VIOLATION   1008
#define WS_CLOSE_MESSAGE_TOO_BIG    1009
#define WS_CLOSE_INTERNAL_ERROR     1011

/** Result of an authentication callback */
typedef enum {
  /** accept the upgrade */
  HTTPD_WS_AUTH_OK = 0,
  /** answer "401 Unauthorized" (with a Basic challenge) */
  HTTPD_WS_AUTH_REJECTED = 1,
  /** answer "403 Forbidden" */
  HTTPD_WS_AUTH_FORBIDDEN = 2
} httpd_ws_auth_result_t;

/** Upgrade request as seen by auth_cb and open_cb.
 * uri and headers point into the request buffer and are only valid during
 * the callback. headers starts at the first header line (after the request
 * line) and is not NUL-terminated. */
typedef struct {
  struct altcp_pcb *pcb;
  const char *uri;
  const char *headers;
  u16_t headers_len;
  void *user_ctx;
} httpd_ws_req_t;

/** Decide whether an upgrade request is accepted (e.g. check a cookie,
 * token or Origin header). Called before any response is sent. */
typedef httpd_ws_auth_result_t (*httpd_ws_auth_fn)(const httpd_ws_req_t *req);

/** Called after the 101 response has been queued; the connection is open
 * and httpd_ws_write() may be used. */
typedef void (*httpd_ws_open_fn)(const httpd_ws_req_t *req);

/** Complete message, flat buffer receive callback.
 * @param pcb connection
 * @param user_ctx user_ctx of the handler
 * @param data unmasked payload of the complete message;
 *        only valid during the callback, may be modified in place
 * @param len payload length (at most LWIP_HTTPD_WS_RX_BUF_SIZE)
 * @param opcode WS_OPCODE_TEXT or WS_OPCODE_BIN
 */
typedef void (*httpd_ws_msg_fn)(struct altcp_pcb *pcb, void *user_ctx,
                                const u8_t *data, u16_t len, u8_t opcode);

/** Complete message, pbuf chain receive callback.
 * @param pcb connection
 * @param user_ctx user_ctx of the handler
 * @param p unmasked payload as a pbuf chain (p->tot_len == len); freed by
 *        the caller after the callback returns: call pbuf_ref() to keep it
 * @param len payload length (at most LWIP_HTTPD_WS_MAX_MSG_SIZE)
 * @param opcode WS_OPCODE_TEXT or WS_OPCODE_BIN
 */
typedef void (*httpd_ws_msg_pbuf_fn)(struct altcp_pcb *pcb, void *user_ctx,
                                     struct pbuf *p, u16_t len, u8_t opcode);

/** Connection closed (close handshake finished, protocol error, timeout,
 * TCP reset or local close).
 * @param pcb identity of the connection only: it may already be freed
 *        (TCP error/reset) and must not be used to send anything
 * @param user_ctx user_ctx of the handler
 * @param code close code received from the peer, or the code sent by the
 *        server if the peer did not send one, or WS_CLOSE_ABNORMAL (1006)
 *        if the connection ended without a close frame
 * @param reason close reason received from the peer (not NUL-terminated,
 *        may be NULL)
 * @param reason_len length of reason
 */
typedef void (*httpd_ws_close_fn)(struct altcp_pcb *pcb, void *user_ctx,
                                  u16_t code, const u8_t *reason, u16_t reason_len);

/** PING or PONG received (the PONG answer to a PING is sent automatically) */
typedef void (*httpd_ws_ctrl_fn)(struct altcp_pcb *pcb, void *user_ctx,
                                 const u8_t *payload, u16_t len);

/** Handler for one URI. The array passed to httpd_ws_register_handlers()
 * must stay valid while the server runs.
 * For each connection exactly one receive callback is used: msg_pbuf_cb if
 * set, else msg_cb. Without both, data messages are discarded (control
 * frames are still handled). All callbacks are optional. */
typedef struct {
  /** URI to match (exact, case-sensitive, e.g. "/ws") */
  const char *uri;
  httpd_ws_open_fn open_cb;
  httpd_ws_msg_fn msg_cb;
  httpd_ws_msg_pbuf_fn msg_pbuf_cb;
  httpd_ws_close_fn close_cb;
  httpd_ws_ctrl_fn ping_cb;
  httpd_ws_ctrl_fn pong_cb;
  /** NULL: use the credentials of httpd_ws_set_basic_auth() (if any) */
  httpd_ws_auth_fn auth_cb;
  void *user_ctx;
} httpd_ws_handler_t;

void  httpd_ws_register_handlers(const httpd_ws_handler_t *handlers, size_t count);
void  httpd_ws_set_basic_auth(const char *username, const char *password);

err_t httpd_ws_write(struct altcp_pcb *pcb, const u8_t *data, u16_t len, u8_t opcode);
err_t httpd_ws_broadcast(const u8_t *data, u16_t len, u8_t opcode);
err_t httpd_ws_broadcast_uri(const char *uri, const u8_t *data, u16_t len, u8_t opcode);
err_t httpd_ws_ping(struct altcp_pcb *pcb, const u8_t *payload, u16_t len);
err_t httpd_ws_close(struct altcp_pcb *pcb, u16_t code, const u8_t *reason, u16_t reason_len);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HTTPD_SUPPORT_WEBSOCKET && LWIP_TCP && LWIP_CALLBACK_API */

#endif /* LWIP_HDR_APPS_HTTPD_WS_H */
