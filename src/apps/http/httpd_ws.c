/**
 * @file
 * HTTP server WebSocket extension (RFC 6455)
 *
 * The design follows the WebSocket support added to the lwIP httpd by
 * Sakari Kapanen (esp-open-rtos, extras/httpd) and its descendant
 * lujji/esp-httpd: httpd.c keeps parsing the request, and an upgraded
 * connection is handed over to this module via a few hooks.
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

#include "lwip/apps/httpd_ws.h"
#include "lwip/apps/httpd_ws_priv.h"
#include "lwip/apps/httpd.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/debug.h"
#include "lwip/tcp.h"

#include <string.h>

#if LWIP_HTTPD_WS_MAX_MSG_SIZE > 0xFFFF
#error "LWIP_HTTPD_WS_MAX_MSG_SIZE must not exceed 65535"
#endif
#if LWIP_HTTPD_WS_RX_BUF_SIZE > LWIP_HTTPD_WS_MAX_MSG_SIZE
#error "LWIP_HTTPD_WS_RX_BUF_SIZE must not exceed LWIP_HTTPD_WS_MAX_MSG_SIZE"
#endif
#if (LWIP_HTTPD_WS_PING_INTERVAL_POLLS + LWIP_HTTPD_WS_PONG_TIMEOUT_POLLS) > 255
#error "LWIP_HTTPD_WS_PING_INTERVAL_POLLS + LWIP_HTTPD_WS_PONG_TIMEOUT_POLLS must not exceed 255"
#endif

#define WS_CRLF                 "\r\n"
#define WS_GUID                 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_KEY_LEN              24 /* base64 of a 16-byte nonce */
#define WS_ACCEPT_LEN           HTTPD_WS_BASE64_LEN(HTTPD_WS_SHA1_DIGEST_LEN)
#define WS_CTRL_MAX_PAYLOAD     125
#define WS_MAX_HEADER_LEN       14 /* 2 + 8 (64-bit length) + 4 (mask) */

#define WS_FIN                  0x80
#define WS_RSV_MASK             0x70
#define WS_OPCODE_MASK          0x0F
#define WS_MASK_BIT             0x80
#define WS_IS_CONTROL(op)       (((op) & 0x08) != 0)

static const char ws_response_101[] =
  "HTTP/1.1 101 Switching Protocols" WS_CRLF
  "Upgrade: websocket" WS_CRLF
  "Connection: Upgrade" WS_CRLF
  "Sec-WebSocket-Accept: ";
static const char ws_response_400[] =
  "HTTP/1.1 400 Bad Request" WS_CRLF
  "Content-Length: 0" WS_CRLF "Connection: close" WS_CRLF WS_CRLF;
static const char ws_response_401[] =
  "HTTP/1.1 401 Unauthorized" WS_CRLF
  "WWW-Authenticate: Basic realm=\"lwIP\"" WS_CRLF
  "Content-Length: 0" WS_CRLF "Connection: close" WS_CRLF WS_CRLF;
static const char ws_response_403[] =
  "HTTP/1.1 403 Forbidden" WS_CRLF
  "Content-Length: 0" WS_CRLF "Connection: close" WS_CRLF WS_CRLF;
static const char ws_response_404[] =
  "HTTP/1.1 404 Not Found" WS_CRLF
  "Content-Length: 0" WS_CRLF "Connection: close" WS_CRLF WS_CRLF;
static const char ws_response_426[] =
  "HTTP/1.1 426 Upgrade Required" WS_CRLF
  "Sec-WebSocket-Version: 13" WS_CRLF
  "Content-Length: 0" WS_CRLF "Connection: close" WS_CRLF WS_CRLF;
static const char ws_response_503[] =
  "HTTP/1.1 503 Service Unavailable" WS_CRLF
  "Content-Length: 0" WS_CRLF "Connection: close" WS_CRLF WS_CRLF;

/** Per-connection state */
struct httpd_ws_conn {
  struct httpd_ws_conn *next;
  struct altcp_pcb *pcb;
  const httpd_ws_handler_t *handler;

  /* message reassembly (data frames) */
  u8_t *rx_buf;              /* flat mode: message buffer, else NULL */
  struct pbuf *rx_msg;       /* pbuf mode: message chain so far */
  u16_t msg_len;             /* bytes of the current message so far */
  u8_t msg_opcode;           /* opcode of the current message, 0: none */

  /* current frame */
  u32_t frame_len;           /* payload length */
  u32_t frame_pos;           /* payload bytes consumed */
  u8_t hdr[WS_MAX_HEADER_LEN];
  u8_t hdr_have;
  u8_t hdr_need;
  u8_t in_payload;           /* header parsed, consuming payload */
  u8_t frame_opcode;
  u8_t frame_fin;
  u8_t mask[4];

  /* control frame payload (PING/PONG/CLOSE), also keeps the close reason */
  u8_t ctrl[WS_CTRL_MAX_PAYLOAD];
  u8_t close_reason_len;
  u16_t close_code;          /* received (close_rcvd) or sent (closing) */


  u8_t closing;              /* Close frame sent by the server */
  u8_t close_rcvd;           /* Close frame received from the peer */
  u8_t close_polls;
  u8_t tx_broken;            /* partial frame queued, stream unusable */
#if LWIP_HTTPD_WS_SERVER_PING_ENABLE
  u8_t idle_polls;
  u8_t ping_pending;
#endif /* LWIP_HTTPD_WS_SERVER_PING_ENABLE */
};

LWIP_MEMPOOL_DECLARE(HTTPD_WS_CONN, MEMP_NUM_PARALLEL_HTTPD_WEBSOCKET_CONNS,
                     sizeof(struct httpd_ws_conn), "HTTPD_WS_CONN")

static struct httpd_ws_conn *ws_conns;
static const httpd_ws_handler_t *ws_handlers;
static size_t ws_handlers_count;
static const char *ws_auth_user;
static const char *ws_auth_pass;

/*---------------------------------------------------------------------------*/
/* connection list */

static void
ws_list_remove(struct httpd_ws_conn *ws)
{
  struct httpd_ws_conn **pp;
  for (pp = &ws_conns; *pp != NULL; pp = &(*pp)->next) {
    if (*pp == ws) {
      *pp = ws->next;
      ws->next = NULL;
      return;
    }
  }
}

static struct httpd_ws_conn *
ws_find(const struct altcp_pcb *pcb)
{
  struct httpd_ws_conn *ws;
  for (ws = ws_conns; ws != NULL; ws = ws->next) {
    if (ws->pcb == pcb) {
      return ws;
    }
  }
  return NULL;
}

/*---------------------------------------------------------------------------*/
/* transmit */

/** Queue one frame. Either the whole frame is queued or nothing (ERR_MEM:
 * not enough send buffer, try again later). */
static err_t
ws_send_frame(struct httpd_ws_conn *ws, u8_t b0, const u8_t *data, u16_t len)
{
  u8_t hdr[4];
  u16_t hdr_len;
  u16_t sndbuf;
  u16_t mss;
  err_t err;

  if (ws->tx_broken) {
    return ERR_CLSD;
  }
  hdr[0] = b0;
  if (len < 126) {
    hdr[1] = (u8_t)len;
    hdr_len = 2;
  } else {
    hdr[1] = 126;
    hdr[2] = (u8_t)(len >> 8);
    hdr[3] = (u8_t)len;
    hdr_len = 4;
  }

  /* All-or-nothing: a frame header without its payload would corrupt the
     stream, so check the send buffer and queue length first. */
  sndbuf = altcp_sndbuf(ws->pcb);
  if ((sndbuf < hdr_len) || (len > (u16_t)(sndbuf - hdr_len))) {
    return ERR_MEM;
  }
  mss = altcp_mss(ws->pcb);
  if (mss == 0) {
    mss = 1;
  }
  if ((u32_t)altcp_sndqueuelen(ws->pcb) + 2 + (len / mss) > TCP_SND_QUEUELEN) {
    return ERR_MEM;
  }

  err = altcp_write(ws->pcb, hdr, hdr_len,
                    (u8_t)(TCP_WRITE_FLAG_COPY | ((len > 0) ? TCP_WRITE_FLAG_MORE : 0)));
  if (err != ERR_OK) {
    return err; /* nothing queued */
  }
  if (len > 0) {
    err = altcp_write(ws->pcb, data, len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
      /* header queued without payload: the connection cannot be used any
         more, it is closed on the next poll */
      LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_ws: payload write failed (%d), closing\n", (int)err));
      ws->tx_broken = 1;
      return ERR_CLSD;
    }
  }
  altcp_output(ws->pcb);
  return ERR_OK;
}

static err_t
ws_send_close(struct httpd_ws_conn *ws, u16_t code, const u8_t *reason, u16_t reason_len)
{
  u8_t payload[WS_CTRL_MAX_PAYLOAD];
  err_t err;

  LWIP_ASSERT("reason too long", reason_len <= WS_CTRL_MAX_PAYLOAD - 2);
  payload[0] = (u8_t)(code >> 8);
  payload[1] = (u8_t)code;
  if (reason_len > 0) {
    MEMCPY(&payload[2], reason, reason_len);
  }
  err = ws_send_frame(ws, WS_FIN | WS_OPCODE_CLOSE, payload, (u16_t)(2 + reason_len));
  if (err == ERR_OK) {
    ws->closing = 1;
    ws->close_polls = 0;
    if (!ws->close_rcvd) {
      ws->close_code = code;
    }
  }
  return err;
}

/** Fail the connection (RFC 6455 7.1.7): send Close and let httpd close TCP */
static err_t
ws_fail(struct httpd_ws_conn *ws, u16_t code)
{
  LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_ws: failing connection, code %u\n", (unsigned)code));
  if (!ws->closing) {
    ws_send_close(ws, code, NULL, 0);
  }
  ws->closing = 1;
  if (!ws->close_rcvd) {
    ws->close_code = code;
  }
  return ERR_VAL;
}

/*---------------------------------------------------------------------------*/
/* receive */


static void
ws_unmask(const struct httpd_ws_conn *ws, u8_t *data, u16_t len, u32_t pos)
{
  u16_t i;
  for (i = 0; i < len; i++) {
    data[i] ^= ws->mask[(pos + i) & 3];
  }
}

static void
ws_frame_reset(struct httpd_ws_conn *ws)
{
  ws->in_payload = 0;
  ws->hdr_have = 0;
  ws->hdr_need = 2;
  ws->frame_len = 0;
  ws->frame_pos = 0;
}

static void
ws_msg_reset(struct httpd_ws_conn *ws)
{
  ws->msg_opcode = 0;
  ws->msg_len = 0;
  if (ws->rx_msg != NULL) {
    pbuf_free(ws->rx_msg);
    ws->rx_msg = NULL;
  }
}

/** Parse the frame header collected in ws->hdr.
 * @return ERR_OK: header complete; ERR_INPROGRESS: more header bytes needed
 *         (ws->hdr_need updated); ERR_VAL: connection failed */
static err_t
ws_parse_header(struct httpd_ws_conn *ws)
{
  u8_t b0 = ws->hdr[0];
  u8_t b1 = ws->hdr[1];
  u8_t opcode = (u8_t)(b0 & WS_OPCODE_MASK);
  u8_t fin = (u8_t)((b0 & WS_FIN) != 0);
  u8_t len7 = (u8_t)(b1 & 0x7F);
  u8_t need;
  u32_t len;

  if ((b0 & WS_RSV_MASK) != 0) {
    /* no extension negotiated */
    return ws_fail(ws, WS_CLOSE_PROTOCOL_ERROR);
  }
  if ((b1 & WS_MASK_BIT) == 0) {
    /* client frames must be masked (5.1) */
    return ws_fail(ws, WS_CLOSE_PROTOCOL_ERROR);
  }
  if (WS_IS_CONTROL(opcode)) {
    if ((opcode != WS_OPCODE_CLOSE) && (opcode != WS_OPCODE_PING) && (opcode != WS_OPCODE_PONG)) {
      return ws_fail(ws, WS_CLOSE_PROTOCOL_ERROR);
    }
    if (!fin || (len7 > WS_CTRL_MAX_PAYLOAD)) {
      return ws_fail(ws, WS_CLOSE_PROTOCOL_ERROR);
    }
  } else if ((opcode == WS_OPCODE_TEXT) || (opcode == WS_OPCODE_BIN)) {
    if (!fin) {
      /* fragmented messages (continuation frames) are not supported */
      return ws_fail(ws, WS_CLOSE_PROTOCOL_ERROR);
    }
  } else {
    /* reserved data opcode or continuation */
    return ws_fail(ws, WS_CLOSE_PROTOCOL_ERROR);
  }

  if (len7 < 126) {
    need = 2 + 4;
  } else if (len7 == 126) {
    need = 2 + 2 + 4;
  } else {
    need = 2 + 8 + 4;
  }
  if (ws->hdr_have < need) {
    ws->hdr_need = need;
    return ERR_INPROGRESS;
  }

  if (len7 < 126) {
    len = len7;
  } else if (len7 == 126) {
    len = ((u32_t)ws->hdr[2] << 8) | ws->hdr[3];
  } else {
    if ((ws->hdr[2] & 0x80) != 0) {
      /* most significant bit must be 0 (5.2) */
      return ws_fail(ws, WS_CLOSE_PROTOCOL_ERROR);
    }
    if ((ws->hdr[2] | ws->hdr[3] | ws->hdr[4] | ws->hdr[5]) != 0) {
      return ws_fail(ws, WS_CLOSE_MESSAGE_TOO_BIG);
    }
    len = ((u32_t)ws->hdr[6] << 24) | ((u32_t)ws->hdr[7] << 16) |
          ((u32_t)ws->hdr[8] << 8) | ws->hdr[9];
  }
  MEMCPY(ws->mask, &ws->hdr[need - 4], 4);

  if (!WS_IS_CONTROL(opcode)) {
    u16_t limit = (ws->rx_buf != NULL) ? LWIP_HTTPD_WS_RX_BUF_SIZE : LWIP_HTTPD_WS_MAX_MSG_SIZE;
    ws_msg_reset(ws);
    ws->msg_opcode = opcode;
    if (len > limit) {
      return ws_fail(ws, WS_CLOSE_MESSAGE_TOO_BIG);
    }
  }

  ws->frame_opcode = opcode;
  ws->frame_fin = fin;
  ws->frame_len = len;
  ws->frame_pos = 0;
  ws->in_payload = 1;
  return ERR_OK;
}

/** Consume @p take payload bytes from the front of *pp (advances *pp). */
static err_t
ws_consume_payload(struct httpd_ws_conn *ws, struct pbuf **pp, u16_t take)
{
  struct pbuf *p = *pp;
  const httpd_ws_handler_t *h = ws->handler;

  if (WS_IS_CONTROL(ws->frame_opcode)) {
    u8_t *dst = &ws->ctrl[ws->frame_pos];
    pbuf_copy_partial(p, dst, take, 0);
    ws_unmask(ws, dst, take, ws->frame_pos);
    *pp = pbuf_free_header(p, take);
  } else if (ws->closing) {
    /* discard data after our Close frame */
    *pp = pbuf_free_header(p, take);
  } else if (ws->rx_buf != NULL) {
    u8_t *dst = &ws->rx_buf[ws->msg_len];
    pbuf_copy_partial(p, dst, take, 0);
    ws_unmask(ws, dst, take, ws->frame_pos);
    *pp = pbuf_free_header(p, take);
  } else if (h->msg_pbuf_cb != NULL) {
    struct pbuf *chunk;
    struct pbuf *q;
    u32_t pos = ws->frame_pos;
    if (take == p->tot_len) {
      /* the rest of the segment belongs to this frame: keep it (no copy) */
      chunk = p;
      *pp = NULL;
    } else {
      chunk = pbuf_alloc(PBUF_RAW, take, PBUF_RAM);
      if (chunk == NULL) {
        return ws_fail(ws, WS_CLOSE_INTERNAL_ERROR);
      }
      pbuf_copy_partial(p, chunk->payload, take, 0);
      *pp = pbuf_free_header(p, take);
    }
    for (q = chunk; q != NULL; q = q->next) {
      ws_unmask(ws, (u8_t *)q->payload, q->len, pos);
      pos += q->len;
    }
    if (ws->rx_msg == NULL) {
      ws->rx_msg = chunk;
    } else {
      pbuf_cat(ws->rx_msg, chunk);
    }
  } else {
    /* no receive callback: discard */
    *pp = pbuf_free_header(p, take);
  }

  ws->frame_pos += take;
  if (!WS_IS_CONTROL(ws->frame_opcode)) {
    ws->msg_len = (u16_t)(ws->msg_len + take);
  }
  return ERR_OK;
}

static void
ws_deliver_message(struct httpd_ws_conn *ws)
{
  const httpd_ws_handler_t *h = ws->handler;

  if (ws->closing) {
    return;
  }
  if (ws->rx_buf != NULL) {
    if (h->msg_cb != NULL) {
      h->msg_cb(ws->pcb, h->user_ctx, ws->rx_buf, ws->msg_len, ws->msg_opcode);
    }
  } else if (h->msg_pbuf_cb != NULL) {
    if (ws->rx_msg == NULL) {
      /* empty message */
      ws->rx_msg = pbuf_alloc(PBUF_RAW, 0, PBUF_RAM);
    }
    if (ws->rx_msg != NULL) {
      h->msg_pbuf_cb(ws->pcb, h->user_ctx, ws->rx_msg, ws->msg_len, ws->msg_opcode);
    }
  }
}

/** Close code allowed in a received Close frame (RFC 6455 7.4) */
static u8_t
ws_close_code_valid(u16_t code)
{
  if ((code >= 1000) && (code <= 1003)) {
    return 1;
  }
  if ((code >= 1007) && (code <= 1011)) {
    return 1;
  }
  return (u8_t)((code >= 3000) && (code <= 4999));
}

static err_t
ws_handle_control(struct httpd_ws_conn *ws)
{
  const httpd_ws_handler_t *h = ws->handler;
  u16_t len = (u16_t)ws->frame_len;

  switch (ws->frame_opcode) {
    case WS_OPCODE_PING:
      if (!ws->closing) {
        ws_send_frame(ws, WS_FIN | WS_OPCODE_PONG, ws->ctrl, len);
        if (h->ping_cb != NULL) {
          h->ping_cb(ws->pcb, h->user_ctx, ws->ctrl, len);
        }
      }
      return ERR_OK;

    case WS_OPCODE_PONG:
      if (h->pong_cb != NULL) {
        h->pong_cb(ws->pcb, h->user_ctx, ws->ctrl, len);
      }
      return ERR_OK;

    case WS_OPCODE_CLOSE:
    default: {
      u16_t code = WS_CLOSE_NO_STATUS;
      if (len == 1) {
        return ws_fail(ws, WS_CLOSE_PROTOCOL_ERROR);
      }
      if (len >= 2) {
        code = (u16_t)(((u16_t)ws->ctrl[0] << 8) | ws->ctrl[1]);
        if (!ws_close_code_valid(code)) {
          return ws_fail(ws, WS_CLOSE_PROTOCOL_ERROR);
        }
      }
      ws->close_rcvd = 1;
      ws->close_code = code;
      ws->close_reason_len = (u8_t)((len > 2) ? (len - 2) : 0);
      if (!ws->closing) {
        /* answer with the same status code (5.5.1, 1000 for an empty Close);
           the reason is not echoed */
        ws_send_close(ws, (code == WS_CLOSE_NO_STATUS) ? WS_CLOSE_NORMAL : code, NULL, 0);
      }
      /* close handshake done: httpd closes the TCP connection */
      return ERR_CLSD;
    }
  }
}

static err_t
ws_frame_complete(struct httpd_ws_conn *ws)
{
  err_t err = ERR_OK;

  if (WS_IS_CONTROL(ws->frame_opcode)) {
    err = ws_handle_control(ws);
  } else {
    ws_deliver_message(ws);
    ws_msg_reset(ws);
  }
  ws_frame_reset(ws);
  return err;
}

err_t
httpd_ws_recv(struct httpd_ws_conn *ws, struct pbuf *p)
{
  err_t err = ERR_OK;

  LWIP_ASSERT("ws != NULL", ws != NULL);
  LWIP_ASSERT("p != NULL", p != NULL);

#if LWIP_HTTPD_WS_SERVER_PING_ENABLE
  /* any data from the peer counts as a sign of life */
  ws->idle_polls = 0;
  ws->ping_pending = 0;
#endif /* LWIP_HTTPD_WS_SERVER_PING_ENABLE */

  while ((p != NULL) && (p->tot_len > 0) && (err == ERR_OK)) {
    if (!ws->in_payload) {
      u16_t got = pbuf_copy_partial(p, &ws->hdr[ws->hdr_have],
                                    (u16_t)(ws->hdr_need - ws->hdr_have), 0);
      ws->hdr_have = (u8_t)(ws->hdr_have + got);
      p = pbuf_free_header(p, got);
      if (ws->hdr_have < ws->hdr_need) {
        continue; /* p is used up, wait for more */
      }
      err = ws_parse_header(ws);
      if (err == ERR_INPROGRESS) {
        err = ERR_OK;
        continue;
      }
      if ((err == ERR_OK) && (ws->frame_len == 0)) {
        err = ws_frame_complete(ws);
      }
    } else {
      u32_t left = ws->frame_len - ws->frame_pos;
      u16_t take = (left < p->tot_len) ? (u16_t)left : p->tot_len;
      err = ws_consume_payload(ws, &p, take);
      if ((err == ERR_OK) && (ws->frame_pos == ws->frame_len)) {
        err = ws_frame_complete(ws);
      }
    }
  }
  if (p != NULL) {
    pbuf_free(p);
  }
  return err;
}

/*---------------------------------------------------------------------------*/
/* handshake */

/** Find a header line "name: value" (name case-insensitive).
 * @return 1 if found, value without surrounding white space in val/val_len */
static u8_t
ws_find_header(const char *hdrs, u16_t len, const char *name,
               const char **val, u16_t *val_len)
{
  size_t name_len = strlen(name);
  u16_t pos = 0;

  while (pos < len) {
    const char *line = &hdrs[pos];
    const char *end = lwip_strnstr(line, WS_CRLF, (size_t)(len - pos));
    u16_t line_len = (u16_t)((end != NULL) ? (end - line) : (len - pos));
    if (line_len == 0) {
      break; /* empty line: end of headers */
    }
    if ((line_len > name_len) && (line[name_len] == ':') &&
        (lwip_strnicmp(line, name, name_len) == 0)) {
      u16_t s = (u16_t)(name_len + 1);
      u16_t e = line_len;
      while ((s < e) && ((line[s] == ' ') || (line[s] == '\t'))) {
        s++;
      }
      while ((e > s) && ((line[e - 1] == ' ') || (line[e - 1] == '\t'))) {
        e--;
      }
      *val = &line[s];
      *val_len = (u16_t)(e - s);
      return 1;
    }
    pos = (u16_t)(pos + line_len + 2);
  }
  return 0;
}

/** Check a comma-separated header value for a token (case-insensitive) */
static u8_t
ws_has_token(const char *val, u16_t len, const char *token)
{
  size_t token_len = strlen(token);
  u16_t i = 0;

  while (i < len) {
    u16_t s, e;
    while ((i < len) && ((val[i] == ' ') || (val[i] == '\t') || (val[i] == ','))) {
      i++;
    }
    s = i;
    while ((i < len) && (val[i] != ',')) {
      i++;
    }
    e = i;
    while ((e > s) && ((val[e - 1] == ' ') || (val[e - 1] == '\t'))) {
      e--;
    }
    if (((size_t)(e - s) == token_len) && (lwip_strnicmp(&val[s], token, token_len) == 0)) {
      return 1;
    }
  }
  return 0;
}

static const httpd_ws_handler_t *
ws_find_handler(const char *uri)
{
  size_t i;
  for (i = 0; i < ws_handlers_count; i++) {
    const char *h_uri = ws_handlers[i].uri;
    if (h_uri != NULL) {
      size_t n = strlen(h_uri);
      /* exact match, a query string ("?...") is ignored */
      if ((strncmp(uri, h_uri, n) == 0) && ((uri[n] == 0) || (uri[n] == '?'))) {
        return &ws_handlers[i];
      }
    }
  }
  return NULL;
}

static httpd_ws_auth_result_t
ws_basic_auth_check(const char *hdrs, u16_t len)
{
  char plain[LWIP_HTTPD_WS_BASIC_AUTH_MAX];
  char expected[HTTPD_WS_BASE64_LEN(LWIP_HTTPD_WS_BASIC_AUTH_MAX)];
  const char *val;
  u16_t val_len;
  size_t ulen, plen;
  u16_t exp_len, i;
  u8_t diff = 0;

  if ((ws_auth_user == NULL) || (ws_auth_pass == NULL)) {
    return HTTPD_WS_AUTH_OK;
  }
  ulen = strlen(ws_auth_user);
  plen = strlen(ws_auth_pass);
  if (ulen + 1 + plen > sizeof(plain)) {
    return HTTPD_WS_AUTH_FORBIDDEN;
  }
  MEMCPY(plain, ws_auth_user, ulen);
  plain[ulen] = ':';
  MEMCPY(&plain[ulen + 1], ws_auth_pass, plen);
  exp_len = httpd_ws_base64_encode((const u8_t *)plain, (u16_t)(ulen + 1 + plen), expected);

  if (!ws_find_header(hdrs, len, "Authorization", &val, &val_len) ||
      (val_len < 6) || (lwip_strnicmp(val, "Basic ", 6) != 0)) {
    return HTTPD_WS_AUTH_REJECTED;
  }
  val += 6;
  val_len = (u16_t)(val_len - 6);
  while ((val_len > 0) && (*val == ' ')) {
    val++;
    val_len--;
  }
  if (val_len != exp_len) {
    return HTTPD_WS_AUTH_REJECTED;
  }
  /* constant-time compare */
  for (i = 0; i < exp_len; i++) {
    diff |= (u8_t)(val[i] ^ expected[i]);
  }
  return (diff == 0) ? HTTPD_WS_AUTH_OK : HTTPD_WS_AUTH_REJECTED;
}

static err_t
ws_reject(struct altcp_pcb *pcb, const char *rsp, u16_t rsp_len)
{
  if (altcp_write(pcb, rsp, rsp_len, TCP_WRITE_FLAG_COPY) == ERR_OK) {
    altcp_output(pcb);
  }
  return ERR_ARG; /* httpd closes the connection */
}

#define WS_REJECT(pcb, rsp) ws_reject(pcb, rsp, (u16_t)(sizeof(rsp) - 1))

err_t
httpd_ws_handshake(struct altcp_pcb *pcb, const char *uri,
                   const char *headers, u16_t headers_len,
                   struct httpd_ws_conn **conn)
{
  const httpd_ws_handler_t *h;
  struct httpd_ws_conn *ws;
  httpd_ws_req_t req;
  httpd_ws_auth_result_t auth;
  const char *val;
  u16_t val_len;
  char key[WS_KEY_LEN + sizeof(WS_GUID) - 1];
  u8_t digest[HTTPD_WS_SHA1_DIGEST_LEN];
  char rsp[sizeof(ws_response_101) - 1 + WS_ACCEPT_LEN + 4];
  u16_t rsp_len;
  err_t err;

  LWIP_ASSERT("conn != NULL", conn != NULL);
  *conn = NULL;

  if (!ws_find_header(headers, headers_len, "Upgrade", &val, &val_len) ||
      !ws_has_token(val, val_len, "websocket")) {
    return ERR_VAL; /* not for us */
  }
  LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_ws: upgrade request for \"%s\"\n", uri));

  if (!ws_find_header(headers, headers_len, "Connection", &val, &val_len) ||
      !ws_has_token(val, val_len, "upgrade")) {
    return WS_REJECT(pcb, ws_response_400);
  }
  if (!ws_find_header(headers, headers_len, "Sec-WebSocket-Version", &val, &val_len) ||
      (val_len != 2) || (val[0] != '1') || (val[1] != '3')) {
    return WS_REJECT(pcb, ws_response_426);
  }
  if (!ws_find_header(headers, headers_len, "Sec-WebSocket-Key", &val, &val_len) ||
      (val_len != WS_KEY_LEN)) {
    return WS_REJECT(pcb, ws_response_400);
  }
  MEMCPY(key, val, WS_KEY_LEN);
  MEMCPY(&key[WS_KEY_LEN], WS_GUID, sizeof(WS_GUID) - 1);

  h = ws_find_handler(uri);
  if (h == NULL) {
    return WS_REJECT(pcb, ws_response_404);
  }

  req.pcb = pcb;
  req.uri = uri;
  req.headers = headers;
  req.headers_len = headers_len;
  req.user_ctx = h->user_ctx;
  if (h->auth_cb != NULL) {
    auth = h->auth_cb(&req);
  } else {
    auth = ws_basic_auth_check(headers, headers_len);
  }
  if (auth == HTTPD_WS_AUTH_REJECTED) {
    return WS_REJECT(pcb, ws_response_401);
  } else if (auth != HTTPD_WS_AUTH_OK) {
    return WS_REJECT(pcb, ws_response_403);
  }

  /* allocate everything before answering 101, so that a lack of memory can
     still be reported as 503 */
  ws = (struct httpd_ws_conn *)LWIP_MEMPOOL_ALLOC(HTTPD_WS_CONN);
  if (ws == NULL) {
    LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_ws: no free connection\n"));
    return WS_REJECT(pcb, ws_response_503);
  }
  memset(ws, 0, sizeof(struct httpd_ws_conn));
  ws->pcb = pcb;
  ws->handler = h;
  ws_frame_reset(ws);
  ws_msg_reset(ws);
  if ((h->msg_pbuf_cb == NULL) && (h->msg_cb != NULL)) {
    ws->rx_buf = (u8_t *)mem_malloc(LWIP_HTTPD_WS_RX_BUF_SIZE);
    if (ws->rx_buf == NULL) {
      LWIP_MEMPOOL_FREE(HTTPD_WS_CONN, ws);
      return WS_REJECT(pcb, ws_response_503);
    }
  }

  LWIP_HTTPD_WS_SHA1((const u8_t *)key, (u16_t)sizeof(key), digest);
  rsp_len = (u16_t)(sizeof(ws_response_101) - 1);
  MEMCPY(rsp, ws_response_101, rsp_len);
  rsp_len = (u16_t)(rsp_len + httpd_ws_base64_encode(digest, HTTPD_WS_SHA1_DIGEST_LEN, &rsp[rsp_len]));
  MEMCPY(&rsp[rsp_len], WS_CRLF WS_CRLF, 4);
  rsp_len = (u16_t)(rsp_len + 4);
  LWIP_ASSERT("response length", rsp_len == sizeof(rsp));

  err = altcp_write(pcb, rsp, rsp_len, TCP_WRITE_FLAG_COPY);
  if (err != ERR_OK) {
    if (ws->rx_buf != NULL) {
      mem_free(ws->rx_buf);
    }
    LWIP_MEMPOOL_FREE(HTTPD_WS_CONN, ws);
    return WS_REJECT(pcb, ws_response_503);
  }
  altcp_output(pcb);

  ws->next = ws_conns;
  ws_conns = ws;
  *conn = ws;

  if (h->open_cb != NULL) {
    h->open_cb(&req);
  }
  return ERR_OK;
}

/*---------------------------------------------------------------------------*/
/* other hooks */

void
httpd_ws_init(void)
{
  LWIP_MEMPOOL_INIT(HTTPD_WS_CONN);
}

err_t
httpd_ws_poll(struct httpd_ws_conn *ws)
{
  LWIP_ASSERT("ws != NULL", ws != NULL);

  if (ws->tx_broken) {
    return ERR_ABRT;
  }
  if (ws->closing) {
    ws->close_polls++;
    if (ws->close_polls >= LWIP_HTTPD_WS_CLOSE_TIMEOUT_POLLS) {
      LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_ws: close timeout\n"));
      return ERR_TIMEOUT;
    }
    return ERR_OK;
  }
#if LWIP_HTTPD_WS_SERVER_PING_ENABLE
  if (ws->idle_polls < 255) {
    ws->idle_polls++;
  }
  if (ws->ping_pending) {
    if (ws->idle_polls >= LWIP_HTTPD_WS_PING_INTERVAL_POLLS + LWIP_HTTPD_WS_PONG_TIMEOUT_POLLS) {
      LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_ws: no answer to PING, closing\n"));
      return ERR_TIMEOUT;
    }
  } else if (ws->idle_polls >= LWIP_HTTPD_WS_PING_INTERVAL_POLLS) {
    if (ws_send_frame(ws, WS_FIN | WS_OPCODE_PING, NULL, 0) == ERR_OK) {
      ws->ping_pending = 1;
    }
  }
#endif /* LWIP_HTTPD_WS_SERVER_PING_ENABLE */
  return ERR_OK;
}

void
httpd_ws_free(struct httpd_ws_conn *ws)
{
  const httpd_ws_handler_t *h;
  u16_t code;

  LWIP_ASSERT("ws != NULL", ws != NULL);
  h = ws->handler;

  /* unlink first so that the API no longer finds this connection */
  ws_list_remove(ws);
  ws->closing = 1;

  if (ws->close_rcvd || ws->close_code != 0) {
    code = ws->close_code;
  } else {
    code = WS_CLOSE_ABNORMAL;
  }
  if (h->close_cb != NULL) {
    h->close_cb(ws->pcb, h->user_ctx, code,
                (ws->close_rcvd && (ws->close_reason_len > 0)) ? &ws->ctrl[2] : NULL,
                ws->close_rcvd ? ws->close_reason_len : 0);
  }

  if (ws->rx_msg != NULL) {
    pbuf_free(ws->rx_msg);
  }
  if (ws->rx_buf != NULL) {
    mem_free(ws->rx_buf);
  }
  LWIP_MEMPOOL_FREE(HTTPD_WS_CONN, ws);
}

/*---------------------------------------------------------------------------*/
/* public API */

/**
 * @ingroup httpd_ws
 * Register the WebSocket handlers (one per URI). The array is not copied.
 * Connections that are already open keep their handler.
 */
void
httpd_ws_register_handlers(const httpd_ws_handler_t *handlers, size_t count)
{
  LWIP_ASSERT_CORE_LOCKED();
  ws_handlers = handlers;
  ws_handlers_count = (handlers != NULL) ? count : 0;
}

/**
 * @ingroup httpd_ws
 * Set credentials for HTTP Basic authentication of upgrade requests to
 * handlers without auth_cb. NULL disables the check. The strings are not
 * copied. Note that Basic authentication sends the password in clear text
 * unless the server runs over TLS.
 */
void
httpd_ws_set_basic_auth(const char *username, const char *password)
{
  LWIP_ASSERT_CORE_LOCKED();
  ws_auth_user = username;
  ws_auth_pass = password;
}

/**
 * @ingroup httpd_ws
 * Send a complete message as one frame. The data is copied.
 *
 * The frame is queued completely or not at all, so a message must fit into
 * the TCP send buffer (altcp_sndbuf()).
 *
 * @param pcb connection
 * @param data payload
 * @param len payload length
 * @param opcode WS_OPCODE_TEXT or WS_OPCODE_BIN
 * @return ERR_OK; ERR_MEM: not enough send buffer, nothing queued, try again
 *         later; ERR_CONN: not an open WebSocket; ERR_CLSD: connection is
 *         closing; ERR_ARG: invalid argument
 */
err_t
httpd_ws_write(struct altcp_pcb *pcb, const u8_t *data, u16_t len, u8_t opcode)
{
  struct httpd_ws_conn *ws;

  LWIP_ASSERT_CORE_LOCKED();
  if ((pcb == NULL) || ((data == NULL) && (len > 0)) ||
      ((opcode != WS_OPCODE_TEXT) && (opcode != WS_OPCODE_BIN))) {
    return ERR_ARG;
  }
  ws = ws_find(pcb);
  if (ws == NULL) {
    return ERR_CONN;
  }
  if (ws->closing) {
    return ERR_CLSD;
  }
  return ws_send_frame(ws, (u8_t)(WS_FIN | opcode), data, len);
}

static err_t
ws_broadcast(const httpd_ws_handler_t *target, const u8_t *data, u16_t len, u8_t opcode)
{
  struct httpd_ws_conn *ws;
  err_t ret = ERR_OK;

  if (((data == NULL) && (len > 0)) ||
      ((opcode != WS_OPCODE_TEXT) && (opcode != WS_OPCODE_BIN))) {
    return ERR_ARG;
  }
  for (ws = ws_conns; ws != NULL; ws = ws->next) {
    if (((target == NULL) || (ws->handler == target)) && !ws->closing) {
      err_t err = ws_send_frame(ws, (u8_t)(WS_FIN | opcode), data, len);
      if ((err != ERR_OK) && (ret == ERR_OK)) {
        ret = err; /* keep going, report the first failure */
      }
    }
  }
  return ret;
}

/**
 * @ingroup httpd_ws
 * Send a message to all open WebSocket connections.
 * Connections that cannot take the message now are skipped.
 * @return ERR_OK if all connections queued the message, else the first error
 *         (typically ERR_MEM: at least one peer did not get the message)
 */
err_t
httpd_ws_broadcast(const u8_t *data, u16_t len, u8_t opcode)
{
  LWIP_ASSERT_CORE_LOCKED();
  return ws_broadcast(NULL, data, len, opcode);
}

/**
 * @ingroup httpd_ws
 * Send a message to all open connections of the handler registered for uri.
 * @return see httpd_ws_broadcast(); ERR_ARG if no handler matches uri
 */
err_t
httpd_ws_broadcast_uri(const char *uri, const u8_t *data, u16_t len, u8_t opcode)
{
  const httpd_ws_handler_t *h;

  LWIP_ASSERT_CORE_LOCKED();
  if (uri == NULL) {
    return ERR_ARG;
  }
  h = ws_find_handler(uri);
  if (h == NULL) {
    return ERR_ARG;
  }
  return ws_broadcast(h, data, len, opcode);
}

/**
 * @ingroup httpd_ws
 * Send a PING (at most 125 bytes payload). The answer is reported to
 * pong_cb.
 */
err_t
httpd_ws_ping(struct altcp_pcb *pcb, const u8_t *payload, u16_t len)
{
  struct httpd_ws_conn *ws;

  LWIP_ASSERT_CORE_LOCKED();
  if ((pcb == NULL) || (len > WS_CTRL_MAX_PAYLOAD) || ((payload == NULL) && (len > 0))) {
    return ERR_ARG;
  }
  ws = ws_find(pcb);
  if (ws == NULL) {
    return ERR_CONN;
  }
  if (ws->closing) {
    return ERR_CLSD;
  }
  return ws_send_frame(ws, WS_FIN | WS_OPCODE_PING, payload, len);
}

/**
 * @ingroup httpd_ws
 * Start the close handshake: send a Close frame. The TCP connection is
 * closed when the peer answers, or after LWIP_HTTPD_WS_CLOSE_TIMEOUT_POLLS
 * polls; close_cb is called then. No data can be sent after this call.
 *
 * @param pcb connection
 * @param code close status code (e.g. WS_CLOSE_NORMAL)
 * @param reason optional UTF-8 reason (copied, may be NULL)
 * @param reason_len length of reason (at most 123)
 * @return ERR_OK; ERR_MEM: not enough send buffer, try again; ERR_CLSD:
 *         already closing; ERR_CONN: not an open WebSocket; ERR_ARG
 */
err_t
httpd_ws_close(struct altcp_pcb *pcb, u16_t code, const u8_t *reason, u16_t reason_len)
{
  struct httpd_ws_conn *ws;

  LWIP_ASSERT_CORE_LOCKED();
  if ((pcb == NULL) || (reason_len > WS_CTRL_MAX_PAYLOAD - 2) ||
      ((reason == NULL) && (reason_len > 0))) {
    return ERR_ARG;
  }
  ws = ws_find(pcb);
  if (ws == NULL) {
    return ERR_CONN;
  }
  if (ws->closing) {
    return ERR_CLSD;
  }
  return ws_send_close(ws, code, reason, reason_len);
}

#endif /* LWIP_HTTPD_SUPPORT_WEBSOCKET && LWIP_TCP && LWIP_CALLBACK_API */
