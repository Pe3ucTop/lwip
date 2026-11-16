/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/apps/httpd_opts.h"
#include "lwip/def.h"
#include "lwip/debug.h"
#include "lwip/apps/fs.h"
#include <string.h>


#include HTTPD_FSDATA_FILE

#if LWIP_HTTPD_CUSTOM_FILE_PROVIDERS
#if !LWIP_HTTPD_CUSTOM_FILES
#error LWIP_HTTPD_CUSTOM_FILE_PROVIDERS needs LWIP_HTTPD_CUSTOM_FILES
#endif

/** Registered custom file providers, in registration order */
static struct fs_custom_provider *fs_custom_providers;

/**
 * @ingroup httpd
 * Register a source of custom files (LWIP_HTTPD_CUSTOM_FILE_PROVIDERS).
 * Providers with the same @p where are asked in registration order.
 *
 * @param provider the provider, must stay valid (it is linked into a list)
 * @param where FS_CUSTOM_PROVIDER_BEFORE_FSDATA or FS_CUSTOM_PROVIDER_AFTER_FSDATA
 * @return ERR_OK, ERR_ARG on invalid arguments, ERR_VAL if already registered
 */
err_t
fs_custom_provider_register(struct fs_custom_provider *provider, u8_t where)
{
  struct fs_custom_provider **tail;

  LWIP_ERROR("fs_custom_provider_register: invalid provider",
             (provider != NULL) && (provider->open != NULL), return ERR_ARG;);
  LWIP_ERROR("fs_custom_provider_register: invalid where",
             (where == FS_CUSTOM_PROVIDER_BEFORE_FSDATA) ||
             (where == FS_CUSTOM_PROVIDER_AFTER_FSDATA), return ERR_ARG;);

  for (tail = &fs_custom_providers; *tail != NULL; tail = &(*tail)->next) {
    if (*tail == provider) {
      return ERR_VAL;
    }
  }
  provider->where = where;
  provider->next = NULL;
  *tail = provider;
  return ERR_OK;
}

static int
fs_custom_open_where(struct fs_file *file, const char *name, u8_t where)
{
  struct fs_custom_provider *p;
  for (p = fs_custom_providers; p != NULL; p = p->next) {
    if ((p->where == where) && p->open(file, name)) {
      file->provider = p;
      return 1;
    }
  }
  return 0;
}

/* With LWIP_HTTPD_CUSTOM_FILE_PROVIDERS, the fs_*_custom() functions are
   implemented here and dispatch to the registered providers. */
int
fs_open_custom(struct fs_file *file, const char *name)
{
  return fs_custom_open_where(file, name, FS_CUSTOM_PROVIDER_BEFORE_FSDATA);
}

void
fs_close_custom(struct fs_file *file)
{
  const struct fs_custom_provider *p = file->provider;
  LWIP_ASSERT("fs_close_custom: no provider", p != NULL);
  file->provider = NULL;
  if ((p != NULL) && (p->close != NULL)) {
    p->close(file);
  }
}

#if LWIP_HTTPD_FS_ASYNC_READ
u8_t
fs_canread_custom(struct fs_file *file)
{
  const struct fs_custom_provider *p = file->provider;
  LWIP_ASSERT("fs_canread_custom: no provider", p != NULL);
  if ((p == NULL) || (p->canread == NULL)) {
    return 1;
  }
  return p->canread(file);
}

u8_t
fs_wait_read_custom(struct fs_file *file, fs_wait_cb callback_fn, void *callback_arg)
{
  const struct fs_custom_provider *p = file->provider;
  LWIP_ASSERT("fs_wait_read_custom: no provider", p != NULL);
  if ((p == NULL) || (p->wait_read == NULL)) {
    return 0;
  }
  return p->wait_read(file, callback_fn, callback_arg);
}

int
fs_read_async_custom(struct fs_file *file, char *buffer, int count, fs_wait_cb callback_fn, void *callback_arg)
{
  const struct fs_custom_provider *p = file->provider;
  LWIP_ASSERT("fs_read_async_custom: no provider", p != NULL);
  if ((p == NULL) || (p->read_async == NULL)) {
    return FS_READ_EOF;
  }
  return p->read_async(file, buffer, count, callback_fn, callback_arg);
}
#else /* LWIP_HTTPD_FS_ASYNC_READ */
int
fs_read_custom(struct fs_file *file, char *buffer, int count)
{
  const struct fs_custom_provider *p = file->provider;
  LWIP_ASSERT("fs_read_custom: no provider", p != NULL);
  if ((p == NULL) || (p->read == NULL)) {
    return FS_READ_EOF;
  }
  return p->read(file, buffer, count);
}
#endif /* LWIP_HTTPD_FS_ASYNC_READ */
#endif /* LWIP_HTTPD_CUSTOM_FILE_PROVIDERS */

/*-----------------------------------------------------------------------------------*/
err_t
fs_open(struct fs_file *file, const char *name)
{
  const struct fsdata_file *f;

  if ((file == NULL) || (name == NULL)) {
    return ERR_ARG;
  }

#if LWIP_HTTPD_CUSTOM_FILES
  if (fs_open_custom(file, name)) {
    file->flags |= FS_FILE_FLAGS_CUSTOM;
    return ERR_OK;
  }
#endif /* LWIP_HTTPD_CUSTOM_FILES */

  for (f = FS_ROOT; f != NULL; f = f->next) {
    if (!strcmp(name, (const char *)f->name)) {
      file->data = (const char *)f->data;
      file->len = f->len;
      file->index = f->len;
      file->flags = f->flags;
#if HTTPD_PRECALCULATED_CHECKSUM
      file->chksum_count = f->chksum_count;
      file->chksum = f->chksum;
#endif /* HTTPD_PRECALCULATED_CHECKSUM */
#if LWIP_HTTPD_FILE_EXTENSION
      file->pextension = NULL;
#endif /* LWIP_HTTPD_FILE_EXTENSION */
#if LWIP_HTTPD_FILE_STATE
      file->state = fs_state_init(file, name);
#endif /* #if LWIP_HTTPD_FILE_STATE */
      return ERR_OK;
    }
  }
#if LWIP_HTTPD_CUSTOM_FILES && LWIP_HTTPD_CUSTOM_FILE_PROVIDERS
  if (fs_custom_open_where(file, name, FS_CUSTOM_PROVIDER_AFTER_FSDATA)) {
    file->flags |= FS_FILE_FLAGS_CUSTOM;
    return ERR_OK;
  }
#endif /* LWIP_HTTPD_CUSTOM_FILES && LWIP_HTTPD_CUSTOM_FILE_PROVIDERS */
  /* file not found */
  return ERR_VAL;
}

/*-----------------------------------------------------------------------------------*/
void
fs_close(struct fs_file *file)
{
#if LWIP_HTTPD_CUSTOM_FILES
  if ((file->flags & FS_FILE_FLAGS_CUSTOM) != 0) {
    fs_close_custom(file);
  }
#endif /* LWIP_HTTPD_CUSTOM_FILES */
#if LWIP_HTTPD_FILE_STATE
  fs_state_free(file, file->state);
#endif /* #if LWIP_HTTPD_FILE_STATE */
  LWIP_UNUSED_ARG(file);
}
/*-----------------------------------------------------------------------------------*/
#if LWIP_HTTPD_DYNAMIC_FILE_READ
#if LWIP_HTTPD_FS_ASYNC_READ
int
fs_read_async(struct fs_file *file, char *buffer, int count, fs_wait_cb callback_fn, void *callback_arg)
#else /* LWIP_HTTPD_FS_ASYNC_READ */
int
fs_read(struct fs_file *file, char *buffer, int count)
#endif /* LWIP_HTTPD_FS_ASYNC_READ */
{
  int read;
  if (file->index == file->len) {
    return FS_READ_EOF;
  }
#if LWIP_HTTPD_FS_ASYNC_READ
  LWIP_UNUSED_ARG(callback_fn);
  LWIP_UNUSED_ARG(callback_arg);
#endif /* LWIP_HTTPD_FS_ASYNC_READ */
#if LWIP_HTTPD_CUSTOM_FILES
  if ((file->flags & FS_FILE_FLAGS_CUSTOM) != 0) {
#if LWIP_HTTPD_FS_ASYNC_READ
    return fs_read_async_custom(file, buffer, count, callback_fn, callback_arg);
#else /* LWIP_HTTPD_FS_ASYNC_READ */
    return fs_read_custom(file, buffer, count);
#endif /* LWIP_HTTPD_FS_ASYNC_READ */
  }
#endif /* LWIP_HTTPD_CUSTOM_FILES */

  read = file->len - file->index;
  if (read > count) {
    read = count;
  }

  MEMCPY(buffer, (file->data + file->index), read);
  file->index += read;

  return (read);
}
#endif /* LWIP_HTTPD_DYNAMIC_FILE_READ */
/*-----------------------------------------------------------------------------------*/
#if LWIP_HTTPD_FS_ASYNC_READ
int
fs_is_file_ready(struct fs_file *file, fs_wait_cb callback_fn, void *callback_arg)
{
  if (file != NULL) {
#if LWIP_HTTPD_FS_ASYNC_READ
#if LWIP_HTTPD_CUSTOM_FILES
    if (!fs_canread_custom(file)) {
      if (fs_wait_read_custom(file, callback_fn, callback_arg)) {
        return 0;
      }
    }
#else /* LWIP_HTTPD_CUSTOM_FILES */
    LWIP_UNUSED_ARG(callback_fn);
    LWIP_UNUSED_ARG(callback_arg);
#endif /* LWIP_HTTPD_CUSTOM_FILES */
#endif /* LWIP_HTTPD_FS_ASYNC_READ */
  }
  return 1;
}
#endif /* LWIP_HTTPD_FS_ASYNC_READ */
/*-----------------------------------------------------------------------------------*/
int
fs_bytes_left(struct fs_file *file)
{
  return file->len - file->index;
}
