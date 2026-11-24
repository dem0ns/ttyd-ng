#include <errno.h>
#include <json.h>
#include <libwebsockets.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pty.h"
#include "server.h"
#include "utils.h"
#include "compat.h"

// initial message list
static char initial_cmds[] = {SET_WINDOW_TITLE, SET_PREFERENCES};

// VULN-1 (security audit): websocket messages are accumulated fragment by
// fragment; without a cap a client can grow the buffer without bound and
// exhaust server memory. 1 MiB comfortably covers legitimate INPUT messages
// (large pastes) while bounding per-connection memory.
#define MAX_WS_MESSAGE_LEN (1024 * 1024)

static int send_initial_message(struct lws *wsi, int index) {
  char cmd = initial_cmds[index];
  char host[128] = "";
  char *message = NULL;
  size_t payload_size = 0;

  switch (cmd) {
    case SET_WINDOW_TITLE:
      gethostname(host, sizeof(host) - 1);
      payload_size = strlen(server->command) + strlen(host) + 8;
      message = xmalloc(LWS_PRE + payload_size);
      snprintf(message + LWS_PRE, payload_size, "%c%s (%s)", cmd, server->command, host);
      break;
    case SET_PREFERENCES:
      payload_size = strlen(server->prefs_json) + 2;
      message = xmalloc(LWS_PRE + payload_size);
      snprintf(message + LWS_PRE, payload_size, "%c%s", cmd, server->prefs_json);
      break;
    default:
      return 0;
  }

  // Size the message from the input instead of truncating it: a truncated
  // title or preference payload used to over-read (or hand the client
  // unparsable JSON).
  size_t len = strlen(message + LWS_PRE);
  int ret = lws_write(wsi, (unsigned char *)message + LWS_PRE, len, LWS_WRITE_BINARY);
  free(message);
  return ret;
}

static json_object *parse_window_size(const char *buf, size_t len, uint16_t *cols, uint16_t *rows,
                                       uint16_t *xpixel, uint16_t *ypixel) {
  json_tokener *tok = json_tokener_new();
  json_object *obj = json_tokener_parse_ex(tok, buf, len);
  json_tokener_free(tok);

  if (obj == NULL) return NULL;

  struct json_object *o = NULL;
  if (json_object_object_get_ex(obj, "columns", &o)) *cols = (uint16_t)json_object_get_int(o);
  if (json_object_object_get_ex(obj, "rows", &o)) *rows = (uint16_t)json_object_get_int(o);
  if (json_object_object_get_ex(obj, "xpixel", &o)) *xpixel = (uint16_t)json_object_get_int(o);
  if (json_object_object_get_ex(obj, "ypixel", &o)) *ypixel = (uint16_t)json_object_get_int(o);

  return obj;
}

static bool check_host_origin(struct lws *wsi) {
  char origin[256];
  memset(origin, 0, sizeof(origin));
  int len = lws_hdr_copy(wsi, origin, (int)sizeof(origin), WSI_TOKEN_ORIGIN);
  if (len <= 0) return false;

  // Compare host[:port] with the Host header. Parse into a separate buffer:
  // the old code overwrote the string it was still reading from.
  char origin_host[256];
  origin_host[0] = '\0';

#if defined(LWS_LIBRARY_VERSION_NUMBER) && LWS_LIBRARY_VERSION_NUMBER >= 5000000
  lws_parse_uri_t *uri = lws_parse_uri_create(origin);
  if (uri == NULL || uri->host == NULL) return false;
  bool v6 = strchr(uri->host, ':') != NULL;
  if (uri->port == 80 || uri->port == 443) {
    snprintf(origin_host, sizeof(origin_host), v6 ? "[%s]" : "%s", uri->host);
  } else {
    snprintf(origin_host, sizeof(origin_host), v6 ? "[%s]:%u" : "%s:%u", uri->host, (unsigned)uri->port);
  }
  lws_parse_uri_destroy(&uri);
#else
  const char *prot = NULL, *address = NULL, *path = NULL;
  int port = 0;
  if (lws_parse_uri(origin, &prot, &address, &port, &path) || address == NULL) return false;
  bool v6 = strchr(address, ':') != NULL;
  if (port == 80 || port == 443) {
    snprintf(origin_host, sizeof(origin_host), v6 ? "[%s]" : "%s", address);
  } else {
    snprintf(origin_host, sizeof(origin_host), v6 ? "[%s]:%d" : "%s:%d", address, port);
  }
#endif

  char host_buf[256];
  memset(host_buf, 0, sizeof(host_buf));
  len = lws_hdr_copy(wsi, host_buf, (int)sizeof(host_buf), WSI_TOKEN_HOST);

#if defined(LWS_ROLE_H2)
  // Upstream issue tsl0922/ttyd#1566: HTTP/2 has no Host header (RFC 9113
  // carries the authority in the :authority pseudo-header), so the check
  // can never pass for ws-over-h2; fall back to :authority.
  if (len <= 0) len = lws_hdr_copy(wsi, host_buf, (int)sizeof(host_buf), WSI_TOKEN_HTTP_COLON_AUTHORITY);
#endif

  return len > 0 && strcasecmp(origin_host, host_buf) == 0;
}

static pty_ctx_t *pty_ctx_init(struct pss_tty *pss) {
  pty_ctx_t *ctx = xmalloc(sizeof(pty_ctx_t));
  ctx->pss = pss;
  ctx->ws_closed = false;
  return ctx;
}

static void pty_ctx_free(pty_ctx_t *ctx) { free(ctx); }

static void process_read_cb(pty_process *process, pty_buf_t *buf, bool eof) {
  pty_ctx_t *ctx = (pty_ctx_t *)process->ctx;
  if (ctx->ws_closed) {
    pty_buf_free(buf);
    return;
  }

  // A live child can also lose its readable PTY (reconnect attempts
  // exhausted); close the session instead of leaving a frozen terminal.
  if (eof && (process->read_failed || !process_running(process)))
    ctx->pss->lws_close_status = process->read_failed ? 1006 : (process->exit_code == 0 ? 1000 : 1006);
  else
    ctx->pss->pty_buf = buf;
  lws_callback_on_writable(ctx->pss->wsi);
}

static void process_exit_cb(pty_process *process) {
  pty_ctx_t *ctx = (pty_ctx_t *)process->ctx;
  if (ctx->ws_closed) {
    lwsl_notice("process killed with signal %d, pid: %d\n", process->exit_signal, process->pid);
    goto done;
  }

  lwsl_notice("process exited with code %d, pid: %d\n", process->exit_code, process->pid);
  ctx->pss->process = NULL;
  ctx->pss->lws_close_status = process->exit_code == 0 ? 1000 : 1006;
  lws_callback_on_writable(ctx->pss->wsi);

done:
  pty_ctx_free(ctx);

  // if we are going to exit, do it now.
  if (force_exit) exit(0);
}

static char **build_args(struct pss_tty *pss) {
  int i, n = 0;
  char **argv = xmalloc((server->argc + pss->argc + 1) * sizeof(char *));

  for (i = 0; i < server->argc; i++) {
    argv[n++] = server->argv[i];
  }

  for (i = 0; i < pss->argc; i++) {
    argv[n++] = pss->args[i];
  }

  argv[n] = NULL;

  return argv;
}

static char **build_env(struct pss_tty *pss) {
  int i = 0, n = 2;
  char **envp = xmalloc(n * sizeof(char *));

  // TERM
  envp[i] = xmalloc(36);
  snprintf(envp[i], 36, "TERM=%s", server->terminal_type);
  i++;

  // TTYD_USER
  if (strlen(pss->user) > 0) {
    envp = xrealloc(envp, (++n) * sizeof(char *));
    envp[i] = xmalloc(40);
    snprintf(envp[i], 40, "TTYD_USER=%s", pss->user);
    i++;
  }

  envp[i] = NULL;

  return envp;
}

static bool spawn_process(struct pss_tty *pss, uint16_t columns, uint16_t rows,
                          uint16_t xpixel, uint16_t ypixel) {
  pty_process *process = process_init((void *)pty_ctx_init(pss), server->loop, build_args(pss), build_env(pss));
  if (server->cwd != NULL) process->cwd = strdup(server->cwd);
  if (columns > 0) process->columns = columns;
  if (rows > 0) process->rows = rows;
  if (xpixel > 0) process->xpixel = xpixel;
  if (ypixel > 0) process->ypixel = ypixel;
  if (pty_spawn(process, process_read_cb, process_exit_cb) != 0) {
    lwsl_err("pty_spawn: %d (%s)\n", errno, strerror(errno));
    pty_ctx_free((pty_ctx_t *)process->ctx);
    process_free(process);
    return false;
  }
  lwsl_notice("started process, pid: %d\n", process->pid);
  pss->process = process;
  lws_callback_on_writable(pss->wsi);

  return true;
}

static void wsi_output(struct lws *wsi, pty_buf_t *buf) {
  if (buf == NULL) return;
  char *message = xmalloc(LWS_PRE + 1 + buf->len);
  char *ptr = message + LWS_PRE;

  *ptr = OUTPUT;
  memcpy(ptr + 1, buf->base, buf->len);
  size_t n = buf->len + 1;

  int written = lws_write(wsi, (unsigned char *)ptr, n, LWS_WRITE_BINARY);
  if (written < 0 || (size_t)written < n) {
    lwsl_err("write OUTPUT to WS\n");
  }

  free(message);
}

// 1 = a valid Basic credential, 0 = header present but wrong, -1 = no header
static int basic_credential_state(struct lws *wsi) {
  if (server->credential == NULL) return -1;
  int total = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION);
  if (total < 7) return -1;
  char *buf = xmalloc((size_t)total + 1);
  int n = lws_hdr_copy(wsi, buf, total + 1, WSI_TOKEN_HTTP_AUTHORIZATION);
  bool ok = n >= 7 && strncmp(buf, "Basic ", 6) == 0 && !strcmp(buf + 6, server->credential);
  free(buf);
  return ok ? 1 : 0;
}

static bool check_auth(struct lws *wsi, struct pss_tty *pss) {
  if (server->auth_header != NULL) {
    size_t name_len = strlen(server->auth_header);
    int value_len = lws_hdr_custom_length(wsi, server->auth_header, (int)name_len);
    if (value_len <= 0) return false;
    // Proxy headers can be long JWTs; size the copy dynamically so a long
    // value is not mistaken for a missing header.
    char *value = xmalloc((size_t)value_len + 1);
    int n = lws_hdr_custom_copy(wsi, value, value_len + 1, server->auth_header, (int)name_len);
    if (n > 0) snprintf(pss->user, sizeof(pss->user), "%s", value);
    free(value);
    return n > 0;
  }

  if (server->credential != NULL) {
    // Browsers are not required to send cached Basic credentials on the
    // WebSocket handshake (Safari does not), so an absent header falls through
    // to the AuthToken flow: the connection is unusable for anything except
    // JSON_DATA until the token from /token is validated.
    return basic_credential_state(wsi) != 0;
  }

  return true;
}

int callback_tty(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
  struct pss_tty *pss = (struct pss_tty *)user;
  char buf[256];
  size_t n = 0;

  switch (reason) {
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
      if (server->once && server->client_count > 0) {
        lwsl_warn("refuse to serve WS client due to the --once option.\n");
        return 1;
      }
      if (server->max_clients > 0 && server->client_count == server->max_clients) {
        lwsl_warn("refuse to serve WS client due to the --max-clients option.\n");
        return 1;
      }
      if (!check_auth(wsi, pss)) return 1;

      int path_len = lws_hdr_copy(wsi, pss->path, sizeof(pss->path), WSI_TOKEN_GET_URI);
#if defined(LWS_ROLE_H2)
      if (path_len <= 0) path_len = lws_hdr_copy(wsi, pss->path, sizeof(pss->path), WSI_TOKEN_HTTP_COLON_PATH);
#endif
      if (path_len <= 0 || strcmp(pss->path, endpoints.ws) != 0) {
        lwsl_warn("refuse to serve WS client for illegal ws path: %s\n", pss->path);
        return 1;
      }

      if (server->check_origin && !check_host_origin(wsi)) {
        lwsl_warn(
            "refuse to serve WS client from different origin due to the "
            "--check-origin option.\n");
        return 1;
      }
      break;

    case LWS_CALLBACK_ESTABLISHED:
      pss->initialized = false;
      pss->authenticated = false;
      pss->wsi = wsi;
      pss->lws_close_status = LWS_CLOSE_STATUS_NOSTATUS;

      if (server->credential != NULL) {
        if (basic_credential_state(wsi) == 1) {
          // A client that presented the Basic credential at the handshake is
          // already authenticated; it does not need the AuthToken as well.
          pss->authenticated = true;
        } else {
          // Browsers may skip the Basic credentials on the WS handshake and
          // authenticate with the AuthToken instead. Do not let such a
          // connection occupy a --max-clients / --once slot indefinitely.
          lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND, 5);
        }
      }

      if (server->url_arg) {
        while (lws_hdr_copy_fragment(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_URI_ARGS, n++) > 0) {
          if (strncmp(buf, "arg=", 4) == 0) {
            pss->args = xrealloc(pss->args, (pss->argc + 1) * sizeof(char *));
            pss->args[pss->argc] = strdup(&buf[4]);
            pss->argc++;
          }
        }
      }

      server->client_count++;

      lws_get_peer_simple(lws_get_network_wsi(wsi), pss->address, sizeof(pss->address));
      lwsl_notice("WS   %s - %s, clients: %d\n", pss->path, pss->address, server->client_count);
      break;

    case LWS_CALLBACK_SERVER_WRITEABLE:
      if (pss->lws_close_status > LWS_CLOSE_STATUS_NOSTATUS) {
        lws_close_reason(wsi, pss->lws_close_status, NULL, 0);
        return 1;
      }

      // The initial title/preferences messages contain the configured
      // command line; never send them to an unauthenticated connection.
      if (server->credential != NULL && !pss->authenticated) return 0;

      if (!pss->initialized) {
        if (pss->initial_cmd_index == sizeof(initial_cmds)) {
          pss->initialized = true;
          pty_resume(pss->process);
          break;
        }
        if (send_initial_message(wsi, pss->initial_cmd_index) < 0) {
          lwsl_err("failed to send initial message, index: %d\n", pss->initial_cmd_index);
          lws_close_reason(wsi, LWS_CLOSE_STATUS_UNEXPECTED_CONDITION, NULL, 0);
          return -1;
        }
        pss->initial_cmd_index++;
        lws_callback_on_writable(wsi);
        break;
      }

      if (pss->pty_buf != NULL) {
        wsi_output(wsi, pss->pty_buf);
        pty_buf_free(pss->pty_buf);
        pss->pty_buf = NULL;
        pty_resume(pss->process);
      }
      break;

    case LWS_CALLBACK_RECEIVE:
      // Zero-length fragments carry no data. The command byte has to come from
      // a non-empty fragment: xmalloc(0) returns NULL and dereferencing it
      // would crash the whole process. An empty final fragment still completes
      // a message that was accumulated from earlier fragments.
      if (len == 0) {
        if (pss->buffer == NULL) return 0;
        if (lws_remaining_packet_payload(wsi) > 0 || !lws_is_final_fragment(wsi)) return 0;
      } else {
        // Bound the accumulated message size; close with "message too big"
        // instead of letting the buffer grow without limit.
        if (len > MAX_WS_MESSAGE_LEN || (pss->buffer != NULL && pss->len + len > MAX_WS_MESSAGE_LEN)) {
          lwsl_warn("WS message too large (max %d bytes), closing connection\n", MAX_WS_MESSAGE_LEN);
          if (pss->buffer != NULL) {
            free(pss->buffer);
            pss->buffer = NULL;
            pss->len = 0;
          }
          lws_close_reason(wsi, LWS_CLOSE_STATUS_MESSAGE_TOO_LARGE, NULL, 0);
          return -1;
        }
        if (pss->buffer == NULL) {
          pss->buffer = xmalloc(len);
          pss->len = len;
          memcpy(pss->buffer, in, len);
        } else {
          pss->buffer = xrealloc(pss->buffer, pss->len + len);
          memcpy(pss->buffer + pss->len, in, len);
          pss->len += len;
        }
      }

      if (pss->buffer == NULL) return 0;

      const char command = pss->buffer[0];

      // check auth
      if (server->credential != NULL && !pss->authenticated && command != JSON_DATA) {
        lwsl_warn("WS client not authenticated\n");
        return 1;
      }

      // check if there are more fragmented messages
      if (lws_remaining_packet_payload(wsi) > 0 || !lws_is_final_fragment(wsi)) {
        return 0;
      }

      switch (command) {
        case INPUT:
          if (!server->writable) break;
          // Ignore the bare command byte (and any input before the process
          // exists); there is nothing to write.
          if (pss->len <= 1 || pss->process == NULL) break;
          int err = pty_write(pss->process, pty_buf_init(pss->buffer + 1, pss->len - 1));
          if (err) {
            lwsl_err("uv_write: %s (%s)\n", uv_err_name(err), uv_strerror(err));
            return -1;
          }
          break;
        case RESIZE_TERMINAL:
          if (pss->process == NULL) break;
          json_object_put(
              parse_window_size(pss->buffer + 1, pss->len - 1, &pss->process->columns, &pss->process->rows,
                                &pss->process->xpixel, &pss->process->ypixel));
          pty_resize(pss->process);
          break;
        case PAUSE:
          pty_pause(pss->process);
          break;
        case RESUME:
          // Do not re-arm the PTY read while the previous chunk still waits
          // for LWS_CALLBACK_SERVER_WRITEABLE: process_read_cb would overwrite
          // pss->pty_buf and leak (and lose) that chunk.
          if (pss->pty_buf == NULL) pty_resume(pss->process);
          break;
        case JSON_DATA:
          if (pss->process != NULL) break;
          uint16_t columns = 0;
          uint16_t rows = 0;
          uint16_t xpixel = 0;
          uint16_t ypixel = 0;
          json_object *obj = parse_window_size(pss->buffer, pss->len, &columns, &rows, &xpixel, &ypixel);
          if (obj == NULL) break;
          if (server->credential != NULL && !pss->authenticated) {
            // A client that already authenticated with the Basic header on
            // the handshake does not need to send the AuthToken as well.
            struct json_object *o = NULL;
            if (json_object_object_get_ex(obj, "AuthToken", &o)) {
              const char *token = json_object_get_string(o);
              if (token != NULL && !strcmp(token, server->credential)) {
                pss->authenticated = true;
                lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
              }
              else
                lwsl_warn("WS authentication failed\n");
            }
            if (!pss->authenticated) {
              json_object_put(obj);
              lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, NULL, 0);
              return -1;
            }
          }
          json_object_put(obj);
          if (!spawn_process(pss, columns, rows, xpixel, ypixel)) return 1;
          break;
        default:
          lwsl_warn("ignored unknown message type: %d\n", (int)(unsigned char)command);
          break;
      }

      if (pss->buffer != NULL) {
        free(pss->buffer);
        pss->buffer = NULL;
      }
      break;

    case LWS_CALLBACK_CLOSED:
      if (pss->wsi == NULL) break;

      server->client_count--;
      lwsl_notice("WS closed from %s, clients: %d\n", pss->address, server->client_count);
      if (pss->buffer != NULL) free(pss->buffer);
      if (pss->pty_buf != NULL) pty_buf_free(pss->pty_buf);
      for (int i = 0; i < pss->argc; i++) {
        free(pss->args[i]);
      }
      free(pss->args);

      if (pss->process != NULL) {
        ((pty_ctx_t *)pss->process->ctx)->ws_closed = true;
        if (process_running(pss->process)) {
          pty_pause(pss->process);
          lwsl_notice("killing process, pid: %d\n", pss->process->pid);
          pty_kill(pss->process, server->sig_code);
        }
      }

      if ((server->once || server->exit_no_conn) && server->client_count == 0) {
        lwsl_notice("exiting due to the --once/--exit-no-conn option.\n");

        // stop accepting new ws connections
        lws_cancel_service(context);

        if (process_running(pss->process)) {
          force_exit = true;
          lwsl_notice("send ^C to force exit.\n");
        } else {
          exit(0);
        }
      }
      break;

    default:
      break;
  }

  return 0;
}
