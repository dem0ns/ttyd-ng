# Security notes

ttyd-ng is a terminal exposed over the network: anyone who can reach the port
and pass authentication can run the configured command. The defaults are the
same as ttyd (no authentication, no origin check, bind to all interfaces), so
how you deploy it matters more than any single option.

## Deployment checklist

- Put it behind TLS (`--ssl -C cert -K key`) or a TLS-terminating proxy.
- Set `--credential user:password` (or let a reverse proxy authenticate and
  pass `--auth-header`). Without one, every visitor can start the command.
- Keep `--check-origin` on for browser use. It rejects WebSocket handshakes
  whose `Origin` is not the same host, which blocks cross-site WebSocket
  hijacking. Without it, any page the user visits can open `ws://host:7681/ws`
  and drive the terminal.
- Only use `--url-arg` when the command tolerates arbitrary extra arguments.
  A crafted link can append `?arg=...` values to the child's argv (for example
  `ssh`, `git` or `vim` options); ttyd logs a warning at startup.
- Do not place a custom `--index` file in a directory writable by other users;
  it is opened by path when requested.
- When using `--interface /path/x.sock`, keep the socket in a root-owned
  directory. libwebsockets 4.5.7 creates it and then chowns it by path while
  ttyd is still privileged.
- Prefer a build linked against libwebsockets 5.x when using a UNIX socket:
  ttyd performs and verifies the `--uid`/`--gid` drop itself, but 4.5.7 does
  the socket chown/chmod by path while still privileged.
- The container images run as a non-root `ttyd` user. Do not add `--user root`
  unless you need it, and publish the port on loopback unless remote access is
  intended.

## Hardening in this fork

- WebSocket messages are reassembled with a 1 MiB cap; empty fragments and
  malformed JSON are handled without crashes.
- WebSocket paths must match exactly; plaintext upgrades are refused when TLS
  is enabled; client certificates are verified via `preverify_ok`.
- Unauthenticated WebSocket connections expire after 5 s and never receive the
  configured command line or client preferences.
- The PTY read path survives `EAGAIN` and transient `EIO`, and a `RESUME`
  cannot overwrite a chunk that is still waiting to be written.
- Credentials of any length are supported; the encoded credential is not
  written to logs, and `/token` is sent with `Cache-Control: no-store`.
- `--uid`/`--gid` are applied and verified by ttyd; the primary gid is derived
  when `-g` is omitted.
- URL query parameters can only change presentation options; ZMODEM, trzsz,
  sixel, reconnect policy, the leave alert and fixed titles stay under the
  server operator's control.
- ZMODEM downloads require confirmation and are capped at 256 MiB; the upload
  dialog can be cancelled.
- OSC 52 clipboard reads only answer the system selection and can be disabled
  with `-t disableOsc52=true`. Writes use an `execCommand('copy')` fallback so
  asynchronous clipboard updates work, as in other terminals.

## Residual risks

- Credentials over plain HTTP are base64, not encryption. Use TLS.
- Credential comparison is not constant-time; there is no login rate limiting.
- There is no CSP or `X-Frame-Options`; ttyd can be framed, which enables
  clickjacking of the terminal UI. Do not frame it from untrusted sites.
- CSS can be influenced by URL options (clamped/sanitized) but script injection
  was not found in the client.
- Build scripts download pinned dependency versions without checksums, and the
  CI workflows use action tags rather than commit SHAs. Verify release
  artifacts (`SHA256SUMS`) and pin actions if you mirror the release pipeline.
- A hostile local user with write access to the socket directory can race the
  socket creation on libwebsockets 4.5.7 (see above).
