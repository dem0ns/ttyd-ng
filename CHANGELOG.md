# Changelog

## 2.0.0 (2026-11-25)

First release of ttyd-ng, a community-maintained continuation of ttyd. The
binary is still called `ttyd`; the command-line interface and the WebSocket
protocol are compatible with ttyd 1.7.7.

Based on ttyd 1.7.7 with the upstream commits up to `2922cb8`, plus reviewed
pull requests that upstream never merged (see `docs/upstream-prs.md`).

### Security

- Bound reassembled WebSocket messages to 1 MiB and ignore zero-length
  fragments, instead of letting a connection grow memory without limit.
- Guard against a NULL dereference when the window-size JSON is malformed.
- Require an exact WebSocket path match and free the URL argument array.
- Reject plaintext WebSocket upgrades when TLS is enabled, closing an mTLS
  verification bypass.
- Verify client certificates using libwebsockets' `preverify_ok` (fixes
  verification with OpenSSL 4.1).
- Fall back to the HTTP/2 `:authority` pseudo-header in the origin check.
- Keep the copied argv NULL-terminated (fixes a crash with musl's getopt).
- Expire unauthenticated WebSocket connections so they cannot hold a
  `--max-clients` / `--once` slot indefinitely.
- Update webpack and webpack-dev-server to patched versions.
- Fix out-of-bounds reads in the initial window-title/preferences messages and
  in `--base-path` handling (over-long input used to overrun a fixed buffer).
- Support credentials too long for the old fixed buffer (password-manager
  output) and stop printing the encoded credential to the log.
- Mark the `/token` response `no-store` and `nosniff`.
- Ignore a bare INPUT frame instead of running zero-length buffer copies.
- A URL can no longer enable ZMODEM/trzsz/sixel, disable the leave alert or
  set a fixed title: only presentation options are taken from the query
  string, and client options are clamped/sanitized (no CSS injection).
- ZMODEM downloads ask for confirmation and refuse files over 256 MiB; the
  "remote requests a file" dialog can now be cancelled.
- OSC 52 clipboard reads are limited to the system clipboard and can be
  disabled with `-t disableOsc52=true`.

### Bug fixes

- Keep reading the PTY after a zero-byte read (`EAGAIN`) instead of stalling
  the terminal permanently.
- Recover the PTY reader after a transient `EIO`, e.g. when `login(1)` calls
  `vhangup()`.
- Support libwebsockets 5.x, where `lws_service()` no longer blocks.
- Refit the terminal after font, line-height, letter-spacing and renderer
  changes, and parse float client options correctly.
- Reconnect with exponential backoff after network drops and sleep/wake; a
  normal close or a policy rejection still waits for the user.
- OSC 52 clipboard writes work for all selection types and without a user
  gesture (`execCommand` fallback). As in other terminals, programs in the
  session can set the clipboard this way.
- Update xterm.js to 6.0.
- Mobile: keep the terminal inside the visual viewport, honor safe-area insets
  and avoid the iOS focus zoom.
- Suppress the browser context menu while a program is tracking the mouse.
- Split large pastes into messages below the server's 1 MiB cap.
- Do not reset the reconnect backoff on a server that accepts and closes
  immediately, and ignore close events from a replaced socket.
- A `RESUME` message no longer overwrites (and leaks) a PTY chunk that is
  still waiting to be written to the client.
- An unauthenticated WebSocket no longer receives the configured command line
  and client preferences before the AuthToken is accepted.
- A client that authenticates with Basic on the handshake no longer needs the
  AuthToken as well; failed AuthToken values are no longer written to logs.
- `--uid` now drops privileges reliably (ttyd performs and verifies the drop
  itself, deriving the primary gid when `-g` is omitted) instead of silently
  continuing as root under libwebsockets 4.5.7.
- Container images run as a non-root `ttyd` user by default.
- Raise the HTTP header pool and shorten the half-header idle timeout, so a
  few slow request headers cannot stall every new connection.
- Base paths up to 255 bytes now work, and a base path must start with `/`.
- Validate `-p`, `-m`, `-P`, `-f`, `-u` and `-g` ranges and reject trailing
  garbage in numbers; validate `--cwd` at startup.
- The Windows command line is built with an exact allocation instead of a
  256-byte stack buffer.
- Container base images are pinned, CI jobs have explicit read-only
  permissions and do not persist the checkout token, and the snap recipe
  builds this repository instead of upstream.

### Features

- Forward the client's pixel size (`xpixel`/`ypixel`) to the PTY, fixing sixel
  images inside tmux.

### Build and CI

- Native macOS static build script and arm64/x86_64 CI artifacts.
- SBOM and provenance attestations for container images.
- Ubuntu 26.04 container base.
- Linux CI job that builds and runs the WebSocket regression tests.
