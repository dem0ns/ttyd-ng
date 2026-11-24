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

### Features

- Forward the client's pixel size (`xpixel`/`ypixel`) to the PTY, fixing sixel
  images inside tmux.

### Build and CI

- Native macOS static build script and arm64/x86_64 CI artifacts.
- SBOM and provenance attestations for container images.
- Ubuntu 26.04 container base.
- Linux CI job that builds and runs the WebSocket regression tests.
