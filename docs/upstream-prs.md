# Upstream pull request triage

This document records what happened to the open pull requests on
[tsl0922/ttyd](https://github.com/tsl0922/ttyd) when ttyd-ng was started
(November 2026). Each PR was reviewed for whether it fixes a real problem and
whether the change is safe; PRs that only rebuilt the bundled frontend, had no
working change, or introduced a new feature were handled separately.

## Merged (possibly adapted)

| PR | Change | Note |
| --- | --- | --- |
| #1465 | Refit after preferences | Superseded by the shared refit work (#1530, #1595) |
| #1488 | Fedora build instructions | Merged with the unnecessary `libev-devel` removed |
| #1518 | OSC 52 all selection types | Merged together with #1565 (custom provider + execCommand) |
| #1520 | Context menu during mouse tracking | Merged in a simplified, capture-phase form |
| #1525 | Distro install instructions | Merged |
| #1529 | Recover PTY reader after `vhangup()`/EIO | Merged; the `EAGAIN` fix from #1573 is preserved |
| #1530 | Refit on line-height/letter-spacing, float options | Merged |
| #1531 | Mobile keyboard viewport / background | Merged |
| #1533 | Ubuntu 26.04 container base | Merged |
| #1536 | Reconnect with exponential backoff | Merged, but a normal close (1000) still waits for Enter |
| #1544 | WebSocket message size cap | Superseded by #1593 (1 MiB cap) |
| #1545 | NULL dereference on malformed JSON | Merged |
| #1550 | Reject plaintext upgrades when TLS is enabled | Merged |
| #1553 | Native macOS build + CI | Merged with current runner labels |
| #1556 | webpack-dev-server security bump | Covered by the dependency upgrade |
| #1560 | Forward `xpixel`/`ypixel` to the PTY | Merged, and the web client now sends them |
| #1561 | Initial terminal size | Covered by the refit work |
| #1562 | SBOM/provenance for container images | Merged |
| #1565 | OSC 52 without a user gesture | Merged together with #1518 |
| #1573 | Keep reading after a zero-byte PTY read | Merged |
| #1574 | Ignore empty WebSocket messages | Superseded by #1593 |
| #1576 | NULL-terminate the copied argv | Merged |
| #1580 | Allow the AuthToken flow when Basic credentials are absent | Merged; unauthenticated sockets now expire after 5 s |
| #1584 | Use `preverify_ok` for client certificates | Merged and verified with OpenSSL 4.1 |
| #1585 | Exact WebSocket path match, free URL args | Merged |
| #1589 | Drive the libuv loop directly on libwebsockets 5 | Merged |
| #1591 | Dependency update + libwebsockets 5 support | Only the compatibility parts were taken (event loop, URI parsing, Windows link libs); the dependency overhaul was not |
| #1592 | HTTP/2 `:authority` in the origin check | Merged |
| #1593 | Bound WebSocket messages, ignore zero-length fragments | Merged, plus handling for an empty final fragment |
| #1595 | Refit after a renderer switch | Merged (`onRender` one-shot fit) |
| #1597 | Safe-area insets and iOS input zoom | Merged |
| #1526, #1540, #1542, #1543, #1552, #1554, #1555, #1559 | Dependabot bumps | Superseded by a single dependency upgrade; `yarn npm audit` is clean apart from the eslint 8 deprecation notice |

## Not merged

| PR | Reason |
| --- | --- |
| #747 | Stale (`-f` now means `--srv-buf-size`), writes URL arguments to a temp file, needs a product decision |
| #1448 | New `--config` feature; the implementation rebuilds the uv loop and needs a rewrite |
| #1450 | Superseded by #1580, which rejects a wrong Basic header instead of ignoring it |
| #1464 | Credentials in URL parameters leak into logs and history |
| #1468 | `postMessage` input injection without any origin check |
| #1451 | Bell sound support; new feature, not approved |
| #1469 | Small cross-origin notification feature; not approved |
| #1481 | POST-body argument passing; sketchy implementation and no clear use case |
| #1493 | Mobile toolbar; superseded by #1504 |
| #1504 | Large mobile on-screen keyboard feature; not approved |
| #1549 | Title mismatch (adds a libsystemd D-Bus notification bridge), new Linux-only dependency, unrelated clipboard changes |
| #1558 | Duplicate of #1529 with a hard-coded `-codex-pty1` version suffix |
| #1587 | Mixes a real xterm.js 6 update with a committed `/root/ttyd` Makefile, a CMake minimum downgrade and arbitrary version bumps; the xterm 6 update was redone cleanly instead |
| #1523 | Outbound WebSocket client mode; large architectural feature, not approved |

## Verification

- `tests/ws_test.py` and `tests/backend-regression.py` are stdlib-only
  integration tests that start a real server on an ephemeral port.
- The backend is built and tested with AddressSanitizer/UndefinedBehaviorSanitizer
  on macOS, with the macOS static dependency build (libwebsockets 4.5.7), and on
  Linux/Alpine (musl) with libwebsockets 4.x.
- TLS: plaintext upgrades are rejected when `--ssl` is set; with `--ssl-ca`,
  a client certificate is required and a valid one is accepted on OpenSSL 4.1.
