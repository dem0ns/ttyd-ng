![backend](https://github.com/dem0ns/ttyd-ng/actions/workflows/backend.yml/badge.svg)
![frontend](https://github.com/dem0ns/ttyd-ng/actions/workflows/frontend.yml/badge.svg)
[![GitHub Releases](https://img.shields.io/github/downloads/dem0ns/ttyd-ng/total)](https://github.com/dem0ns/ttyd-ng/releases)
![GitHub](https://img.shields.io/github/license/dem0ns/ttyd-ng)

# ttyd-ng - Share your terminal over the web

ttyd-ng is a community-maintained fork of [ttyd](https://github.com/tsl0922/ttyd),
which has been effectively unmaintained since 2024. It keeps the same command
line interface and WebSocket protocol (the binary is still called `ttyd`) and
folds in the security fixes and bug fixes that accumulated upstream.

![screenshot](https://github.com/dem0ns/ttyd-ng/raw/main/screenshot.gif)

# Features

- Built on top of [libuv](https://libuv.org) and [WebGL2](https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API) for speed
- Fully-featured terminal with [CJK](https://en.wikipedia.org/wiki/CJK_characters) and IME support
- [ZMODEM](https://en.wikipedia.org/wiki/ZMODEM) ([lrzsz](https://ohse.de/uwe/software/lrzsz.html)) / [trzsz](https://trzsz.github.io) file transfer support
- [Sixel](https://en.wikipedia.org/wiki/Sixel) image output support ([img2sixel](https://saitoha.github.io/libsixel) / [lsix](https://github.com/hackerb9/lsix))
- SSL support based on [OpenSSL](https://www.openssl.org) / [Mbed TLS](https://github.com/Mbed-TLS/mbedtls)
- Run any custom command with options
- Basic authentication support and many other custom options
- Cross platform: macOS, Linux, FreeBSD/OpenBSD, [OpenWrt](https://openwrt.org), Windows

# Changes from upstream

ttyd-ng is based on ttyd 1.7.7 plus the upstream commits up to `2922cb8`
(August 2026). On top of that it integrates the useful, reviewed pull requests
that upstream never merged:

- **Security**
  - Bound reassembled WebSocket messages (1 MiB) and ignore zero-length
    fragments, closing the connection instead of growing memory without limit
    (upstream #1544, #1574, #1593).
  - Guard the NULL dereference on malformed window-size JSON (#1545).
  - Require an exact WebSocket path match and free the URL argument array (#1585).
  - Reject plaintext WebSocket upgrades when TLS is enabled, closing the mTLS
    verification bypass (#1550).
  - Verify client certificates with libwebsockets' `preverify_ok` (#1584).
  - Fall back to the HTTP/2 `:authority` pseudo-header in the origin check (#1592).
  - Keep the copied argv NULL-terminated (#1576).
  - Update the frontend toolchain to patched webpack / webpack-dev-server versions.
  - Expire unauthenticated WebSocket connections so they cannot hold a
    `--max-clients` / `--once` slot indefinitely.
- **Bug fixes**
  - Keep reading the PTY after a zero-byte read instead of stalling the terminal
    forever (#1573).
  - Recover the PTY reader after a transient `EIO` (e.g. `login(1)` calling
    `vhangup()`), instead of showing a permanently black terminal (#1529).
  - Support libwebsockets 5.x, where `lws_service()` no longer blocks.
  - Refit the terminal after font, line-height, letter-spacing and renderer
    changes (#1530, #1595) and parse float client options correctly.
  - Reconnect with exponential backoff after network drops and sleep/wake (#1536).
  - OSC 52 clipboard writes work for all selection types and without a user
    gesture (#1518, #1565).
  - Update xterm.js to 6.0.
  - Mobile: keep the terminal inside the visual viewport, honor safe-area insets
    and avoid the iOS focus zoom (#1531, #1597).
  - Suppress the browser context menu while a program is tracking the mouse (#1520).
- **Features**
  - Forward the client's pixel size (`xpixel`/`ypixel`) to the PTY, fixing sixel
    images inside tmux (#1560).
- **Build and CI**
  - Native macOS build script and CI artifacts for arm64 and x86_64 (#1553).
  - SBOM and provenance attestations for published container images (#1562).
  - Ubuntu 26.04 container base, current runner images, additional distro
    install instructions.

# Installation

## Install on macOS

- Install with [Homebrew](http://brew.sh): `brew install ttyd`
- Install with [MacPorts](https://www.macports.org): `sudo port install ttyd`
- Precompiled binaries: download from the [releases](https://github.com/dem0ns/ttyd-ng/releases) page (note: not codesigned/notarized — see [Gatekeeper and quarantine](docs/macos-build.md#gatekeeper-and-quarantine-on-downloaded-release-binaries))
- [Build from source](docs/macos-build.md)

## Install on Linux

> The distro packages below install **upstream ttyd**, not ttyd-ng. Use the
> release binaries for the fixes in this fork.

- Install on Debian/Ubuntu: `sudo apt install ttyd`
- Install the snap: `sudo snap install ttyd --classic`
- Install on OpenWrt: `opkg install ttyd`
- Install on Gentoo: `emerge -a www-apps/ttyd`
- Install on Arch: `sudo pacman -S ttyd`
- Install on Void: `sudo xbps-install ttyd`
- Install on Fedora: `sudo dnf install ttyd`
- Install on Alpine: `doas apk add ttyd`
- Install on FreeBSD: `sudo pkg install ttyd`
- Install on OpenBSD: `doas pkg_add ttyd`
- Install with [Homebrew](https://docs.brew.sh/Homebrew-on-Linux) : `brew install ttyd`
- Precompiled static binaries: download from the [releases](https://github.com/dem0ns/ttyd-ng/releases) page

Build from source (Fedora/RHEL):

```bash
sudo dnf install -y gcc gcc-c++ make cmake libuv-devel libwebsockets-devel json-c-devel openssl-devel zlib-devel
git clone https://github.com/dem0ns/ttyd-ng.git
cd ttyd-ng && mkdir build && cd build
cmake .. && make && sudo make install
```

## Install on Windows

- Binary version (recommended): download from the [releases](https://github.com/dem0ns/ttyd-ng/releases) page
- [Compile on Windows](https://github.com/tsl0922/ttyd/wiki/Compile-on-Windows) (upstream wiki)

# Usage

## Command-line Options

```
USAGE:
    ttyd [options] <command> [<arguments...>]

OPTIONS:
    -p, --port              Port to listen (default: 7681, use `0` for random port)
    -i, --interface         Network interface to bind (eg: eth0), or UNIX domain socket path (eg: /var/run/ttyd.sock)
    -U, --socket-owner      User owner of the UNIX domain socket file, when enabled (eg: user:group)
    -c, --credential        Credential for basic authentication (format: username:password)
    -H, --auth-header       HTTP Header name for auth proxy, this will configure ttyd to let a HTTP reverse proxy handle authentication
    -u, --uid               User id to run with
    -g, --gid               Group id to run with
    -s, --signal            Signal to send to the command when exit it (default: 1, SIGHUP)
    -w, --cwd               Working directory to be set for the child program
    -a, --url-arg           Allow client to send command line arguments in URL (eg: http://localhost:7681?arg=foo&arg=bar)
    -W, --writable          Allow clients to write to the TTY (readonly by default)
    -t, --client-option     Send option to client (format: key=value), repeat to add more options
    -T, --terminal-type     Terminal type to report, default: xterm-256color
    -O, --check-origin      Do not allow websocket connection from different origin
    -m, --max-clients       Maximum clients to support (default: 0, no limit)
    -o, --once              Accept only one client and exit on disconnection
    -q, --exit-no-conn      Exit on all clients disconnection
    -B, --browser           Open terminal with the default system browser
    -I, --index             Custom index.html path
    -b, --base-path         Expected base path for requests coming from a reverse proxy (eg: /mounted/here, max length: 128)
    -P, --ping-interval     Websocket ping interval(sec) (default: 5)
    -6, --ipv6              Enable IPv6 support
    -S, --ssl               Enable SSL
    -C, --ssl-cert          SSL certificate file path
    -K, --ssl-key           SSL key file path
    -A, --ssl-ca            SSL CA file path for client certificate verification
    -d, --debug             Set log level (default: 7)
    -v, --version           Print the version and exit
    -h, --help              Print this text and exit
```

Read the example usage on the [upstream wiki](https://github.com/tsl0922/ttyd/wiki/Example-Usage).

## Browser Support

Modern browsers, See [Browser Support](https://github.com/xtermjs/xterm.js#browser-support).

## Alternatives

* [Wetty](https://github.com/krishnasrinivas/wetty): [Node](https://nodejs.org) based web terminal (SSH/login)
* [GoTTY](https://github.com/yudai/gotty): [Go](https://golang.org) based web terminal
