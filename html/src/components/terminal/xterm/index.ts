import { bind } from 'decko';
import type { IDisposable, ITerminalOptions } from '@xterm/xterm';
import { Terminal } from '@xterm/xterm';
import { CanvasAddon } from '@xterm/addon-canvas';
import { ClipboardAddon, type IClipboardProvider, type ClipboardSelectionType } from '@xterm/addon-clipboard';
import { WebglAddon } from '@xterm/addon-webgl';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { ImageAddon } from '@xterm/addon-image';
import { Unicode11Addon } from '@xterm/addon-unicode11';
import { OverlayAddon } from './addons/overlay';
import { ZmodemAddon } from './addons/zmodem';

import '@xterm/xterm/css/xterm.css';

interface TtydTerminal extends Terminal {
    fit(): void;
}

declare global {
    interface Window {
        term: TtydTerminal;
    }
}

enum Command {
    // server side
    OUTPUT = '0',
    SET_WINDOW_TITLE = '1',
    SET_PREFERENCES = '2',

    // client side
    INPUT = '0',
    RESIZE_TERMINAL = '1',
    PAUSE = '2',
    RESUME = '3',
}
type Preferences = ITerminalOptions & ClientOptions;

export type RendererType = 'dom' | 'canvas' | 'webgl';

export interface ClientOptions {
    rendererType: RendererType;
    disableLeaveAlert: boolean;
    disableResizeOverlay: boolean;
    enableZmodem: boolean;
    enableTrzsz: boolean;
    enableSixel: boolean;
    titleFixed?: string;
    isWindows: boolean;
    trzszDragInitTimeout: number;
    unicodeVersion: string;
    closeOnDisconnect: boolean;
}

export interface FlowControl {
    limit: number;
    highWater: number;
    lowWater: number;
}

export interface XtermOptions {
    wsUrl: string;
    tokenUrl: string;
    flowControl: FlowControl;
    clientOptions: ClientOptions;
    termOptions: ITerminalOptions;
}

function toDisposable(f: () => void): IDisposable {
    return { dispose: f };
}

function addEventListener(target: EventTarget, type: string, listener: EventListener): IDisposable {
    target.addEventListener(type, listener);
    return toDisposable(() => target.removeEventListener(type, listener));
}

// document.execCommand('copy') predates the user-activation requirement of
// navigator.clipboard: OSC 52 writes arrive asynchronously from the PTY, well
// outside any gesture, so the async clipboard API rejects them. Try the legacy
// path first and let the caller fall back if it returns false.
function copyWithExecCommand(text: string): boolean {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.cssText = 'position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;';
    document.body.appendChild(textarea);

    const selection = document.getSelection();
    const savedRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;
    const previousFocus = document.activeElement as HTMLElement | null;
    textarea.select();

    let copied = false;
    try {
        copied = document.execCommand('copy');
    } catch {
        copied = false;
    }

    document.body.removeChild(textarea);
    if (savedRange && selection) {
        selection.removeAllRanges();
        selection.addRange(savedRange);
    }
    // Selecting the textarea moved focus away from the terminal; give it back
    // so the user can keep typing after an OSC 52 write.
    previousFocus?.focus?.();
    return copied;
}

// Browsers have a single clipboard, so accept every OSC 52 selection type
// instead of dropping all but 'c' (tmux uses 'p' by default).
class TtydClipboardProvider implements IClipboardProvider {
    constructor(private overlayAddon: OverlayAddon) {}

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async readText(_selection: ClipboardSelectionType): Promise<string> {
        if (!navigator.clipboard) return '';
        try {
            return await navigator.clipboard.readText();
        } catch {
            return '';
        }
    }

    async writeText(_selection: ClipboardSelectionType, text: string): Promise<void> {
        if (!copyWithExecCommand(text)) {
            try {
                await navigator.clipboard.writeText(text);
            } catch (e) {
                console.warn('[ttyd] clipboard write failed:', e);
                return;
            }
        }
        this.overlayAddon.showOverlay('✂', 200);
    }
}

// The addon's typings declare (provider?), but the runtime constructor is
// (base64, provider); passing undefined keeps the default base64 codec.
type ClipboardAddonCtor = new (base64?: unknown, provider?: IClipboardProvider) => ClipboardAddon;

export class Xterm {
    private disposables: IDisposable[] = [];
    private textEncoder = new TextEncoder();
    private textDecoder = new TextDecoder();
    private written = 0;
    private pending = 0;

    private terminal: Terminal;
    private fitAddon = new FitAddon();
    private overlayAddon = new OverlayAddon();
    private clipboardAddon = new (ClipboardAddon as unknown as ClipboardAddonCtor)(
        undefined,
        new TtydClipboardProvider(this.overlayAddon)
    );
    private webLinksAddon = new WebLinksAddon();
    private webglAddon?: WebglAddon;
    private canvasAddon?: CanvasAddon;
    private zmodemAddon?: ZmodemAddon;

    private socket?: WebSocket;
    private token: string;
    private opened = false;
    private title?: string;
    private titleFixed?: string;
    private resizeOverlay = true;
    private reconnect = true;
    private doReconnect = true;
    private closeOnDisconnect = false;

    // Reconnect with exponential backoff: a laptop waking from sleep or a
    // short network drop should not leave the terminal stuck until the user
    // notices and presses Enter.
    private reconnectDelay = 1000;
    private readonly reconnectMaxDelay = 30000;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private reconnectKeyDisposable?: IDisposable;
    private visibilityHandlerInstalled = false;
    private fitPending = false;
    private parent?: HTMLElement;

    private writeFunc = (data: ArrayBuffer) => this.writeData(new Uint8Array(data));

    constructor(
        private options: XtermOptions,
        private sendCb: () => void
    ) {}

    dispose() {
        for (const d of this.disposables) {
            d.dispose();
        }
        this.disposables.length = 0;
        if (this.reconnectTimer !== null) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this.reconnectKeyDisposable?.dispose();
        this.reconnectKeyDisposable = undefined;
        this.visibilityHandlerInstalled = false;
    }

    @bind
    private register<T extends IDisposable>(d: T): T {
        this.disposables.push(d);
        return d;
    }

    @bind
    public sendFile(files: FileList) {
        this.zmodemAddon?.sendFile(files);
    }

    @bind
    public async refreshToken() {
        try {
            const resp = await fetch(this.options.tokenUrl);
            if (resp.ok) {
                const json = await resp.json();
                this.token = json.token;
            }
        } catch (e) {
            console.error(`[ttyd] fetch ${this.options.tokenUrl}: `, e);
        }
    }

    @bind
    private onWindowUnload(event: BeforeUnloadEvent) {
        event.preventDefault();
        if (this.socket?.readyState === WebSocket.OPEN) {
            const message = 'Close terminal? this will also terminate the command.';
            event.returnValue = message;
            return message;
        }
        return undefined;
    }

    @bind
    public open(parent: HTMLElement) {
        this.parent = parent;
        this.terminal = new Terminal(this.options.termOptions);
        const { terminal, fitAddon, overlayAddon, clipboardAddon, webLinksAddon } = this;
        window.term = terminal as TtydTerminal;
        window.term.fit = () => {
            this.fitAddon.fit();
        };

        terminal.loadAddon(fitAddon);
        terminal.loadAddon(overlayAddon);
        terminal.loadAddon(clipboardAddon);
        terminal.loadAddon(webLinksAddon);

        terminal.open(parent);
        this.syncPageBackground();
        this.syncViewport();
        fitAddon.fit();

        // Suppress the browser context menu while the program is handling
        // mouse events (tmux, vim, ...); Shift+right-click keeps the native
        // menu available.
        terminal.element?.addEventListener(
            'contextmenu',
            e => {
                if (e.shiftKey) return;
                if (terminal.modes.mouseTrackingMode !== 'none') {
                    e.preventDefault();
                    e.stopImmediatePropagation();
                }
            },
            { capture: true }
        );
    }

    @bind
    private syncPageBackground() {
        const themeBackground = this.terminal?.options.theme?.background;
        const color = typeof themeBackground === 'string' && themeBackground !== '' ? themeBackground : '#2b2b2b';
        document.documentElement.style.backgroundColor = color;
        document.body.style.backgroundColor = color;
    }

    // Keep the terminal exactly inside the visual viewport: on mobile the
    // layout viewport does not shrink when the on-screen keyboard opens, so
    // without this the bottom of the terminal (and the cursor) scrolls out of
    // view.
    @bind
    private syncViewport() {
        if (!this.parent) return;
        const viewport = window.visualViewport;
        if (viewport) {
            this.parent.style.height = `${Math.round(viewport.height)}px`;
            this.parent.style.top = `${Math.max(0, Math.round(viewport.offsetTop))}px`;
        } else {
            this.parent.style.height = '';
            this.parent.style.top = '';
        }
    }

    // Coalesce fits requested from renderer/font changes into one animation
    // frame; fitting synchronously right after changing renderer options
    // measures stale cell metrics.
    @bind
    private scheduleFit() {
        if (this.fitPending) return;
        this.fitPending = true;
        requestAnimationFrame(() => {
            this.fitPending = false;
            if (this.terminal?.element) this.fitAddon.fit();
        });
    }

    // xterm sizes the .xterm-screen element to the character grid, so its CSS
    // size is the terminal's pixel size. Programs read it through TIOCGWINSZ
    // (sixel images inside tmux depend on it).
    private getPixelSize(): { xpixel: number; ypixel: number } {
        const screen = this.terminal?.element?.querySelector('.xterm-screen') as HTMLElement | null;
        if (!screen) return { xpixel: 0, ypixel: 0 };
        return { xpixel: Math.round(screen.offsetWidth), ypixel: Math.round(screen.offsetHeight) };
    }

    private getWindowSizeMessage(cols: number, rows: number, authToken?: string): string {
        const { xpixel, ypixel } = this.getPixelSize();
        const msg: { [key: string]: number | string } = {};
        if (authToken !== undefined) msg.AuthToken = authToken;
        msg.columns = cols;
        msg.rows = rows;
        // A zero would reset the PTY pixel size; omit the fields until the
        // screen element has been laid out instead.
        if (xpixel > 0 && ypixel > 0) {
            msg.xpixel = xpixel;
            msg.ypixel = ypixel;
        }
        return JSON.stringify(msg);
    }

    private sendWindowSize(cols: number, rows: number) {
        this.socket?.send(this.textEncoder.encode(Command.RESIZE_TERMINAL + this.getWindowSizeMessage(cols, rows)));
    }

    // A newly loaded renderer may measure character cells differently; fit
    // once after it has drawn, otherwise the terminal keeps its old column
    // count until the window happens to be resized.
    @bind
    private fitOnNextRender() {
        if (!this.terminal) return;
        const disposable = this.terminal.onRender(() => {
            disposable.dispose();
            this.scheduleFit();
        });
    }

    @bind
    private initListeners() {
        const { terminal, fitAddon, overlayAddon, register, sendData } = this;
        register(
            terminal.onTitleChange(data => {
                if (data && data !== '' && !this.titleFixed) {
                    document.title = data + ' | ' + this.title;
                }
            })
        );
        register(terminal.onData(data => sendData(data)));
        register(terminal.onBinary(data => sendData(Uint8Array.from(data, v => v.charCodeAt(0)))));
        register(
            terminal.onResize(({ cols, rows }) => {
                this.sendWindowSize(cols, rows);
                if (this.resizeOverlay) overlayAddon.showOverlay(`${cols}x${rows}`, 300);
            })
        );
        register(
            terminal.onSelectionChange(() => {
                if (this.terminal.getSelection() === '') return;
                try {
                    document.execCommand('copy');
                } catch (e) {
                    return;
                }
                this.overlayAddon?.showOverlay('\u2702', 200);
            })
        );
        register(
            addEventListener(window, 'resize', () => {
                this.syncViewport();
                fitAddon.fit();
            })
        );
        if (window.visualViewport) {
            // Pinch-zoom changes visualViewport.height/scale; refitting on
            // every zoom step would turn magnification into a reflow.
            register(
                addEventListener(window.visualViewport, 'resize', () => {
                    if (window.visualViewport!.scale !== 1) return;
                    this.syncViewport();
                    fitAddon.fit();
                })
            );
            register(
                addEventListener(window.visualViewport, 'scroll', () => {
                    if (window.visualViewport!.scale !== 1) return;
                    this.syncViewport();
                })
            );
        }
        register(addEventListener(window, 'beforeunload', this.onWindowUnload));
    }

    @bind
    public writeData(data: string | Uint8Array) {
        const { terminal, textEncoder } = this;
        const { limit, highWater, lowWater } = this.options.flowControl;

        this.written += data.length;
        if (this.written > limit) {
            terminal.write(data, () => {
                this.pending = Math.max(this.pending - 1, 0);
                if (this.pending < lowWater) {
                    this.socket?.send(textEncoder.encode(Command.RESUME));
                }
            });
            this.pending++;
            this.written = 0;
            if (this.pending > highWater) {
                this.socket?.send(textEncoder.encode(Command.PAUSE));
            }
        } else {
            terminal.write(data);
        }
    }

    @bind
    public sendData(data: string | Uint8Array) {
        const { socket, textEncoder } = this;
        if (socket?.readyState !== WebSocket.OPEN) return;

        if (typeof data === 'string') {
            const payload = new Uint8Array(data.length * 3 + 1);
            payload[0] = Command.INPUT.charCodeAt(0);
            const stats = textEncoder.encodeInto(data, payload.subarray(1));
            socket.send(payload.subarray(0, (stats.written as number) + 1));
        } else {
            const payload = new Uint8Array(data.length + 1);
            payload[0] = Command.INPUT.charCodeAt(0);
            payload.set(data, 1);
            socket.send(payload);
        }
    }

    @bind
    public connect() {
        // Reconnect can be requested from the backoff timer, the visibility
        // handler and the Enter key; only one socket may be in flight.
        const state = this.socket?.readyState;
        if (state === WebSocket.CONNECTING || state === WebSocket.OPEN) return;
        this.reconnectKeyDisposable?.dispose();
        this.reconnectKeyDisposable = undefined;

        this.socket = new WebSocket(this.options.wsUrl, ['tty']);
        const { socket, register } = this;

        socket.binaryType = 'arraybuffer';
        register(addEventListener(socket, 'open', this.onSocketOpen));
        register(addEventListener(socket, 'message', this.onSocketData as EventListener));
        register(addEventListener(socket, 'close', this.onSocketClose as EventListener));
        // Do not give up on reconnect here: the browser always fires `close`
        // after `error`, and onSocketClose schedules a backoff retry.
        register(addEventListener(socket, 'error', () => console.log('[ttyd] websocket error (will retry on close)')));
        this.installVisibilityHandler();
    }

    @bind
    private installVisibilityHandler() {
        if (this.visibilityHandlerInstalled) return;
        this.visibilityHandlerInstalled = true;
        const { register } = this;
        register(
            addEventListener(document, 'visibilitychange', () => {
                if (document.visibilityState !== 'visible') return;
                const state = this.socket?.readyState;
                const socketDown = state === undefined || state === WebSocket.CLOSED || state === WebSocket.CLOSING;
                if (!socketDown || !this.reconnect) return;
                console.log('[ttyd] tab visible again, reconnecting immediately');
                if (this.reconnectTimer !== null) {
                    clearTimeout(this.reconnectTimer);
                    this.reconnectTimer = null;
                }
                this.reconnectDelay = 1000;
                this.refreshToken().then(this.connect);
            })
        );
    }

    @bind
    private onSocketOpen() {
        console.log('[ttyd] websocket connection opened');

        const { textEncoder, terminal, overlayAddon } = this;
        this.socket?.send(textEncoder.encode(this.getWindowSizeMessage(terminal.cols, terminal.rows, this.token)));
        // The socket can open before the first render, when .xterm-screen has
        // no size yet; resend the size once the grid has been laid out.
        if (this.getPixelSize().xpixel === 0) {
            requestAnimationFrame(() => {
                if (this.socket?.readyState === WebSocket.OPEN) this.sendWindowSize(terminal.cols, terminal.rows);
            });
        }

        if (this.opened) {
            terminal.reset();
            terminal.options.disableStdin = false;
            overlayAddon.showOverlay('Reconnected', 300);
        } else {
            this.opened = true;
        }

        this.doReconnect = this.reconnect;
        this.reconnectDelay = 1000;
        if (this.reconnectTimer !== null) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this.syncViewport();
        this.initListeners();
        terminal.focus();
    }

    @bind
    private onSocketClose(event: CloseEvent) {
        console.log(`[ttyd] websocket connection closed with code: ${event.code}`);

        const { refreshToken, connect, overlayAddon } = this;
        overlayAddon.showOverlay('Connection Closed');
        this.dispose();

        if (this.closeOnDisconnect) {
            window.close();
            return;
        }

        // 1000: CLOSE_NORMAL means the server or the child process finished on
        // purpose, and 1008 is a policy rejection (bad AuthToken). Retrying
        // either automatically makes no sense; anything else (network drop,
        // sleep/wake, VPN flap) is retried with exponential backoff.
        if (!this.reconnect || event.code === 1000 || event.code === 1008) {
            const { terminal } = this;
            const keyDispose = terminal.onKey(e => {
                if (e.domEvent.key === 'Enter') {
                    keyDispose.dispose();
                    this.reconnectKeyDisposable = undefined;
                    overlayAddon.showOverlay('Reconnecting...');
                    refreshToken().then(connect);
                }
            });
            this.reconnectKeyDisposable = keyDispose;
            overlayAddon.showOverlay('Press ⏎ to Reconnect');
            return;
        }

        // dispose() removed the visibility listener (it was registered while
        // the socket was still open); re-arm it for the disconnected window so
        // a tab switch can skip the remaining backoff.
        this.installVisibilityHandler();
        this.scheduleReconnect();
    }

    @bind
    private scheduleReconnect() {
        if (this.reconnectTimer !== null) return;
        const delay = this.reconnectDelay;
        const seconds = Math.round(delay / 100) / 10;
        this.overlayAddon.showOverlay(`Reconnecting in ${seconds}s...`, Math.min(delay, 2000));
        console.log(`[ttyd] scheduling reconnect in ${delay}ms`);
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.reconnectMaxDelay);
            this.overlayAddon.showOverlay('Reconnecting...');
            this.refreshToken().then(this.connect);
        }, delay);
    }

    @bind
    private parseOptsFromUrlQuery(query: string): Preferences {
        const { terminal } = this;
        const { clientOptions } = this.options;
        const prefs = {} as Preferences;
        const queryObj = Array.from(new URLSearchParams(query) as unknown as Iterable<[string, string]>);

        for (const [k, queryVal] of queryObj) {
            let v = clientOptions[k];
            if (v === undefined) v = terminal.options[k];
            switch (typeof v) {
                case 'boolean':
                    prefs[k] = queryVal === 'true' || queryVal === '1';
                    break;
                case 'number': {
                    // lineHeight, letterSpacing, ... are floats; parseInt
                    // silently turned 1.5 into 1.
                    const parsed = Number.parseFloat(queryVal);
                    prefs[k] = Number.isNaN(parsed) ? queryVal : parsed;
                    break;
                }
                case 'bigint':
                    prefs[k] = Number.parseInt(queryVal, 10);
                    break;
                case 'string':
                    prefs[k] = queryVal;
                    break;
                case 'object':
                    prefs[k] = JSON.parse(queryVal);
                    break;
                default:
                    console.warn(`[ttyd] maybe unknown option: ${k}=${queryVal}, treating as string`);
                    prefs[k] = queryVal;
                    break;
            }
        }

        return prefs;
    }

    @bind
    private onSocketData(event: MessageEvent) {
        const { textDecoder } = this;
        const rawData = event.data as ArrayBuffer;
        const cmd = String.fromCharCode(new Uint8Array(rawData)[0]);
        const data = rawData.slice(1);

        switch (cmd) {
            case Command.OUTPUT:
                this.writeFunc(data);
                break;
            case Command.SET_WINDOW_TITLE:
                this.title = textDecoder.decode(data);
                document.title = this.title;
                break;
            case Command.SET_PREFERENCES:
                this.applyPreferences({
                    ...this.options.clientOptions,
                    ...JSON.parse(textDecoder.decode(data)),
                    ...this.parseOptsFromUrlQuery(window.location.search),
                } as Preferences);
                break;
            default:
                console.warn(`[ttyd] unknown command: ${cmd}`);
                break;
        }
    }

    @bind
    private applyPreferences(prefs: Preferences) {
        const { terminal, register } = this;
        let needsFit = false;
        if (prefs.enableZmodem || prefs.enableTrzsz) {
            this.zmodemAddon = new ZmodemAddon({
                zmodem: prefs.enableZmodem,
                trzsz: prefs.enableTrzsz,
                windows: prefs.isWindows,
                trzszDragInitTimeout: prefs.trzszDragInitTimeout,
                onSend: this.sendCb,
                sender: this.sendData,
                writer: this.writeData,
            });
            this.writeFunc = data => this.zmodemAddon?.consume(data);
            terminal.loadAddon(register(this.zmodemAddon));
        }

        for (const [key, value] of Object.entries(prefs)) {
            switch (key) {
                case 'rendererType':
                    this.setRendererType(value);
                    needsFit = true;
                    break;
                case 'disableLeaveAlert':
                    if (value) {
                        window.removeEventListener('beforeunload', this.onWindowUnload);
                        console.log('[ttyd] Leave site alert disabled');
                    }
                    break;
                case 'disableResizeOverlay':
                    if (value) {
                        console.log('[ttyd] Resize overlay disabled');
                        this.resizeOverlay = false;
                    }
                    break;
                case 'disableReconnect':
                    if (value) {
                        console.log('[ttyd] Reconnect disabled');
                        this.reconnect = false;
                        this.doReconnect = false;
                    }
                    break;
                case 'enableZmodem':
                    if (value) console.log('[ttyd] Zmodem enabled');
                    break;
                case 'enableTrzsz':
                    if (value) console.log('[ttyd] trzsz enabled');
                    break;
                case 'trzszDragInitTimeout':
                    if (value) console.log(`[ttyd] trzsz drag init timeout: ${value}`);
                    break;
                case 'enableSixel':
                    if (value) {
                        terminal.loadAddon(register(new ImageAddon()));
                        console.log('[ttyd] Sixel enabled');
                    }
                    break;
                case 'closeOnDisconnect':
                    if (value) {
                        console.log('[ttyd] close on disconnect enabled (Reconnect disabled)');
                        this.closeOnDisconnect = true;
                        this.reconnect = false;
                        this.doReconnect = false;
                    }
                    break;
                case 'titleFixed':
                    if (!value || value === '') break;
                    console.log(`[ttyd] setting fixed title: ${value}`);
                    this.titleFixed = value;
                    document.title = value;
                    break;
                case 'isWindows':
                    if (value) console.log('[ttyd] is windows');
                    break;
                case 'unicodeVersion':
                    switch (value) {
                        case 6:
                        case '6':
                            console.log('[ttyd] setting Unicode version: 6');
                            break;
                        case 11:
                        case '11':
                        default:
                            console.log('[ttyd] setting Unicode version: 11');
                            terminal.loadAddon(new Unicode11Addon());
                            terminal.unicode.activeVersion = '11';
                            break;
                    }
                    break;
                default:
                    console.log(`[ttyd] option: ${key}=${JSON.stringify(value)}`);
                    if (terminal.options[key] instanceof Object) {
                        terminal.options[key] = Object.assign({}, terminal.options[key], value);
                    } else {
                        terminal.options[key] = value;
                    }
                    // Anything that changes the measured cell size needs a
                    // refit; the old code only covered fontSize/fontFamily and
                    // ran before the renderer had applied the new metrics.
                    if (key.indexOf('font') === 0 || key === 'lineHeight' || key === 'letterSpacing') {
                        needsFit = true;
                    }
                    break;
            }
        }
        this.syncPageBackground();
        if (needsFit) this.scheduleFit();
    }

    @bind
    private setRendererType(value: RendererType) {
        const { terminal } = this;
        const disposeCanvasRenderer = () => {
            try {
                this.canvasAddon?.dispose();
            } catch {
                // ignore
            }
            this.canvasAddon = undefined;
        };
        const disposeWebglRenderer = () => {
            try {
                this.webglAddon?.dispose();
            } catch {
                // ignore
            }
            this.webglAddon = undefined;
        };
        const enableCanvasRenderer = () => {
            if (this.canvasAddon) return;
            this.canvasAddon = new CanvasAddon();
            disposeWebglRenderer();
            try {
                this.terminal.loadAddon(this.canvasAddon);
                console.log('[ttyd] canvas renderer loaded');
                this.fitOnNextRender();
            } catch (e) {
                console.log('[ttyd] canvas renderer could not be loaded, falling back to dom renderer', e);
                disposeCanvasRenderer();
            }
        };
        const enableWebglRenderer = () => {
            if (this.webglAddon) return;
            this.webglAddon = new WebglAddon();
            disposeCanvasRenderer();
            try {
                this.webglAddon.onContextLoss(() => {
                    this.webglAddon?.dispose();
                });
                terminal.loadAddon(this.webglAddon);
                console.log('[ttyd] WebGL renderer loaded');
                this.fitOnNextRender();
            } catch (e) {
                console.log('[ttyd] WebGL renderer could not be loaded, falling back to canvas renderer', e);
                disposeWebglRenderer();
                enableCanvasRenderer();
            }
        };

        switch (value) {
            case 'canvas':
                enableCanvasRenderer();
                break;
            case 'webgl':
                enableWebglRenderer();
                break;
            case 'dom':
                disposeWebglRenderer();
                disposeCanvasRenderer();
                console.log('[ttyd] dom renderer loaded');
                break;
            default:
                break;
        }
    }
}
