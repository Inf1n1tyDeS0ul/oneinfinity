'use strict';

/**
 * SSL_read / SSL_write native hook — OneInfinity Layer 2
 *
 * Hooks SSL_write (plaintext BEFORE encryption) and SSL_read (plaintext AFTER
 * decryption) across ALL loaded SSL libraries including:
 *   - /system/lib64/libssl.so  (Android system BoringSSL)
 *   - libcronet.so             (Chrome, Google apps)
 *   - libflutter.so            (Flutter apps)
 *   - Any bundled libssl*.so   (React Native, Xamarin, etc.)
 *
 * Also exports SSLKEYLOGFILE lines for offline Wireshark decryption.
 *
 * Interactive modification: when OI_INTERCEPT=1, SSL_write hooks emit
 * ssl_write_intercept and spin-wait for a resume signal written to a
 * shared memory cell — backend calls breakpoint_resume to unblock.
 *
 * Usage:
 *   frida -U -f <package> -l ssl_read_write_hook.js --no-pause
 *   frida -U --attach-name <package> -l ssl_read_write_hook.js
 */

var INTERCEPT_MODE = false;  // set via send({type:'set_intercept', enabled:true})
var MAX_BUF = 65536;

// Per-SSL* context: connId -> {host, pending requests}
var _connMeta = {};

// Intercept: per-call intercept_id -> Memory cell for spin-wait
var _interceptCells = {};

function emit(tag, data) {
    try {
        console.log('[FRIDA_FINDING] ' + JSON.stringify({ tag: tag, data: data, ts: new Date().toISOString() }));
    } catch(e) {}
}

function bufToStr(ptr, len) {
    try {
        var bytes = Memory.readByteArray(ptr, Math.min(len, MAX_BUF));
        if (!bytes) return '';
        var arr = new Uint8Array(bytes);
        var str = '';
        for (var i = 0; i < arr.length; i++) {
            if (arr[i] >= 32 && arr[i] < 127) {
                str += String.fromCharCode(arr[i]);
            } else {
                str += '\\x' + ('00' + arr[i].toString(16)).slice(-2);
            }
        }
        return str;
    } catch(e) { return ''; }
}

function isHttpData(ptr, len) {
    if (len < 4) return false;
    try {
        var head = Memory.readUtf8String(ptr, Math.min(len, 16));
        return /^(GET |POST |PUT |DELETE |PATCH |HEAD |OPTIONS |HTTP\/|PRI \*)/.test(head);
    } catch(e) { return false; }
}

// ── SSL_write hook ────────────────────────────────────────────────────────────

var ssl_write_handler = {
    onEnter: function(args) {
        this.ssl = args[0];
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.callId = Math.random().toString(36).slice(2);
    },
    onLeave: function(retval) {
        if (this.len <= 0 || this.len > MAX_BUF) return;

        var data = bufToStr(this.buf, this.len);
        if (!data) return;

        if (INTERCEPT_MODE && isHttpData(this.buf, this.len)) {
            // Suspend: allocate a cell, spin-wait
            var cell = Memory.alloc(8);
            Memory.writeInt(cell, 0);  // 0 = waiting, 1 = resume-unchanged, 2 = resume-modified
            _interceptCells[this.callId] = { cell: cell, buf: this.buf, len: this.len };

            emit('ssl_write_intercept', {
                call_id: this.callId,
                data: data,
                len: this.len,
            });

            // Spin-wait (max 120s = 12,000,000 iterations at ~10µs each)
            var deadline = Date.now() + 120000;
            while (Memory.readInt(cell) === 0 && Date.now() < deadline) {
                Thread.sleep(0.01);
            }

            var signal = Memory.readInt(cell);
            if (signal === 2) {
                // Modified bytes were written to cell+4 pointer
                // (backend writes modified length as int at cell+4)
                // For simplicity: modified content is base64 decoded and
                // written back to this.buf by the backend via a temp file approach.
                // (Full implementation: read modified bytes from a named pipe)
            }

            delete _interceptCells[this.callId];
        } else {
            emit('ssl_write', { data: data, len: this.len, call_id: this.callId });
        }
    }
};

// ── SSL_read hook ─────────────────────────────────────────────────────────────

var ssl_read_handler = {
    onEnter: function(args) {
        this.ssl = args[0];
        this.buf = args[1];
        this.maxLen = args[2].toInt32();
    },
    onLeave: function(retval) {
        var len = retval.toInt32();
        if (len <= 0 || len > MAX_BUF) return;

        var data = bufToStr(this.buf, len);
        if (data) {
            emit('ssl_read', { data: data, len: len });
        }
    }
};

// ── SSLKEYLOGFILE export ──────────────────────────────────────────────────────

function hookKeylogCallback(modName) {
    try {
        var fn = Module.findExportByName(modName, 'SSL_CTX_set_keylog_callback');
        if (!fn) return;
        var SSL_CTX_set_keylog_callback = new NativeFunction(fn, 'void', ['pointer', 'pointer']);
        var cb = new NativeCallback(function(ssl, line) {
            try {
                emit('keylog', { line: Memory.readUtf8String(line) });
            } catch(e) {}
        }, 'void', ['pointer', 'pointer']);
        // Get the default SSL_CTX — hook after app creates its contexts
        // by attaching to SSL_CTX_new
        var ctxNew = Module.findExportByName(modName, 'SSL_CTX_new');
        if (ctxNew) {
            Interceptor.attach(ctxNew, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        SSL_CTX_set_keylog_callback(retval, cb);
                    }
                }
            });
        }
    } catch(e) {}
}

// ── Multi-library scan ────────────────────────────────────────────────────────

var hooked = {};

function hookModule(m) {
    if (hooked[m.name]) return;

    var hasW = Module.findExportByName(m.name, 'SSL_write');
    var hasR = Module.findExportByName(m.name, 'SSL_read');

    if (hasW || hasR) {
        hooked[m.name] = true;
        console.log('[SSL-Hook] Attaching to ' + m.name);

        if (hasW) {
            try { Interceptor.attach(hasW, ssl_write_handler); } catch(e) {
                console.log('[SSL-Hook] SSL_write attach failed in ' + m.name + ': ' + e.message);
            }
        }
        if (hasR) {
            try { Interceptor.attach(hasR, ssl_read_handler); } catch(e) {
                console.log('[SSL-Hook] SSL_read attach failed in ' + m.name + ': ' + e.message);
            }
        }
        hookKeylogCallback(m.name);
    }
}

// Hook already-loaded modules
Process.enumerateModules().forEach(hookModule);

// Hook modules loaded after script injection (dlopen)
var dlopen = Module.findExportByName(null, 'dlopen') ||
             Module.findExportByName(null, 'android_dlopen_ext');
if (dlopen) {
    Interceptor.attach(dlopen, {
        onLeave: function(retval) {
            if (!retval.isNull()) {
                // Re-scan after new library is loaded
                setTimeout(function() {
                    Process.enumerateModules().forEach(hookModule);
                }, 200);
            }
        }
    });
}

// ── Control channel ───────────────────────────────────────────────────────────

recv(function(message) {
    if (message.type === 'set_intercept') {
        INTERCEPT_MODE = message.enabled;
        emit('control_ack', { intercept: INTERCEPT_MODE });
    } else if (message.type === 'resume') {
        var callId = message.call_id;
        var cell = _interceptCells[callId];
        if (cell) {
            Memory.writeInt(cell.cell, message.modified ? 2 : 1);
        }
    }
});

console.log('[SSL-Hook] Loaded. Monitoring ' + Object.keys(hooked).length + ' SSL libraries.');
emit('hook_loaded', { modules: Object.keys(hooked), intercept: INTERCEPT_MODE });
