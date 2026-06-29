/**
 * ipc_intercept.ts — IPC transport interception
 *
 * Hooks (platform-conditional, silently skip absent symbols):
 *   All platforms  : UNIX domain socket connect/send/recv
 *   macOS/iOS      : mach_msg
 *   Android        : Android Binder IPCThreadState::transact
 *   Linux          : D-Bus dbus_connection_send
 *
 * Emits NDJSON ipc_event records via send().
 */

"use strict";

// ─── helpers ─────────────────────────────────────────────────────────────────

function emitIpc(data: Record<string, unknown>): void {
  send(
    JSON.stringify({
      type: "ipc_event",
      pid: Process.id,
      timestamp: Date.now(),
      ...data,
    })
  );
}

function bytesToHex(ptr: NativePointer, len: number): string {
  const MAX = 256;
  const n = Math.min(len, MAX);
  try {
    const bytes = ptr.readByteArray(n);
    if (!bytes) return "";
    const arr = Array.from(new Uint8Array(bytes));
    return arr.map((b) => b.toString(16).padStart(2, "0")).join("") +
      (len > MAX ? "…" : "");
  } catch {
    return "";
  }
}

// ─── UNIX domain socket ───────────────────────────────────────────────────────
//
// sockaddr_un layout (POSIX):
//   uint16  sun_family  (offset 0, value 1 = AF_UNIX)
//   char[]  sun_path    (offset 2)

const AF_UNIX = 1;

function tryAttachUnixSocket(lib: string | null): void {
  // connect — capture the socket path when family == AF_UNIX
  try {
    const connectPtr = Module.findExportByName(lib, "connect");
    if (connectPtr) {
      Interceptor.attach(connectPtr, {
        onEnter(args) {
          try {
            const family = args[1].readU16();
            if (family === AF_UNIX) {
              this.unixPath = args[1].add(2).readUtf8String() ?? "";
            }
          } catch {
            // unreadable sockaddr — skip
          }
        },
        onLeave(retval) {
          if (this.unixPath) {
            emitIpc({
              transport: "unix_socket",
              subtype: "connect",
              path: this.unixPath,
              result: retval.toInt32(),
            });
          }
        },
      });
    }
  } catch {
    // symbol absent — skip
  }

  // send — emit hex payload for tracked UNIX sockets
  try {
    const sendPtr = Module.findExportByName(lib, "send");
    if (sendPtr) {
      Interceptor.attach(sendPtr, {
        onEnter(args) {
          // args: sockfd, buf, len, flags
          // We can't easily filter by family here without a socket table;
          // emit with a best-effort size check (only small payloads)
          const size = args[2].toUInt32();
          if (size > 0 && size <= 4096) {
            try {
              emitIpc({
                transport: "unix_socket",
                subtype: "send",
                fd: args[0].toInt32(),
                size,
                payload_hex: bytesToHex(args[1], size),
              });
            } catch {
              // unreadable buffer — skip
            }
          }
        },
      });
    }
  } catch {
    // symbol absent — skip
  }

  // recv
  try {
    const recvPtr = Module.findExportByName(lib, "recv");
    if (recvPtr) {
      Interceptor.attach(recvPtr, {
        onEnter(args) {
          this.buf = args[1];
          this.maxLen = args[2].toUInt32();
        },
        onLeave(retval) {
          const received = retval.toInt32();
          if (received > 0) {
            try {
              emitIpc({
                transport: "unix_socket",
                subtype: "recv",
                fd: -1, // fd not captured in onLeave context without extra work
                size: received,
                payload_hex: bytesToHex(this.buf as NativePointer, received),
              });
            } catch {
              // unreadable buffer — skip
            }
          }
        },
      });
    }
  } catch {
    // symbol absent — skip
  }
}

// Try libc variants across platforms
for (const lib of [null, "libc.so", "libc.so.6", "libSystem.B.dylib"]) {
  try {
    tryAttachUnixSocket(lib);
    break; // first successful module wins
  } catch {
    // try next candidate
  }
}

// ─── macOS/iOS: mach_msg ──────────────────────────────────────────────────────
//
// mach_msg_header_t layout:
//   uint32  msgh_bits           (offset 0)
//   uint32  msgh_size           (offset 4)
//   uint32  msgh_remote_port    (offset 8)
//   uint32  msgh_local_port     (offset 12)
//   uint32  msgh_voucher_port   (offset 16)
//   int32   msgh_id             (offset 20)

if (Process.platform === "darwin") {
  try {
    const machMsgPtr = Module.findExportByName("libSystem.B.dylib", "mach_msg");
    if (machMsgPtr) {
      Interceptor.attach(machMsgPtr, {
        onEnter(args) {
          // args[0] = mach_msg_header_t*, args[1] = option, args[2] = send_size, ...
          try {
            const hdr = args[0];
            const msgh_size = hdr.add(4).readU32();
            const msgh_id = hdr.add(20).readS32();
            emitIpc({
              transport: "mach_msg",
              msgh_id,
              size: msgh_size,
              option: args[1].toUInt32(),
            });
          } catch {
            // unreadable header — skip
          }
        },
      });
    }
  } catch {
    // mach_msg not available — skip
  }
}

// ─── Android: Binder IPCThreadState::transact ─────────────────────────────────
//
// Signature (arm64): transact(int32 handle, uint32 code, const Parcel& data,
//                             Parcel* reply, uint32 flags)
// Mangled: _ZN7android14IPCThreadState8transactEijPKNS_6ParcelEPS1_j

if (Process.platform === "linux") {
  try {
    const binderTransact = Module.findExportByName(
      "libbinder.so",
      "_ZN7android14IPCThreadState8transactEijPKNS_6ParcelEPS1_j"
    );
    if (binderTransact) {
      Interceptor.attach(binderTransact, {
        onEnter(args) {
          // args[0] = this, args[1] = handle, args[2] = code,
          // args[3] = data*, args[4] = reply*, args[5] = flags
          emitIpc({
            transport: "binder",
            handle: args[1].toInt32(),
            code: args[2].toUInt32(),
            flags: args[5].toUInt32(),
          });
        },
      });
    }
  } catch {
    // libbinder.so absent — skip
  }
}

// ─── Linux/Desktop: D-Bus dbus_connection_send ────────────────────────────────
//
// int dbus_connection_send(DBusConnection*, DBusMessage*, dbus_uint32_t *serial)

if (Process.platform === "linux") {
  try {
    const dbusSend = Module.findExportByName(
      "libdbus-1.so",
      "dbus_connection_send"
    );
    if (dbusSend) {
      Interceptor.attach(dbusSend, {
        onEnter(args) {
          try {
            // args[2] is a pointer to the serial output — may not be set yet on enter
            emitIpc({
              transport: "dbus",
              connection: args[0].toString(),
              message: args[1].toString(),
              // serial written by callee; read after return
            });
            this.serialPtr = args[2];
          } catch {
            // parse error — skip
          }
        },
        onLeave() {
          try {
            if (this.serialPtr && !this.serialPtr.isNull()) {
              const serial = (this.serialPtr as NativePointer).readU32();
              emitIpc({
                transport: "dbus",
                subtype: "sent",
                serial,
              });
            }
          } catch {
            // unreadable serial — skip
          }
        },
      });
    }
  } catch {
    // libdbus-1.so absent — skip
  }
}

emitIpc({ subtype: "ipc_intercept_installed" });
