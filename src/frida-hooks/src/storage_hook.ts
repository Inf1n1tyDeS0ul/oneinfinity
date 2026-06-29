/**
 * storage_hook.ts — Storage interception: SharedPreferences, SQLite, NSUserDefaults, sqlite3 native
 *
 * Covers:
 *   Android : SharedPreferences$Editor (put*), SharedPreferences (get*)
 *             SQLiteDatabase (execSQL, rawQuery, insert, update, delete)
 *   iOS     : NSUserDefaults (objectForKey:, setObject:forKey:)
 *             native sqlite3_open, sqlite3_exec, sqlite3_prepare_v2
 */

"use strict";

// ─── helpers ─────────────────────────────────────────────────────────────────

function emitEvent(hook: string, data: Record<string, unknown>): void {
  send(
    JSON.stringify({
      type: "hook_event",
      hook,
      timestamp: Date.now(),
      ...data,
    })
  );
}

function bufToHex(ptr: NativePointer, len: number): string {
  const MAX = 256;
  const n = Math.min(len, MAX);
  try {
    const bytes = ptr.readByteArray(n);
    if (!bytes) return "";
    const arr = Array.from(new Uint8Array(bytes));
    return arr.map((b) => b.toString(16).padStart(2, "0")).join("") + (len > MAX ? "…" : "");
  } catch {
    return "";
  }
}

function readCStr(ptr: NativePointer): string {
  try {
    if (ptr.isNull()) return "";
    return ptr.readCString() ?? "";
  } catch {
    return "";
  }
}

// ─── Android: SharedPreferences & SQLite ─────────────────────────────────────

if (typeof Java !== "undefined" && Java.available) {
  Java.perform(() => {

    // ── SharedPreferences$Editor — put operations ──────────────────────────
    try {
      const Editor = Java.use("android.content.SharedPreferences$Editor");

      const putStringOrig = Editor.putString.implementation;
      Editor.putString.implementation = function (key: string, value: string) {
        try {
          emitEvent("storage", {
            platform: "android",
            api: "SharedPreferences.Editor",
            method: "putString",
            key,
            value: value !== null ? String(value).substring(0, 200) : null,
          });
        } catch (e) { console.warn("[storage_hook] putString emit failed:", e); }
        return this.putString(key, value);
      };

      Editor.putInt.implementation = function (key: string, value: number) {
        try {
          emitEvent("storage", { platform: "android", api: "SharedPreferences.Editor", method: "putInt", key, value });
        } catch (e) { console.warn("[storage_hook] putInt emit failed:", e); }
        return this.putInt(key, value);
      };

      Editor.putBoolean.implementation = function (key: string, value: boolean) {
        try {
          emitEvent("storage", { platform: "android", api: "SharedPreferences.Editor", method: "putBoolean", key, value });
        } catch (e) { console.warn("[storage_hook] putBoolean emit failed:", e); }
        return this.putBoolean(key, value);
      };

      Editor.putFloat.implementation = function (key: string, value: number) {
        try {
          emitEvent("storage", { platform: "android", api: "SharedPreferences.Editor", method: "putFloat", key, value });
        } catch (e) { console.warn("[storage_hook] putFloat emit failed:", e); }
        return this.putFloat(key, value);
      };

      Editor.putLong.implementation = function (key: string, value: number) {
        try {
          emitEvent("storage", { platform: "android", api: "SharedPreferences.Editor", method: "putLong", key, value });
        } catch (e) { console.warn("[storage_hook] putLong emit failed:", e); }
        return this.putLong(key, value);
      };

      console.log("[storage_hook] SharedPreferences$Editor hooked.");
    } catch (e) {
      console.warn("[storage_hook] SharedPreferences$Editor hook failed:", e);
    }

    // ── SharedPreferences — get operations ────────────────────────────────
    try {
      // SharedPreferences is an interface; hook via SharedPreferencesImpl
      const SP = Java.use("android.app.SharedPreferencesImpl");

      SP.getString.implementation = function (key: string, defValue: string) {
        const result = this.getString(key, defValue);
        try {
          emitEvent("storage", {
            platform: "android",
            api: "SharedPreferences",
            method: "getString",
            key,
            value: result !== null ? String(result).substring(0, 200) : null,
          });
        } catch (e) { console.warn("[storage_hook] getString emit failed:", e); }
        return result;
      };

      SP.getInt.implementation = function (key: string, defValue: number) {
        const result = this.getInt(key, defValue);
        try {
          emitEvent("storage", { platform: "android", api: "SharedPreferences", method: "getInt", key, value: result });
        } catch (e) { console.warn("[storage_hook] getInt emit failed:", e); }
        return result;
      };

      SP.getBoolean.implementation = function (key: string, defValue: boolean) {
        const result = this.getBoolean(key, defValue);
        try {
          emitEvent("storage", { platform: "android", api: "SharedPreferences", method: "getBoolean", key, value: result });
        } catch (e) { console.warn("[storage_hook] getBoolean emit failed:", e); }
        return result;
      };

      console.log("[storage_hook] SharedPreferencesImpl get* hooked.");
    } catch (e) {
      console.warn("[storage_hook] SharedPreferencesImpl hook failed (interface — skipping):", e);
    }

    // ── SQLiteDatabase ────────────────────────────────────────────────────
    try {
      const SQLiteDB = Java.use("android.database.sqlite.SQLiteDatabase");

      SQLiteDB.execSQL.overload("java.lang.String").implementation = function (sql: string) {
        try {
          emitEvent("storage", { platform: "android", api: "SQLiteDatabase", method: "execSQL", query: sql.substring(0, 500) });
        } catch (e) { console.warn("[storage_hook] execSQL emit failed:", e); }
        return this.execSQL(sql);
      };

      SQLiteDB.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (
        sql: string,
        selArgs: string[]
      ) {
        try {
          emitEvent("storage", {
            platform: "android",
            api: "SQLiteDatabase",
            method: "rawQuery",
            query: sql.substring(0, 500),
            args: selArgs ? JSON.stringify(selArgs) : null,
          });
        } catch (e) { console.warn("[storage_hook] rawQuery emit failed:", e); }
        return this.rawQuery(sql, selArgs);
      };

      SQLiteDB.insert.implementation = function (table: string, nullColumnHack: string, values: unknown) {
        try {
          emitEvent("storage", {
            platform: "android",
            api: "SQLiteDatabase",
            method: "insert",
            query: `INSERT INTO ${table}`,
            key: table,
          });
        } catch (e) { console.warn("[storage_hook] insert emit failed:", e); }
        return this.insert(table, nullColumnHack, values);
      };

      SQLiteDB.update.implementation = function (
        table: string,
        values: unknown,
        whereClause: string,
        whereArgs: string[]
      ) {
        try {
          emitEvent("storage", {
            platform: "android",
            api: "SQLiteDatabase",
            method: "update",
            query: `UPDATE ${table} WHERE ${whereClause}`,
            key: table,
          });
        } catch (e) { console.warn("[storage_hook] update emit failed:", e); }
        return this.update(table, values, whereClause, whereArgs);
      };

      SQLiteDB["delete"].implementation = function (table: string, whereClause: string, whereArgs: string[]) {
        try {
          emitEvent("storage", {
            platform: "android",
            api: "SQLiteDatabase",
            method: "delete",
            query: `DELETE FROM ${table} WHERE ${whereClause}`,
            key: table,
          });
        } catch (e) { console.warn("[storage_hook] delete emit failed:", e); }
        return this["delete"](table, whereClause, whereArgs);
      };

      console.log("[storage_hook] SQLiteDatabase hooked.");
    } catch (e) {
      console.warn("[storage_hook] SQLiteDatabase hook failed:", e);
    }

  });
}

// ─── iOS: NSUserDefaults (ObjC) ──────────────────────────────────────────────

if (typeof ObjC !== "undefined" && ObjC.available) {
  try {
    const NSUserDefaults = ObjC.classes.NSUserDefaults;
    if (NSUserDefaults) {
      // objectForKey:
      const objectForKey = NSUserDefaults["- objectForKey:"];
      if (objectForKey) {
        Interceptor.attach(objectForKey.implementation, {
          onEnter(args) {
            try {
              const key = new ObjC.Object(args[2]).toString();
              (this as Record<string, unknown>)["_key"] = key;
            } catch { /* ignore */ }
          },
          onLeave(retval) {
            try {
              const key = (this as Record<string, unknown>)["_key"] as string | undefined;
              let value: string | null = null;
              if (!retval.isNull()) {
                try { value = new ObjC.Object(retval).toString().substring(0, 200); } catch { /* ignore */ }
              }
              emitEvent("storage", {
                platform: "ios",
                api: "NSUserDefaults",
                method: "objectForKey:",
                key,
                value,
              });
            } catch (e) { console.warn("[storage_hook] NSUserDefaults objectForKey: emit failed:", e); }
          },
        });
      }

      // setObject:forKey:
      const setObjectForKey = NSUserDefaults["- setObject:forKey:"];
      if (setObjectForKey) {
        Interceptor.attach(setObjectForKey.implementation, {
          onEnter(args) {
            try {
              const value = args[2].isNull() ? null : new ObjC.Object(args[2]).toString().substring(0, 200);
              const key = new ObjC.Object(args[3]).toString();
              emitEvent("storage", {
                platform: "ios",
                api: "NSUserDefaults",
                method: "setObject:forKey:",
                key,
                value,
              });
            } catch (e) { console.warn("[storage_hook] NSUserDefaults setObject:forKey: emit failed:", e); }
          },
        });
      }

      console.log("[storage_hook] NSUserDefaults hooked.");
    }
  } catch (e) {
    console.warn("[storage_hook] NSUserDefaults hook failed:", e);
  }
}

// ─── Native sqlite3 (iOS and Android NDK) ────────────────────────────────────

// sqlite3_open(filename, ppDb)
(function hookSqlite3Open(): void {
  const fn = Module.findExportByName(null, "sqlite3_open");
  if (!fn) return;
  try {
    Interceptor.attach(fn, {
      onEnter(args) {
        try {
          const filename = readCStr(args[0]);
          emitEvent("storage", {
            platform: "native",
            api: "sqlite3",
            method: "sqlite3_open",
            query: filename,
          });
        } catch (e) { console.warn("[storage_hook] sqlite3_open emit failed:", e); }
      },
    });
    console.log("[storage_hook] sqlite3_open hooked.");
  } catch (e) {
    console.warn("[storage_hook] sqlite3_open attach failed:", e);
  }
})();

// sqlite3_exec(db, sql, callback, arg, errmsg)
(function hookSqlite3Exec(): void {
  const fn = Module.findExportByName(null, "sqlite3_exec");
  if (!fn) return;
  try {
    Interceptor.attach(fn, {
      onEnter(args) {
        try {
          const sql = readCStr(args[1]);
          emitEvent("storage", {
            platform: "native",
            api: "sqlite3",
            method: "sqlite3_exec",
            query: sql.substring(0, 500),
          });
        } catch (e) { console.warn("[storage_hook] sqlite3_exec emit failed:", e); }
      },
    });
    console.log("[storage_hook] sqlite3_exec hooked.");
  } catch (e) {
    console.warn("[storage_hook] sqlite3_exec attach failed:", e);
  }
})();

// sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail)
(function hookSqlite3PrepareV2(): void {
  const fn = Module.findExportByName(null, "sqlite3_prepare_v2");
  if (!fn) return;
  try {
    Interceptor.attach(fn, {
      onEnter(args) {
        try {
          const sql = readCStr(args[1]);
          emitEvent("storage", {
            platform: "native",
            api: "sqlite3",
            method: "sqlite3_prepare_v2",
            query: sql.substring(0, 500),
          });
        } catch (e) { console.warn("[storage_hook] sqlite3_prepare_v2 emit failed:", e); }
      },
    });
    console.log("[storage_hook] sqlite3_prepare_v2 hooked.");
  } catch (e) {
    console.warn("[storage_hook] sqlite3_prepare_v2 attach failed:", e);
  }
})();

emitEvent("storage", { event: "storage_hook_installed", pid: Process.id });
