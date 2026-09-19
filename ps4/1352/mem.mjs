/* ============================================================
 *  mem.mjs — Memory access layer for the PS4 WebKit exploit.
 * ============================================================ */

import { int64 } from "./int64.mjs";

let _carrier = null;
let _initialized = false;

export function installWindowP(carrier) {
    if (!carrier) throw new Error("installWindowP: no carrier");
    _carrier = carrier;

    function toInt64(v) {
        if (v instanceof int64) return v;
        if (typeof v === "bigint") return int64.fromBigInt(v);
        if (typeof v === "number")
            return new int64(v >>> 0, Math.floor(v / 0x100000000) >>> 0);
        if (v && typeof v === "object" && "lo" in v && "hi" in v)
            return new int64(v.lo, v.hi);
        throw new TypeError("cannot convert to int64: " + v);
    }

    function fromInt64(v) {
        if (typeof v === "bigint") return v;
        if (v instanceof int64) return v.toBigInt();
        if (typeof v === "number") return BigInt(v);
        if (v && typeof v === "object" && "lo" in v && "hi" in v)
            return (BigInt(v.hi) << 32n) | BigInt(v.lo);
        return 0n;
    }

    function read64(addr) {
        const a = toInt64(addr);
        return toInt64(_carrier.read64(a.toBigInt()));
    }

    function write64(addr, value) {
        const a = toInt64(addr);
        _carrier.write64(a.toBigInt(), fromInt64(value));
    }

    function read8(addr) {
        const a = toInt64(addr);
        const aligned = a.and32(0xFFFFFFF8);
        const shift = (a.lo & 7) * 8;
        const q = read64(aligned);
        if (shift < 32) return (q.lo >>> shift) & 0xff;
        return (q.hi >>> (shift - 32)) & 0xff;
    }

    function write8(addr, byte) {
        const a = toInt64(addr);
        const aligned = a.and32(0xFFFFFFF8);
        const shift = (a.lo & 7) * 8;
        const q = read64(aligned);
        const b = byte & 0xff;
        if (shift < 32) {
            const mask = (0xff << shift) >>> 0;
            const newLo = ((q.lo & ~mask) | (b << shift)) >>> 0;
            write64(aligned, new int64(newLo, q.hi));
        } else {
            const hiShift = shift - 32;
            const mask = (0xff << hiShift) >>> 0;
            const newHi = ((q.hi & ~mask) | (b << hiShift)) >>> 0;
            write64(aligned, new int64(q.lo, newHi));
        }
    }

    function read32(addr) {
        const a = toInt64(addr);
        const q = read64(a.and32(0xFFFFFFFC));
        const shift = (a.lo & 3) * 8;
        if (shift === 0)  return q.lo;
        if (shift === 8)  return (q.lo >>> 8)  | ((q.hi & 0xff)   << 24);
        if (shift === 16) return (q.lo >>> 16) | ((q.hi & 0xffff) << 16);
        return (q.lo >>> 24) | ((q.hi & 0xffffff) << 8);
    }

    function write32(addr, value) {
        const a = toInt64(addr);
        if ((a.lo & 3) === 0) {
            write64(a, new int64(value >>> 0, 0));
            return;
        }
        const aligned = a.and32(0xFFFFFFFC);
        const q = read64(aligned);
        const shift = (a.lo & 3) * 8;
        const mask = (0xffffffff << shift) >>> 0;
        const newLo = ((q.lo & ~mask) | ((value << shift) >>> 0)) >>> 0;
        write64(aligned, new int64(newLo, q.hi));
    }

    function addrof(obj) { return toInt64(_carrier.addrof(obj)); }
    function fakeobj(addr) { return _carrier.fakeobj(toInt64(addr).toBigInt()); }

    function syscall(nr, a, b, c, d, e) {
        if (typeof _carrier.syscall === "function")
            return _carrier.syscall(nr, a, b, c, d, e);
        return -1;
    }

    function readBytes(addr, len) {
        const out = new Uint8Array(len);
        const a = toInt64(addr);
        for (let i = 0; i < len; i += 8) {
            const q = read64(a.add32(i)).toBigInt();
            const n = Math.min(8, len - i);
            for (let j = 0; j < n; j++)
                out[i + j] = Number((q >> BigInt(j * 8)) & 0xffn);
        }
        return out;
    }

    function writeBytes(addr, bytes) {
        const a = toInt64(addr);
        for (let i = 0; i < bytes.length; i += 8) {
            let q = 0n;
            const n = Math.min(8, bytes.length - i);
            for (let j = 0; j < n; j++)
                q |= BigInt(bytes[i + j]) << BigInt(j * 8);
            write64(a.add32(i), q);
        }
    }

    window.p = {
        read64, write64, read32, write32, read8, write8,
        addrof, fakeobj, syscall,
        readBytes, writeBytes,
        _carrier
    };

    _initialized = true;
    return window.p;
}

export function isInstalled() {
    return _initialized && typeof window.p !== "undefined";
}

export { int64 };
