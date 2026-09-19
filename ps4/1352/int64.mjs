/* ============================================================
 *  int64.mjs
 *  64-bit unsigned integer represented as two 32-bit words.
 * ============================================================ */

export class int64 {
    constructor(lo, hi) {
        this.lo = lo >>> 0;
        this.hi = hi >>> 0;
    }

    static fromBigInt(v) {
        const mask = 0xFFFFFFFFn;
        return new int64(Number(v & mask), Number((v >> 32n) & mask));
    }

    static fromWords(lo, hi) { return new int64(lo, hi); }

    static fromBytes(bytes, off) {
        let lo = 0, hi = 0;
        for (let i = 0; i < 4; i++) lo |= bytes[off + i] << (i * 8);
        for (let i = 0; i < 4; i++) hi |= bytes[off + 4 + i] << (i * 8);
        return new int64(lo >>> 0, hi >>> 0);
    }

    toBigInt() { return (BigInt(this.hi) << 32n) | BigInt(this.lo); }

    writeTo(bytes, off) {
        for (let i = 0; i < 4; i++) bytes[off + i] = (this.lo >>> (i * 8)) & 0xff;
        for (let i = 0; i < 4; i++) bytes[off + 4 + i] = (this.hi >>> (i * 8)) & 0xff;
    }

    add32(n) {
        const sum = this.lo + n;
        const lo = sum >>> 0;
        const carry = sum > 0xFFFFFFFF ? 1 : 0;
        const signedCarry = (n < 0 && lo > this.lo) ? -1 : 0;
        return new int64(lo, (this.hi + carry + signedCarry) >>> 0);
    }

    sub32(n) { return this.add32(-n); }

    add(o) {
        const sum = this.lo + o.lo;
        const carry = sum > 0xFFFFFFFF ? 1 : 0;
        return new int64(sum >>> 0, (this.hi + o.hi + carry) >>> 0);
    }

    sub(o) {
        const borrow = this.lo < o.lo ? 1 : 0;
        return new int64((this.lo - o.lo) >>> 0,
                         (this.hi - o.hi - borrow) >>> 0);
    }

    and32(mask) { return new int64(this.lo & mask, this.hi & mask); }
    or32(mask)  { return new int64(this.lo | mask, this.hi | mask); }

    shl(n) {
        if (n >= 32) return new int64(0, this.lo << (n - 32));
        if (n === 0) return new int64(this.lo, this.hi);
        return new int64(this.lo << n,
                        (this.hi << n) | (this.lo >>> (32 - n)));
    }

    shr(n) {
        if (n >= 32) return new int64(this.hi >>> (n - 32), 0);
        if (n === 0) return new int64(this.lo, this.hi);
        return new int64((this.lo >>> n) | (this.hi << (32 - n)),
                         this.hi >>> n);
    }

    lt(o)  { return this.hi < o.hi || (this.hi === o.hi && this.lo < o.lo); }
    lte(o) { return this.lt(o) || this.eq(o); }
    gt(o)  { return !this.lte(o); }
    gte(o) { return !this.lt(o); }
    eq(o)  { return this.lo === o.lo && this.hi === o.hi; }
    isZero() { return this.lo === 0 && this.hi === 0; }

    toString() {
        return "0x" + this.toBigInt().toString(16).padStart(16, "0");
    }
    toJSON() { return this.toString(); }
}

export const ZERO = new int64(0, 0);
export const ONE  = new int64(1, 0);
