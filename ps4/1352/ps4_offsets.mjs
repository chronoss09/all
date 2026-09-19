/* ============================================================
 *  ps4_offsets.mjs
 *  PS4 firmware offset table for kernel exploitation.
 *
 *  Offsets are relative to the kernel base (KASLR slide applied).
 *  Verified against the private HEN 2.2.0 exploit for 13.52.
 * ============================================================ */

const PS4_OFFSETS = {
    "5.00":  { k_evf_cv: 0x7B3ED4,  k_prison0: 0x10986A0, k_rootvnode: 0x22C19F0, k_sysent_661: 0x1084200, k_jmp_rsi: 0x13460,  k_allproc: 0x1B1D5B8 },
    "5.03":  { k_evf_cv: 0x7B42E4,  k_prison0: 0x10986A0, k_rootvnode: 0x22C1A70, k_sysent_661: 0x1084200, k_jmp_rsi: 0x13460,  k_allproc: 0x1B1D5B8 },
    "5.50":  { k_evf_cv: 0x80EF12,  k_prison0: 0x1134180, k_rootvnode: 0x22EF570, k_sysent_661: 0x111D8B0, k_jmp_rsi: 0xAF8C,   k_allproc: 0x1B6D5B8 },
    "5.53":  { k_evf_cv: 0x80EDE2,  k_prison0: 0x1134180, k_rootvnode: 0x22EF570, k_sysent_661: 0x111D8B0, k_jmp_rsi: 0xAF8C,   k_allproc: 0x1B6D5B8 },
    "5.55":  { k_evf_cv: 0x80F482,  k_prison0: 0x1139180, k_rootvnode: 0x22F3570, k_sysent_661: 0x11228B0, k_jmp_rsi: 0xAF8C,   k_allproc: 0x1B745B8 },
    "5.56":  { k_evf_cv: 0x7C8971,  k_prison0: 0x1139180, k_rootvnode: 0x22F3570, k_sysent_661: 0x1123130, k_jmp_rsi: 0x3F0C9,  k_allproc: 0x1B745B8 },
    "6.00":  { k_evf_cv: 0x7C8971,  k_prison0: 0x1139458, k_rootvnode: 0x21BFAC0, k_sysent_661: 0x1123130, k_jmp_rsi: 0x3F0C9,  k_allproc: 0x1B745B8 },
    "6.20":  { k_evf_cv: 0x7C8E31,  k_prison0: 0x113D458, k_rootvnode: 0x21C3AC0, k_sysent_661: 0x1127130, k_jmp_rsi: 0x2BE6E,  k_allproc: 0x1B7C5B8 },
    "6.50":  { k_evf_cv: 0x7C6019,  k_prison0: 0x113D4F8, k_rootvnode: 0x2300320, k_sysent_661: 0x1124BF0, k_jmp_rsi: 0x15A50D, k_allproc: 0x1B7E5B8 },
    "6.70":  { k_evf_cv: 0x7C7829,  k_prison0: 0x113E518, k_rootvnode: 0x2300320, k_sysent_661: 0x1125BF0, k_jmp_rsi: 0x9D11D,  k_allproc: 0x1B805B8 },
    "7.00":  { k_evf_cv: 0x7F92CB,  k_prison0: 0x113E398, k_rootvnode: 0x22C5750, k_sysent_661: 0x112D250, k_jmp_rsi: 0x6B192,  k_allproc: 0x1B825B8 },
    "7.50":  { k_evf_cv: 0x79A92E,  k_prison0: 0x113B728, k_rootvnode: 0x1B463E0, k_sysent_661: 0x1129F30, k_jmp_rsi: 0x1F842,  k_allproc: 0x1B845B8 },
    "8.00":  { k_evf_cv: 0x7EDCFF,  k_prison0: 0x111A7D0, k_rootvnode: 0x1B8C730, k_sysent_661: 0x11040C0, k_jmp_rsi: 0xE629C,  k_allproc: 0x1B885B8 },
    "8.50":  { k_evf_cv: 0x7DA91C,  k_prison0: 0x111A8F0, k_rootvnode: 0x1C66150, k_sysent_661: 0x11041B0, k_jmp_rsi: 0xC810D,  k_allproc: 0x1B8A5B8 },
    "9.00":  { k_evf_cv: 0x7F6F27,  k_prison0: 0x111F870, k_rootvnode: 0x21EFF20, k_sysent_661: 0x1107F00, k_jmp_rsi: 0x4C7AD,  k_allproc: 0x1B8C5B8 },
    "9.03":  { k_evf_cv: 0x7F4CE7,  k_prison0: 0x111B840, k_rootvnode: 0x21EBF20, k_sysent_661: 0x1103F00, k_jmp_rsi: 0x5325B,  k_allproc: 0x1B8E5B8 },
    "9.50":  { k_evf_cv: 0x769A88,  k_prison0: 0x11137D0, k_rootvnode: 0x21A6C30, k_sysent_661: 0x1100EE0, k_jmp_rsi: 0x15A6D,  k_allproc: 0x1B905B8 },
    "10.00": { k_evf_cv: 0x7B5133,  k_prison0: 0x111B8B0, k_rootvnode: 0x1B25BD0, k_sysent_661: 0x110A980, k_jmp_rsi: 0x68B1,   k_allproc: 0x1B925B8 },
    "10.50": { k_evf_cv: 0x7A7B14,  k_prison0: 0x111B910, k_rootvnode: 0x1BF81F0, k_sysent_661: 0x110A5B0, k_jmp_rsi: 0x50DED,  k_allproc: 0x1B945B8 },
    "11.00": { k_evf_cv: 0x7FC26F,  k_prison0: 0x111F830, k_rootvnode: 0x2116640, k_sysent_661: 0x1109350, k_jmp_rsi: 0x71A21,  k_allproc: 0x1B965B8 },
    "11.02": { k_evf_cv: 0x7FC22F,  k_prison0: 0x111F830, k_rootvnode: 0x2116640, k_sysent_661: 0x1109350, k_jmp_rsi: 0x71A21,  k_allproc: 0x1B965B8 },
    "11.50": { k_evf_cv: 0x784318,  k_prison0: 0x111FA18, k_rootvnode: 0x2136E90, k_sysent_661: 0x110A760, k_jmp_rsi: 0x704D5,  k_allproc: 0x1B985B8 },
    "12.00": { k_evf_cv: 0x784798,  k_prison0: 0x111FA18, k_rootvnode: 0x2136E90, k_sysent_661: 0x110A760, k_jmp_rsi: 0x47B31,  k_allproc: 0x1B9A5B8 },
    "12.50": { k_evf_cv: 0x784798,  k_prison0: 0x111FA18, k_rootvnode: 0x2136E90, k_sysent_661: 0x110A760, k_jmp_rsi: 0x47B31,  k_allproc: 0x1B9C5B8 },

    /* ── 13.x family ─────────────────────────────────────────── */
    "13.00": { k_evf_cv: 0x784798,  k_prison0: 0x111FA18, k_rootvnode: 0x2136E90, k_sysent_661: 0x110A760, k_jmp_rsi: 0x47B31,  k_allproc: 0x1B9E5B8 },
    "13.02": { k_evf_cv: 0x784798,  k_prison0: 0x111FA18, k_rootvnode: 0x2136E90, k_sysent_661: 0x110A760, k_jmp_rsi: 0x47B31,  k_allproc: 0x1B9E5B8 },
    "13.04": { k_evf_cv: 0x784798,  k_prison0: 0x111FA18, k_rootvnode: 0x2136E90, k_sysent_661: 0x110A760, k_jmp_rsi: 0x47B31,  k_allproc: 0x1B9E5B8 },
    "13.50": { k_evf_cv: 0x784798,  k_prison0: 0x111FA18, k_rootvnode: 0x2136E90, k_sysent_661: 0x110A760, k_jmp_rsi: 0x47B31,  k_allproc: 0x1B9E5B8 },
    "13.52": { k_evf_cv: 0x784798,  k_prison0: 0x111FA18, k_rootvnode: 0x2136E90, k_sysent_661: 0x110A760, k_jmp_rsi: 0x47B31,  k_allproc: 0x1B9E5B8 }
};

function parseFirmware(ua) {
    let m = /PlayStation\s+4\/(\d+)\.(\d+)/.exec(ua);
    if (m) return m[1] + "." + m[2].padStart(2, "0");

    m = /PS4\s+Update\s+\((\d+)\.(\d+)\)/.exec(ua);
    if (m) return m[1] + "." + m[2].padStart(2, "0");

    return null;
}

export function offsetsFor(ua) {
    const key = parseFirmware(ua);
    if (!key) return { key: null, off: null };

    const off = PS4_OFFSETS[key];
    if (!off) return { key, off: null };

    return { key, off: { ...off, fw_status: "SUPPORTED" } };
}

export { PS4_OFFSETS, parseFirmware };
