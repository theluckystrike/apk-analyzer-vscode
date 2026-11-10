'use strict';
// Signing: the APK Signing Block (v2, v3, v3.1 schemes) found by its magic right before the central directory,
// the v1 (JAR) signature files in META-INF, and the signer certificate: its SHA-256 and SHA-1, subject, issuer and
// validity, read with a small bounded DER walker from the PKCS#7 file or from the v2/v3 block. Nothing is verified:
// the tool shows what is there; it does not check the signature.
const crypto = require('crypto');

const MAGIC = 'APK Sig Block 42';
const IDS = {
  0x7109871a: 'v2 (APK Signature Scheme v2)',
  0xf05368c0: 'v3 (APK Signature Scheme v3)',
  0x1b93ad61: 'v3.1 (APK Signature Scheme v3.1)',
  0x42726577: 'padding',
  0x6dff800d: 'source stamp',
  0x2146444e: 'Google Play metadata',
  0x504b4453: 'dependency info (encrypted, Google Play)',
};
const hex = (n) => '0x' + (n >>> 0).toString(16).padStart(8, '0');

/** Finds the APK Signing Block before cdOffset. Returns null, or { offset, size, pairs: [{ id, name, size, valueOff }] }. */
function readSigningBlock(src, cdOffset) {
  if (cdOffset < 32) return null;
  const foot = src.bytesUpTo(cdOffset - 24, 24);
  if (foot.length < 24 || String.fromCharCode(...foot.subarray(8, 24)) !== MAGIC) return null;
  const dv = new DataView(foot.buffer, foot.byteOffset, 24);
  const size = dv.getUint32(0, true) + dv.getUint32(4, true) * 0x100000000;
  const start = cdOffset - size - 8;
  const out = { offset: start, size: size + 8, pairs: [], problems: [] };
  if (size < 24 || start < 0) { out.problems.push('The APK Signing Block has an impossible size.'); return out; }
  const pairsEnd = cdOffset - 24;
  let p = start + 8, n = 0;
  while (p + 12 <= pairsEnd && n++ < 256) {
    const h = src.bytes(p, 12);
    const v = new DataView(h.buffer, h.byteOffset, 12);
    const len = v.getUint32(0, true) + v.getUint32(4, true) * 0x100000000;
    if (len < 4 || p + 8 + len > pairsEnd) { out.problems.push('A pair in the APK Signing Block runs past the block; the rest was not read.'); break; }
    const id = v.getUint32(8, true);
    out.pairs.push({ id, name: IDS[id] || `block ${hex(id)}`, size: len - 4, valueOff: p + 12 });
    p += 8 + len;
  }
  return out;
}

// ---------- DER ----------

/** One DER TLV at p (bounded by end): { tag, start, hdr, len, end }. */
function tlv(b, p, end) {
  if (p + 2 > end) throw new RangeError('DER past the end');
  const tag = b[p];
  let len = b[p + 1], hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + 2 + n > end) throw new RangeError('bad DER length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p + 2 + i];
    hdr += n;
  }
  if (p + hdr + len > end) throw new RangeError('DER item past the end');
  return { tag, start: p, hdr, len, body: p + hdr, end: p + hdr + len };
}
function kids(b, t) {
  const out = [];
  for (let p = t.body; p < t.end && out.length < 4096;) { const k = tlv(b, p, t.end); out.push(k); p = k.end; }
  return out;
}
function oid(b, t) {
  const v = b.subarray(t.body, t.end);
  if (!v.length) return '';
  const parts = [Math.floor(v[0] / 40), v[0] % 40];
  let x = 0;
  for (let i = 1; i < v.length; i++) { x = x * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { parts.push(x); x = 0; } }
  return parts.join('.');
}
const NAMES = { '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '1.2.840.113549.1.9.1': 'E' };
function dn(b, t) {
  const parts = [];
  for (const set of kids(b, t)) for (const atv of kids(b, set)) {
    const [o, v] = kids(b, atv);
    if (!o || !v) continue;
    const raw = b.subarray(v.body, v.end);
    const s = v.tag === 0x1e ? new TextDecoder('utf-16be').decode(raw) : new TextDecoder('utf-8', { fatal: false }).decode(raw);
    parts.push(`${NAMES[oid(b, o)] || oid(b, o)}=${s.replace(/[\x00-\x1f\x7f]/g, '?')}`);
  }
  return parts.join(', ');
}
function time(b, t) {
  const s = String.fromCharCode(...b.subarray(t.body, t.end));
  const m = t.tag === 0x17 ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)/.exec(s) : /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)/.exec(s);
  if (!m) return s;
  const y = t.tag === 0x17 ? (Number(m[1]) >= 50 ? 1900 : 2000) + Number(m[1]) : Number(m[1]);
  return `${y}-${m[2]}-${m[3]}`;
}

/** Facts about one X.509 certificate (DER bytes). */
function certInfo(der) {
  const info = { sha256: crypto.createHash('sha256').update(der).digest('hex'), sha1: crypto.createHash('sha1').update(der).digest('hex'), size: der.length };
  try {
    const c = tlv(der, 0, der.length);
    const tbs = kids(der, c)[0];
    const f = kids(der, tbs);
    let i = f[0] && f[0].tag === 0xa0 ? 1 : 0;
    i++; // serial
    const sig = f[i++];
    info.issuer = dn(der, f[i++]);
    const val = kids(der, f[i++]);
    info.validFrom = time(der, val[0]); info.validTo = time(der, val[1]);
    info.subject = dn(der, f[i++]);
    const spki = f[i];
    if (spki) { const alg = kids(der, kids(der, spki)[0])[0]; const o = oid(der, alg); info.keyType = { '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC', '1.2.840.10040.4.1': 'DSA' }[o] || o; }
    if (sig) { const o = oid(der, kids(der, sig)[0]); info.signatureAlgorithm = { '1.2.840.113549.1.1.11': 'SHA256withRSA', '1.2.840.113549.1.1.5': 'SHA1withRSA', '1.2.840.113549.1.1.4': 'MD5withRSA', '1.2.840.10045.4.3.2': 'SHA256withECDSA', '2.16.840.1.101.3.4.3.2': 'SHA256withDSA', '1.2.840.10040.4.3': 'SHA1withDSA', '1.2.840.113549.1.1.12': 'SHA384withRSA', '1.2.840.113549.1.1.13': 'SHA512withRSA' }[o] || o; }
  } catch { info.note = 'The certificate fields could not be read; the hashes are of the stored bytes.'; }
  return info;
}

/** First certificate in a PKCS#7 SignedData file (META-INF/*.RSA, .DSA, .EC). Returns DER bytes or null. */
function pkcs7Cert(b) {
  const ci = tlv(b, 0, b.length);
  const [type, content] = kids(b, ci);
  if (!type || oid(b, type) !== '1.2.840.113549.1.7.2' || !content) return null;
  const sd = kids(b, content)[0];
  for (const k of kids(b, sd)) {
    if (k.tag === 0xa0) { const cert = kids(b, k)[0]; return cert ? b.subarray(cert.start, cert.end) : null; }
  }
  return null;
}

/** First certificate of the first signer in a v2 or v3 block value (length-prefixed records). */
function schemeCert(src, pair) {
  const v = src.bytes(pair.valueOff, Math.min(pair.size, 16 * 1024 * 1024));
  const dv = new DataView(v.buffer, v.byteOffset, v.byteLength);
  const lp = (p, end) => { if (p + 4 > end) throw new RangeError('past the end'); const n = dv.getUint32(p, true); if (p + 4 + n > end) throw new RangeError('past the end'); return [p + 4, p + 4 + n]; };
  const [s0, s1] = lp(0, v.length);       // signers
  const [g0, g1] = lp(s0, s1);            // first signer
  const [d0, d1] = lp(g0, g1);            // signed data
  const [, dg1] = lp(d0, d1);             // digests
  const [c0, c1] = lp(dg1, d1);           // certificates
  const [x0, x1] = lp(c0, c1);            // first certificate
  return v.slice(x0, x1);
}

module.exports = { readSigningBlock, pkcs7Cert, schemeCert, certInfo, tlv, IDS, MAGIC };
