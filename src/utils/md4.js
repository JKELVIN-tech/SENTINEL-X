'use strict';

/**
 * Pure JavaScript MD4 implementation.
 * Used for NTLM hash computation on Node.js 22+ where OpenSSL dropped MD4.
 * Based on the RFC 1320 specification.
 */

function md4(input) {
  // Convert input to UTF-16LE Buffer if string
  let buf;
  if (typeof input === 'string') {
    buf = Buffer.from(input, 'utf16le');
  } else {
    buf = Buffer.from(input);
  }

  const msgLen  = buf.length;
  const bitLen  = msgLen * 8;

  // Padding: append 0x80, then zeros, then 64-bit length (LE)
  const padLen  = ((msgLen + 8) % 64 <= 55)
    ? 55 - ((msgLen + 8) % 64) + 9
    : 119 - ((msgLen + 8) % 64) + 9;

  const padded = Buffer.alloc(msgLen + padLen + 8);
  buf.copy(padded);
  padded[msgLen] = 0x80;
  // Append length in bits as 64-bit LE
  padded.writeUInt32LE(bitLen >>> 0,           msgLen + padLen);
  padded.writeUInt32LE(Math.floor(bitLen / 0x100000000), msgLen + padLen + 4);

  // Initial hash values
  let a = 0x67452301;
  let b = 0xEFCDAB89;
  let c = 0x98BADCFE;
  let d = 0x10325476;

  const add32 = (x, y) => (x + y) >>> 0;
  const rol32 = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

  // Process each 512-bit block
  for (let i = 0; i < padded.length; i += 64) {
    const X = [];
    for (let j = 0; j < 16; j++) {
      X[j] = padded.readUInt32LE(i + j * 4);
    }

    let aa = a, bb = b, cc = c, dd = d;

    // Round 1 — F(b,c,d) = (b AND c) OR (NOT b AND d)
    const F = (b, c, d) => ((b & c) | (~b & d)) >>> 0;
    const r1 = (a, b, c, d, k, s) => rol32(add32(a, add32(F(b,c,d), X[k])), s);
    const S1 = [3,7,11,19];
    const r1seq = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    for (let j = 0; j < 16; j++) {
      const k = r1seq[j];
      const s = S1[j % 4];
      if (j % 4 === 0)      a = r1(a,b,c,d,k,s);
      else if (j % 4 === 1) d = r1(d,a,b,c,k,s);
      else if (j % 4 === 2) c = r1(c,d,a,b,k,s);
      else                  b = r1(b,c,d,a,k,s);
    }

    // Round 2 — G(b,c,d) = (b AND c) OR (b AND d) OR (c AND d)
    const G = (b, c, d) => ((b & c) | (b & d) | (c & d)) >>> 0;
    const C2 = 0x5A827999;
    const r2 = (a, b, c, d, k, s) => rol32(add32(add32(a, G(b,c,d)), add32(X[k], C2)), s);
    const S2 = [3,5,9,13];
    const r2seq = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15];
    for (let j = 0; j < 16; j++) {
      const k = r2seq[j];
      const s = S2[j % 4];
      if (j % 4 === 0)      a = r2(a,b,c,d,k,s);
      else if (j % 4 === 1) d = r2(d,a,b,c,k,s);
      else if (j % 4 === 2) c = r2(c,d,a,b,k,s);
      else                  b = r2(b,c,d,a,k,s);
    }

    // Round 3 — H(b,c,d) = b XOR c XOR d
    const H = (b, c, d) => (b ^ c ^ d) >>> 0;
    const C3 = 0x6ED9EBA1;
    const r3 = (a, b, c, d, k, s) => rol32(add32(add32(a, H(b,c,d)), add32(X[k], C3)), s);
    const S3 = [3,9,11,15];
    const r3seq = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15];
    for (let j = 0; j < 16; j++) {
      const k = r3seq[j];
      const s = S3[j % 4];
      if (j % 4 === 0)      a = r3(a,b,c,d,k,s);
      else if (j % 4 === 1) d = r3(d,a,b,c,k,s);
      else if (j % 4 === 2) c = r3(c,d,a,b,k,s);
      else                  b = r3(b,c,d,a,k,s);
    }

    a = add32(a, aa);
    b = add32(b, bb);
    c = add32(c, cc);
    d = add32(d, dd);
  }

  const out = Buffer.alloc(16);
  out.writeUInt32LE(a, 0);
  out.writeUInt32LE(b, 4);
  out.writeUInt32LE(c, 8);
  out.writeUInt32LE(d, 12);
  return out.toString('hex');
}

module.exports = { md4 };
