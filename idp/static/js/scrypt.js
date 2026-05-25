/*
 * Minimal pure-JS scrypt (RFC 7914) implementation for the password
 * challenge-response factor (STEPS.md §1.6, JUSTIFICATIONS.md §3).
 *
 * Exposes one global function:
 *
 *   scryptDerive(password: string|Uint8Array,
 *                salt:     Uint8Array,
 *                opts:     {N: number, r: number, p: number, dkLen: number})
 *      → Promise<Uint8Array>
 *
 * Default parameters (matching the server side): N = 2^14, r = 8, p = 1,
 * dkLen = 32. The derivation runs synchronously inside a setTimeout chunk so
 * the page does not freeze; ~1–2 s on commodity hardware.
 *
 * Uses Web Crypto API for PBKDF2-HMAC-SHA256 (steps 1 and 3 of scrypt).
 */
(function (global) {
  "use strict";

  const SUBTLE = global.crypto && global.crypto.subtle;
  if (!SUBTLE) {
    throw new Error("Web Crypto API not available — cannot derive scrypt verifier");
  }

  function toBytes(s) {
    if (s instanceof Uint8Array) return s;
    return new TextEncoder().encode(String(s));
  }

  async function hmacSha256(keyBytes, dataBytes) {
    const key = await SUBTLE.importKey(
      "raw", keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false, ["sign"]
    );
    const sig = await SUBTLE.sign("HMAC", key, dataBytes);
    return new Uint8Array(sig);
  }

  function u32be(n) {
    return new Uint8Array([
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>>  8) & 0xff,
       n         & 0xff,
    ]);
  }

  function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  // PBKDF2-HMAC-SHA256(password, salt, iterations=1, dkLen).
  // We implement the one-iteration case directly instead of calling
  // subtle.deriveBits("PBKDF2"), because some browsers return a generic
  // OperationError for iterations=1 even though it is valid for scrypt.
  async function pbkdf2(password, salt, dkLen) {
    const keyBytes = toBytes(password);
    const out = new Uint8Array(dkLen);
    let written = 0;
    let block = 1;
    while (written < dkLen) {
      const u = await hmacSha256(keyBytes, concatBytes(salt, u32be(block)));
      out.set(u.subarray(0, Math.min(u.length, dkLen - written)), written);
      written += u.length;
      block += 1;
    }
    return out;
  }

  // 32-bit add and rotate-left
  function add(a, b) { return (a + b) | 0; }
  function rotl(a, b) { return ((a << b) | (a >>> (32 - b))) | 0; }

  // Salsa20/8 core — operates in-place on 16 little-endian uint32 words
  function salsa208(B) {
    const x = new Uint32Array(B);
    for (let i = 0; i < 8; i += 2) {
      x[ 4] ^= rotl(add(x[ 0], x[12]),  7);
      x[ 8] ^= rotl(add(x[ 4], x[ 0]),  9);
      x[12] ^= rotl(add(x[ 8], x[ 4]), 13);
      x[ 0] ^= rotl(add(x[12], x[ 8]), 18);
      x[ 9] ^= rotl(add(x[ 5], x[ 1]),  7);
      x[13] ^= rotl(add(x[ 9], x[ 5]),  9);
      x[ 1] ^= rotl(add(x[13], x[ 9]), 13);
      x[ 5] ^= rotl(add(x[ 1], x[13]), 18);
      x[14] ^= rotl(add(x[10], x[ 6]),  7);
      x[ 2] ^= rotl(add(x[14], x[10]),  9);
      x[ 6] ^= rotl(add(x[ 2], x[14]), 13);
      x[10] ^= rotl(add(x[ 6], x[ 2]), 18);
      x[ 3] ^= rotl(add(x[15], x[11]),  7);
      x[ 7] ^= rotl(add(x[ 3], x[15]),  9);
      x[11] ^= rotl(add(x[ 7], x[ 3]), 13);
      x[15] ^= rotl(add(x[11], x[ 7]), 18);

      x[ 1] ^= rotl(add(x[ 0], x[ 3]),  7);
      x[ 2] ^= rotl(add(x[ 1], x[ 0]),  9);
      x[ 3] ^= rotl(add(x[ 2], x[ 1]), 13);
      x[ 0] ^= rotl(add(x[ 3], x[ 2]), 18);
      x[ 6] ^= rotl(add(x[ 5], x[ 4]),  7);
      x[ 7] ^= rotl(add(x[ 6], x[ 5]),  9);
      x[ 4] ^= rotl(add(x[ 7], x[ 6]), 13);
      x[ 5] ^= rotl(add(x[ 4], x[ 7]), 18);
      x[11] ^= rotl(add(x[10], x[ 9]),  7);
      x[ 8] ^= rotl(add(x[11], x[10]),  9);
      x[ 9] ^= rotl(add(x[ 8], x[11]), 13);
      x[10] ^= rotl(add(x[ 9], x[ 8]), 18);
      x[12] ^= rotl(add(x[15], x[14]),  7);
      x[13] ^= rotl(add(x[12], x[15]),  9);
      x[14] ^= rotl(add(x[13], x[12]), 13);
      x[15] ^= rotl(add(x[14], x[13]), 18);
    }
    for (let i = 0; i < 16; i++) B[i] = add(B[i], x[i]);
  }

  // BlockMix_Salsa20/8(B): B is 2r 16-word blocks
  function blockMix(B, r) {
    const Y = new Uint32Array(B.length);
    const X = new Uint32Array(16);
    // X = B[2r-1]
    X.set(B.subarray((2 * r - 1) * 16, 2 * r * 16));
    for (let i = 0; i < 2 * r; i++) {
      // X = X xor B[i]
      for (let j = 0; j < 16; j++) X[j] ^= B[i * 16 + j];
      // X = Salsa20/8(X)
      salsa208(X);
      // Y[i] = X
      Y.set(X, i * 16);
    }
    // Output reorder: Y[0], Y[2], …, Y[2r-2], Y[1], Y[3], …, Y[2r-1]
    for (let i = 0; i < r; i++) {
      B.set(Y.subarray((i * 2) * 16, (i * 2 + 1) * 16), i * 16);
    }
    for (let i = 0; i < r; i++) {
      B.set(Y.subarray((i * 2 + 1) * 16, (i * 2 + 2) * 16), (i + r) * 16);
    }
  }

  // Integerify: read first 4 bytes (LE) of the last 64-byte block of B mod N
  function integerify(B, r, N) {
    // Last block starts at offset (2r-1) * 16 words.
    return B[(2 * r - 1) * 16] >>> 0 & (N - 1);
    // N is power-of-two so AND with (N-1) is equivalent to mod N.
  }

  function romix(B, r, N) {
    const V = new Uint32Array(N * 32 * r);
    const X = new Uint32Array(B);
    for (let i = 0; i < N; i++) {
      V.set(X, i * 32 * r);
      blockMix(X, r);
    }
    for (let i = 0; i < N; i++) {
      const j = integerify(X, r, N);
      const base = j * 32 * r;
      for (let k = 0; k < 32 * r; k++) X[k] ^= V[base + k];
      blockMix(X, r);
    }
    B.set(X);
  }

  // Convert Uint8Array → Uint32Array (little-endian)
  function bytesToWords(bytes) {
    const n = bytes.length / 4;
    const words = new Uint32Array(n);
    for (let i = 0; i < n; i++) {
      words[i] = ( bytes[4 * i]
                | (bytes[4 * i + 1] <<  8)
                | (bytes[4 * i + 2] << 16)
                | (bytes[4 * i + 3] << 24)) >>> 0;
    }
    return words;
  }
  function wordsToBytes(words) {
    const out = new Uint8Array(words.length * 4);
    for (let i = 0; i < words.length; i++) {
      const w = words[i];
      out[4 * i]     =  w        & 0xff;
      out[4 * i + 1] = (w >>>  8) & 0xff;
      out[4 * i + 2] = (w >>> 16) & 0xff;
      out[4 * i + 3] = (w >>> 24) & 0xff;
    }
    return out;
  }

  async function scryptDerive(password, salt, opts) {
    const N     = opts.N     || 16384;
    const r     = opts.r     || 8;
    const p     = opts.p     || 1;
    const dkLen = opts.dkLen || 32;

    if ((N & (N - 1)) !== 0 || N < 2) {
      throw new Error("scrypt N must be a power of two ≥ 2");
    }

    // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
    const B0 = await pbkdf2(password, salt, p * 128 * r);
    const Bwords = bytesToWords(B0);

    // Step 2: B_i = ROMix(B_i, N) for i in [0, p)
    // p == 1 in our use; loop is left explicit.
    const blockWords = 32 * r;
    for (let i = 0; i < p; i++) {
      const slice = Bwords.subarray(i * blockWords, (i + 1) * blockWords);
      // Use a small async yield so the event loop isn't starved.
      await new Promise((res) => setTimeout(() => { romix(slice, r, N); res(); }, 0));
    }

    // Step 3: DK = PBKDF2-HMAC-SHA256(password, B, 1, dkLen)
    const Bbytes = wordsToBytes(Bwords);
    return pbkdf2(password, Bbytes, dkLen);
  }

  global.scryptDerive = scryptDerive;
})(typeof self !== "undefined" ? self : this);
