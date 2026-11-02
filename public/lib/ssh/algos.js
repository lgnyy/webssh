/* ============ SHA-2 系列（纯 JS，基于 32 位/64 位运算） ============ */
(function () {
  var K256 = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  var H256 = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                              0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  function sha256(bytes) {
    var l = bytes.length, bitLen = l * 8;
    var total = ((l + 9 + 63) >> 6) << 6;
    var m = new Uint8Array(total); m.set(bytes); m[l] = 0x80;
    var dv = new DataView(m.buffer);
    dv.setUint32(total - 4, bitLen >>> 0, false);
    dv.setUint32(total - 8, Math.floor(bitLen / 0x100000000), false);
    var H = H256.slice(), W = new Uint32Array(64);
    for (var off = 0; off < total; off += 64) {
      for (var i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4, false);
      for (i = 16; i < 64; i++) {
        var s0 = (W[i-15]>>>7|W[i-15]<<25) ^ (W[i-15]>>>18|W[i-15]<<14) ^ (W[i-15]>>>3);
        var s1 = (W[i-2]>>>17|W[i-2]<<15) ^ (W[i-2]>>>19|W[i-2]<<13) ^ (W[i-2]>>>10);
        W[i] = (W[i-16] + s0 + W[i-7] + s1) | 0;
      }
      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (i = 0; i < 64; i++) {
        var S1 = (e>>>6|e<<26) ^ (e>>>11|e<<21) ^ (e>>>25|e<<7);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K256[i] + W[i]) | 0;
        var S0 = (a>>>2|a<<30) ^ (a>>>13|a<<19) ^ (a>>>22|a<<10);
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
      }
      H[0]=(H[0]+a)|0; H[1]=(H[1]+b)|0; H[2]=(H[2]+c)|0; H[3]=(H[3]+d)|0;
      H[4]=(H[4]+e)|0; H[5]=(H[5]+f)|0; H[6]=(H[6]+g)|0; H[7]=(H[7]+h)|0;
    }
    var out = new Uint8Array(32), odv = new DataView(out.buffer);
    for (i = 0; i < 8; i++) odv.setUint32(i * 4, H[i], false);
    return out;
  }
  /* SHA-512 用 BigInt 逐块处理（慢但简单） */
  function sha512BigInt(bytes) {
    var K = [
      0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189dbbcn,
      0x3956c25bf348b538n,0x59f111f1b605d019n,0x923f82a4af194f9bn,0xab1c5ed5da6d8118n,
      0xd807aa98a3030242n,0x12835b0145706fben,0x243185be4ee4b28cn,0x550c7dc3d5ffb4e2n,
      0x72be5d74f27b896fn,0x80deb1fe3b1696b1n,0x9bdc06a725c71235n,0xc19bf174cf692694n,
      0xe49b69c19ef14ad2n,0xefbe4786384f25e3n,0x0fc19dc68b8cd5b5n,0x240ca1cc77ac9c65n,
      0x2de92c6f592b0275n,0x4a7484aa6ea6e483n,0x5cb0a9dcbd41fbd4n,0x76f988da831153b5n,
      0x983e5152ee66dfabn,0xa831c66d2db43210n,0xb00327c898fb213fn,0xbf597fc7beef0ee4n,
      0xc6e00bf33da88fc2n,0xd5a79147930aa725n,0x06ca6351e003826fn,0x142929670a0e6e70n,
      0x27b70a8546d22ffcn,0x2e1b21385c26c926n,0x4d2c6dfc5ac42aedn,0x53380d139d95b3dfn,
      0x650a73548baf63den,0x766a0abb3c77b2a8n,0x81c2c92e47edaee6n,0x92722c851482353bn,
      0xa2bfe8a14cf10364n,0xa81a664bbc423001n,0xc24b8b70d0f89791n,0xc76c51a30654be30n,
      0xd192e819d6ef5218n,0xd69906245565a910n,0xf40e35855771202an,0x106aa07032bbd1b8n,
      0x19a4c116b8d2d0c8n,0x1e376c085141ab53n,0x2748774cdf8eeb99n,0x34b0bcb5e19b48a8n,
      0x391c0cb3c5c95a63n,0x4ed8aa4ae3418acbn,0x5b9cca4f7763e373n,0x682e6ff3d6b2b8a3n,
      0x748f82ee5defb2fcn,0x78a5636f43172f60n,0x84c87814a1f0ab72n,0x8cc702081a6439ecn,
      0x90befffa23631e28n,0xa4506cebde82bde9n,0xbef9a3f7b2c67915n,0xc67178f2e372532bn,
      0xca273eceea26619cn,0xd186b8c721c0c207n,0xeada7dd6cde0eb1en,0xf57d4f7fee6ed178n,
      0x06f067aa72176fban,0x0a637dc5a2c898a6n,0x113f9804bef90daen,0x1b710b35131c471bn,
      0x28db77f523047d84n,0x32caab7b40c72493n,0x3c9ebe0a15c9bebcn,0x431d67c49c100d4cn,
      0x4cc5d4becb3e42b6n,0x597f299cfc657e2an,0x5fcb6fab3ad6faecn,0x6c44198c4a475817n];
    var H = [0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,
             0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n];
    var MASK = (1n << 64n) - 1n;
    var l = bytes.length, bitLen = BigInt(l) * 8n;
    var total = ((l + 17 + 127) >> 7) << 7;
    var m = new Uint8Array(total); m.set(bytes); m[l] = 0x80;
    var dv = new DataView(m.buffer);
    var hi = Number(bitLen >> 64n), lo = Number(bitLen & 0xffffffffffffffffn);
    dv.setUint32(total - 8, hi, false); dv.setUint32(total - 4, lo, false);
    function rr(x, n) { return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK; }
    var W = new Array(80);
    for (var off = 0; off < total; off += 128) {
      for (var i = 0; i < 16; i++) {
        var a = BigInt(dv.getUint32(off + i * 8, false));
        var b = BigInt(dv.getUint32(off + i * 8 + 4, false));
        W[i] = (a << 32n) | b;
      }
      for (i = 16; i < 80; i++) {
        var s0 = rr(W[i-15],1) ^ rr(W[i-15],8) ^ (W[i-15] >> 7n);
        var s1 = rr(W[i-2],19) ^ rr(W[i-2],61) ^ (W[i-2] >> 6n);
        W[i] = (W[i-16] + s0 + W[i-7] + s1) & MASK;
      }
      var a1=H[0],b1=H[1],c1=H[2],d1=H[3],e1=H[4],f1=H[5],g1=H[6],h1=H[7];
      for (i = 0; i < 80; i++) {
        var S1 = rr(e1,14) ^ rr(e1,18) ^ rr(e1,41);
        var ch = (e1 & f1) ^ (~e1 & g1 & MASK);
        var t1 = (h1 + S1 + ch + K[i] + W[i]) & MASK;
        var S0 = rr(a1,28) ^ rr(a1,34) ^ rr(a1,39);
        var mj = (a1 & b1) ^ (a1 & c1) ^ (b1 & c1);
        var t2 = (S0 + mj) & MASK;
        h1=g1; g1=f1; f1=e1; e1=(d1+t1)&MASK; d1=c1; c1=b1; b1=a1; a1=(t1+t2)&MASK;
      }
      H[0]=(H[0]+a1)&MASK; H[1]=(H[1]+b1)&MASK; H[2]=(H[2]+c1)&MASK; H[3]=(H[3]+d1)&MASK;
      H[4]=(H[4]+e1)&MASK; H[5]=(H[5]+f1)&MASK; H[6]=(H[6]+g1)&MASK; H[7]=(H[7]+h1)&MASK;
    }
    var out = new Uint8Array(64);
    for (i = 0; i < 8; i++) {
      var v = H[i];
      for (var j = 7; j >= 0; j--) { out[i*8+j] = Number(v & 0xffn); v >>= 8n; }
    }
    return out;
  }
  WSSH._sha256 = sha256;
  WSSH._sha512 = sha512BigInt;
})();


// HMAC（用上面的 hash）
WSSH._hmacJS = function(hashFn, blockSize, key, data) {
  if (key.length > blockSize) key = hashFn(key);
  var k = new Uint8Array(blockSize); k.set(key);
  var ipad = new Uint8Array(blockSize + data.length);
  for (var i = 0; i < blockSize; i++) ipad[i] = k[i] ^ 0x36;
  ipad.set(data, blockSize);
  var inner = hashFn(ipad);
  // opad 大小取决于实际哈希输出长度（SHA-256=32，SHA-512=64），不能写死 32
  var opad = new Uint8Array(blockSize + inner.length);
  for (var i = 0; i < blockSize; i++) opad[i] = k[i] ^ 0x5c;
  opad.set(inner, blockSize);
  return Promise.resolve(hashFn(opad));
};


/* ============ AES 纯 JS（128/192/256，CTR/CBC） ============ */
(function () {
  var SBOX = new Uint8Array(256), INV_SBOX = new Uint8Array(256);
  (function init() {
    var p = 1, q = 1;
    do {
      p = p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0);
      p &= 0xff;
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
      if (q & 0x80) q ^= 0x09;
      var x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^
              ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
      SBOX[p] = (x ^ 0x63) & 0xff;
    } while (p !== 1);
    SBOX[0] = 0x63;
    for (var i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;
  })();
  function xtime(a) { return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff; }
  function mul(a, b) {
    var r = 0;
    while (b) { if (b & 1) r ^= a; a = xtime(a); b >>= 1; }
    return r;
  }
  function expandKey(key) {
    var Nk = key.length / 4, Nr = Nk + 6;
    var w = new Uint8Array(16 * (Nr + 1));
    w.set(key);
    var rcon = 1;
    for (var i = Nk; i < 4 * (Nr + 1); i++) {
      var t = w.subarray((i - 1) * 4, i * 4);
      if (i % Nk === 0) {
        t = new Uint8Array([SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]);
        rcon = xtime(rcon);
      } else if (Nk > 6 && i % Nk === 4) {
        t = new Uint8Array([SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]]);
      }
      for (var j = 0; j < 4; j++) w[i * 4 + j] = w[(i - Nk) * 4 + j] ^ t[j];
    }
    return { w: w, Nr: Nr };
  }
  function encryptBlock(ks, block) {
    var s = new Uint8Array(block), w = ks.w, Nr = ks.Nr;
    addRK(s, w, 0);
    for (var r = 1; r < Nr; r++) { subBytes(s); shiftRows(s); mixColumns(s); addRK(s, w, r); }
    subBytes(s); shiftRows(s); addRK(s, w, Nr);
    return s;
  }
  function decryptBlock(ks, block) {
    var s = new Uint8Array(block), w = ks.w, Nr = ks.Nr;
    addRK(s, w, Nr);
    for (var r = Nr - 1; r > 0; r--) { invShiftRows(s); invSubBytes(s); addRK(s, w, r); invMixColumns(s); }
    invShiftRows(s); invSubBytes(s); addRK(s, w, 0);
    return s;
  }
  function addRK(s, w, r) { for (var i = 0; i < 16; i++) s[i] ^= w[r * 16 + i]; }
  function subBytes(s) { for (var i = 0; i < 16; i++) s[i] = SBOX[s[i]]; }
  function invSubBytes(s) { for (var i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]]; }
  function shiftRows(s) {
    var t;
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
  }
  function invShiftRows(s) {
    var t;
    t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
    t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
    t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
  }
  function mixColumns(s) {
    for (var c = 0; c < 4; c++) {
      var i = c * 4, a = s[i], b = s[i+1], cc = s[i+2], d = s[i+3];
      s[i]   = xtime(a) ^ (xtime(b) ^ b) ^ cc ^ d;
      s[i+1] = a ^ xtime(b) ^ (xtime(cc) ^ cc) ^ d;
      s[i+2] = a ^ b ^ xtime(cc) ^ (xtime(d) ^ d);
      s[i+3] = (xtime(a) ^ a) ^ b ^ cc ^ xtime(d);
    }
  }
  function invMixColumns(s) {
    for (var c = 0; c < 4; c++) {
      var i = c * 4, a = s[i], b = s[i+1], cc = s[i+2], d = s[i+3];
      s[i]   = mul(a,14)^mul(b,11)^mul(cc,13)^mul(d,9);
      s[i+1] = mul(a,9)^mul(b,14)^mul(cc,11)^mul(d,13);
      s[i+2] = mul(a,13)^mul(b,9)^mul(cc,14)^mul(d,11);
      s[i+3] = mul(a,11)^mul(b,13)^mul(cc,9)^mul(d,14);
    }
  }
  function aesCTR(key, iv, data, enc) {
    var ks = expandKey(key);
    var counter = new Uint8Array(iv);          // 16 字节
    var out = new Uint8Array(data.length);
    for (var off = 0; off < data.length; off += 16) {
      var stream = encryptBlock(ks, counter);
      for (var i = 0; i < 16 && off + i < data.length; i++) out[off + i] = data[off + i] ^ stream[i];
      // 大端自增 counter（必须显式处理进位：Uint8Array 的 ++ 返回未截断值，
      // 直接判断 !== 0 会在 0xff 时提前终止，导致后续所有块计数器错误）
      for (var j = 15; j >= 0; j--) {
        var v = counter[j] + 1;
        counter[j] = v & 0xff;
        if (v <= 0xff) break;
      }
    }
    return Promise.resolve(out);
  }
  function aesCBCEncrypt(key, iv, data) {
    var ks = expandKey(key);
    var out = new Uint8Array(data.length);
    var prev = new Uint8Array(iv);
    for (var off = 0; off < data.length; off += 16) {
      var blk = new Uint8Array(16);
      for (var i = 0; i < 16; i++) blk[i] = data[off + i] ^ prev[i];
      var ct = encryptBlock(ks, blk);
      out.set(ct, off); prev = ct;
    }
    return Promise.resolve(out);
  }
  function aesCBCDecrypt(key, iv, data) {
    var ks = expandKey(key);
    var out = new Uint8Array(data.length);
    var prev = new Uint8Array(iv);
    for (var off = 0; off < data.length; off += 16) {
      var ct = data.subarray(off, off + 16);
      var pt = decryptBlock(ks, ct);
      for (var i = 0; i < 16; i++) out[off + i] = pt[i] ^ prev[i];
      prev = ct;
    }
    return Promise.resolve(out);
  }
  WSSH._aesCTR = aesCTR;
  WSSH._aesCBCEncrypt = aesCBCEncrypt;
  WSSH._aesCBCDecrypt = aesCBCDecrypt;
  WSSH._aesEncryptBlock = function (key, block) { return encryptBlock(expandKey(key), block); };
})();


// AES-GCM 纯 JS（含 GHASH）
(function () {
  function gfMul(X, Y) {
    var Z = new Uint8Array(16), V = new Uint8Array(Y);
    for (var i = 0; i < 128; i++) {
      if ((X[i >> 3] >> (7 - (i & 7))) & 1)
        for (var j = 0; j < 16; j++) Z[j] ^= V[j];
      var lsb = V[15] & 1;
      for (j = 15; j > 0; j--) V[j] = (V[j] >> 1) | ((V[j-1] & 1) << 7);
      V[0] >>= 1;
      if (lsb) V[0] ^= 0xe1;
    }
    return Z;
  }
  function ghash(H, aad, ct) {
    var Y = new Uint8Array(16);
    function absorb(bytes) {
      for (var off = 0; off < bytes.length; off += 16) {
        var blk = new Uint8Array(16);
        blk.set(bytes.subarray(off, off + 16));
        for (var i = 0; i < 16; i++) Y[i] ^= blk[i];
        Y = gfMul(Y, H);
      }
    }
    absorb(aad); absorb(ct);
    var lenBlk = new Uint8Array(16);
    var dv = new DataView(lenBlk.buffer);
    dv.setUint32(0, 0, false); dv.setUint32(4, aad.length * 8, false);
    dv.setUint32(8, 0, false); dv.setUint32(12, ct.length * 8, false);
    for (var i = 0; i < 16; i++) Y[i] ^= lenBlk[i];
    return gfMul(Y, H);
  }
  function aesGCMEncrypt(key, iv, plain, aad) {
    aad = aad || new Uint8Array(0);
    // 计算 J0：iv 12 字节 → iv||0x00000001；其他长度用 GHASH
    var H = WSSH._aesEncryptBlock(key, new Uint8Array(16));
    var J0;
    if (iv.length === 12) { J0 = new Uint8Array(16); J0.set(iv); J0[15] = 1; }
    else {
      J0 = ghash(H, new Uint8Array(0), iv);
      var l = new Uint8Array(16); new DataView(l.buffer).setUint32(12, iv.length * 8, false);
      for (var i = 0; i < 16; i++) J0[i] ^= l[i];
      J0 = gfMul(J0, H);
    }
    var ctr = new Uint8Array(J0);
    for (i = 15; i >= 12; i--) { var vv = ctr[i] + 1; ctr[i] = vv & 0xff; if (vv <= 0xff) break; }
    return WSSH._aesCTR(key, ctr, plain, true).then(function (ct) {
      var S = ghash(H, aad, ct);
      var tag = new Uint8Array(16), ctr0 = new Uint8Array(J0);
      var ek = WSSH._aesEncryptBlock(key, ctr0);
      for (var j = 0; j < 16; j++) tag[j] = S[j] ^ ek[j];
      var out = new Uint8Array(ct.length + 16);
      out.set(ct); out.set(tag, ct.length);
      return out;
    });
  }
  function aesGCMDecrypt(key, iv, data, aad) {
    aad = aad || new Uint8Array(0);
    var ct = data.subarray(0, data.length - 16);
    var tag = data.subarray(data.length - 16);
    var H = WSSH._aesEncryptBlock(key, new Uint8Array(16));
    var J0;
    if (iv.length === 12) { J0 = new Uint8Array(16); J0.set(iv); J0[15] = 1; }
    else {
      J0 = ghash(H, new Uint8Array(0), iv);
      var l = new Uint8Array(16); new DataView(l.buffer).setUint32(12, iv.length * 8, false);
      for (var i = 0; i < 16; i++) J0[i] ^= l[i];
      J0 = gfMul(J0, H);
    }
    var S = ghash(H, aad, ct);
    var ek = WSSH._aesEncryptBlock(key, new Uint8Array(J0));
    var expect = new Uint8Array(16);
    for (i = 0; i < 16; i++) expect[i] = S[i] ^ ek[i];
    var diff = 0;
    for (i = 0; i < 16; i++) diff |= expect[i] ^ tag[i];
    if (diff !== 0) return Promise.reject(new Error('GCM auth fail'));
    var ctr = new Uint8Array(J0);
    for (i = 15; i >= 12; i--) { var vv = ctr[i] + 1; ctr[i] = vv & 0xff; if (vv <= 0xff) break; }
    return WSSH._aesCTR(key, ctr, ct, false);
  }
  WSSH._aesGCMEncrypt = aesGCMEncrypt;
  WSSH._aesGCMDecrypt = aesGCMDecrypt;
})();


// PBKDF2（纯 JS）
WSSH._pbkdf2JS = async function(hashFn, hLen, pw, salt, iter, dkLen) {
  var blockSize = hashFn === WSSH._sha512 ? 128 : 64;
  var out = new Uint8Array(dkLen);
  var blocks = Math.ceil(dkLen / hLen);
  for (var i = 1; i <= blocks; i++) {
    var si = new Uint8Array(salt.length + 4);
    si.set(salt); new DataView(si.buffer).setUint32(salt.length, i, false);
    var U = await WSSH._hmacJS(hashFn, blockSize, pw, si);
    var T = new Uint8Array(U);
    for (var j = 1; j < iter; j++) {
      U = await WSSH._hmacJS(hashFn, blockSize, pw, U);
      for (var k = 0; k < hLen; k++) T[k] ^= U[k];
    }
    out.set(T.subarray(0, Math.min(hLen, dkLen - (i - 1) * hLen)), (i - 1) * hLen);
  }
  return out;
}