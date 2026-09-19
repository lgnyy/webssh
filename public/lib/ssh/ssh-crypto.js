/*!
 * ssh-crypto.js - 浏览器密码学原语
 *  - 对称/哈希/HMAC/ECDH/RSA/ECDSA：全部走浏览器 WebCrypto (crypto.subtle)
 *  - X25519 / Ed25519：纯 JS + BigInt 实现（SHA-512 仍走 WebCrypto）
 *  - bcrypt_pbkdf：1:1 移植 OpenBSD blowfish.c / bcrypt_pbkdf.c（OpenSSH 私钥 KDF）
 */
(function (global) {
  'use strict';
  var WSSH = global.WSSH || (global.WSSH = {});
  var U = WSSH.util;
  var subtle = global.crypto.subtle;

  function ab(x) {
    // WebCrypto 接收的必须是视图精确区间：协议层传入的多为大缓冲的 subarray
    if (x && x.buffer) {
      return (x.byteOffset === 0 && x.byteLength === x.buffer.byteLength)
        ? x.buffer
        : x.buffer.slice(x.byteOffset, x.byteOffset + x.byteLength);
    }
    return x;
  }
  function u8(x) { return x instanceof Uint8Array ? x : new Uint8Array(x); }

  /* ================= 随机数 / 哈希 / HMAC ================= */
  function randomBytes(n) {
    var b = new Uint8Array(n);
    global.crypto.getRandomValues(b);
    return b;
  }

  var HASH_MAP = { 'sha1': 'SHA-1', 'sha256': 'SHA-256', 'sha384': 'SHA-384', 'sha512': 'SHA-512' };
  function digest(alg, data) {
    return subtle.digest(HASH_MAP[alg] || alg, ab(data)).then(u8);
  }
  function digestParts(alg, parts) { return digest(alg, U.concat.apply(null, parts)); }

  function hmac(alg, key, data) {
    return subtle.importKey('raw', ab(key), { name: 'HMAC', hash: HASH_MAP[alg] || alg }, false, ['sign'])
      .then(function (ck) { return subtle.sign({ name: 'HMAC' }, ck, ab(data)); })
      .then(u8);
  }

  /* ================= 对称加密 ================= */
  function importAES(key, mode) {
    return subtle.importKey('raw', ab(key), { name: mode }, false, ['encrypt', 'decrypt']);
  }
  function aesCTR(key, iv, data, isEncrypt) {
    return importAES(key, 'AES-CTR').then(function (ck) {
      var op = isEncrypt ? subtle.encrypt : subtle.decrypt;
      return op.call(subtle, { name: 'AES-CTR', counter: ab(iv), length: 64 }, ck, ab(data)).then(u8);
    });
  }
  function aesGCMEncrypt(key, iv, plain, aad) {
    return importAES(key, 'AES-GCM').then(function (ck) {
      return subtle.encrypt({ name: 'AES-GCM', iv: ab(iv), additionalData: aad ? ab(aad) : new Uint8Array(0), tagLength: 128 }, ck, ab(plain)).then(u8);
    });
  }
  function aesGCMDecrypt(key, iv, data, aad) {
    return importAES(key, 'AES-GCM').then(function (ck) {
      return subtle.decrypt({ name: 'AES-GCM', iv: ab(iv), additionalData: aad ? ab(aad) : new Uint8Array(0), tagLength: 128 }, ck, ab(data)).then(u8);
    });
  }
  function aesCBCDecrypt(key, iv, data) {
    return importAES(key, 'AES-CBC').then(function (ck) {
      return subtle.decrypt({ name: 'AES-CBC', iv: ab(iv) }, ck, ab(data)).then(u8);
    });
  }
  function aesCBCEncrypt(key, iv, data) {
    return importAES(key, 'AES-CBC').then(function (ck) {
      return subtle.encrypt({ name: 'AES-CBC', iv: ab(iv) }, ck, ab(data)).then(u8);
    });
  }

  function pbkdf2(pw, salt, iterations, len, hashAlg) {
    return subtle.importKey('raw', ab(pw), { name: 'PBKDF2' }, false, ['deriveBits'])
      .then(function (ck) {
        return subtle.deriveBits(
          { name: 'PBKDF2', salt: ab(salt), iterations: iterations, hash: HASH_MAP[hashAlg] || hashAlg },
          ck, len * 8);
      }).then(u8);
  }

  /* ================= NIST 曲线 ECDH / ECDSA ================= */
  var EC_INFO = {
    'nistp256': { crv: 'P-256', size: 32 },
    'nistp384': { crv: 'P-384', size: 48 },
    'nistp521': { crv: 'P-521', size: 66 }
  };

  function ecdhGenerate(nistName) {
    var info = EC_INFO[nistName];
    return subtle.generateKey({ name: 'ECDH', namedCurve: info.crv }, false, ['deriveBits'])
      .then(function (kp) {
        return subtle.exportKey('raw', kp.publicKey).then(function (raw) {
          return { privateKey: kp.privateKey, pubRaw: u8(raw) };
        });
      });
  }
  function ecdhAgree(privKey, peerPubRaw, nistName) {
    var info = EC_INFO[nistName];
    return subtle.importKey('raw', ab(peerPubRaw), { name: 'ECDH', namedCurve: info.crv }, false, [])
      .then(function (peerKey) {
        return subtle.deriveBits({ name: 'ECDH', public: peerKey }, privKey, info.size * 8);
      }).then(function (bits) {
        // deriveBits 返回 X 坐标（无 04 前缀），长度 = 字段字节数
        return u8(bits);
      });
  }

  /* ECDSA DER(SEC1) <-> SSH(r||s 定长) 互转 */
  function derToRS(der, size) {
    // SEQUENCE { INTEGER r, INTEGER s }
    var i = 0;
    if (der[i++] !== 0x30) throw new Error('ECDSA DER: SEQUENCE 错误');
    var seqLen = der[i++];
    if (seqLen & 0x80) { i += (seqLen & 0x1f); seqLen = der[i - 1]; } // 短格式足够，这里仅兼容
    function readInt() {
      if (der[i++] !== 0x02) throw new Error('ECDSA DER: INTEGER 错误');
      var l = der[i++];
      var v = der.subarray(i, i + l);
      i += l;
      // 去前导零
      var s = 0;
      while (v.length - s > size && v[s] === 0) s++;
      v = v.subarray(s);
      var out = new Uint8Array(size);
      out.set(v, size - v.length);
      return out;
    }
    var r = readInt(), s = readInt();
    return U.concat(r, s);
  }
  function rsToDer(rs) {
    var size = rs.length / 2;
    function trim(b) {
      var i = 0;
      while (i < b.length - 1 && b[i] === 0) i++;
      b = b.subarray(i);
      if (b[0] & 0x80) b = U.concat(new Uint8Array([0]), b);
      return b;
    }
    var r = trim(rs.subarray(0, size));
    var s = trim(rs.subarray(size));
    var body = U.concat(new Uint8Array([0x02, r.length]), r, new Uint8Array([0x02, s.length]), s);
    var head;
    if (body.length < 128) head = new Uint8Array([0x30, body.length]);
    else head = new Uint8Array([0x30, 0x81, body.length]);
    return U.concat(head, body);
  }

  function ecdsaVerify(nistName, msg, sigRS, jwkXY) {
    var info = EC_INFO[nistName];
    // SSH ecdsa-sha2-nistpXXX 签名哈希与曲线一一对应
    var hashName = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' }[info.crv];
    var jwk = { kty: 'EC', crv: info.crv, x: jwkXY.x, y: jwkXY.y, ext: true };
    // WebCrypto ECDSA 使用 IEEE P1363 定长 r||s（不是 DER），sigRS 正是该格式
    return subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: info.crv }, false, ['verify'])
      .then(function (ck) { return subtle.verify({ name: 'ECDSA', hash: hashName }, ck, ab(sigRS), ab(msg)); })
      .catch(function () { return false; });
  }
  function ecdsaSign(nistName, msg, jwkPriv) {
    var info = EC_INFO[nistName];
    var hashName = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' }[info.crv];
    var jwk = {
      kty: 'EC', crv: info.crv,
      x: jwkPriv.x, y: jwkPriv.y, d: jwkPriv.d, ext: true
    };
    return subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: info.crv }, false, ['sign'])
      .then(function (ck) { return subtle.sign({ name: 'ECDSA', hash: hashName }, ck, ab(msg)); })
      // 输出即定长 r||s（IEEE P1363），直接返回
      .then(u8);
  }

  /* ================= RSA（JWK） ================= */
  // Node WebCrypto 要求 importKey 时就在 algorithm 中给出 hash（浏览器也接受）
  function rsaHashName(hashAlg) {
    return hashAlg === 'sha512' ? 'SHA-512' : hashAlg === 'sha256' ? 'SHA-256' : 'SHA-1';
  }
  function rsaVerify(hashAlg, msg, sig, n, e) {
    var jwk = {
      kty: 'RSA',
      n: U.base64UrlEncode(U.bigIntToBytesBE(n)),
      e: U.base64UrlEncode(U.bigIntToBytesBE(e)),
      ext: true
    };
    var alg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: rsaHashName(hashAlg) } };
    return subtle.importKey('jwk', jwk, alg, false, ['verify'])
      .then(function (ck) {
        return subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, ck, ab(sig), ab(msg));
      }).catch(function () { return false; });
  }
  function rsaSign(hashAlg, msg, params) {
    var jwk = { kty: 'RSA', ext: true };
    ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'].forEach(function (k) {
      jwk[k] = U.base64UrlEncode(U.bigIntToBytesBE(params[k]));
    });
    var alg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: rsaHashName(hashAlg) } };
    return subtle.importKey('jwk', jwk, alg, false, ['sign'])
      .then(function (ck) {
        return subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, ck, ab(msg));
      }).then(u8);
  }

  /* ======================================================================
   * X25519 (RFC 7748) — BigInt 实现
   * ====================================================================== */
  var P25519 = (1n << 255n) - 19n;
  function mod25519(a) { var r = a % P25519; return r < 0n ? r + P25519 : r; }
  function inv25519(a) { return powmod25519(a, P25519 - 2n); }
  function powmod25519(a, e) {
    var r = 1n;
    while (e > 0n) {
      if (e & 1n) r = mod25519(r * a);
      a = mod25519(a * a);
      e >>= 1n;
    }
    return r;
  }

  function x25519(scalarBytes, pointBytes) {
    var k = new Uint8Array(scalarBytes);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;
    var x1 = U.bytesToBigIntLE(pointBytes) % P25519;
    var x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n;
    var swap = 0;
    var A, AA, B, BB, E, C, D, DA, CB, t;
    for (var pos = 254; pos >= 0; pos--) {
      var kt = (k[pos >>> 3] >>> (pos & 7)) & 1;
      swap ^= kt;
      if (swap) { t = x2; x2 = x3; x3 = t; t = z2; z2 = z3; z3 = t; }
      swap = kt;
      A = mod25519(x2 + z2); AA = mod25519(A * A);
      B = mod25519(x2 - z2); BB = mod25519(B * B);
      E = mod25519(AA - BB);
      C = mod25519(x3 + z3);
      D = mod25519(x3 - z3);
      DA = mod25519(D * A);
      CB = mod25519(C * B);
      x3 = mod25519(mod25519(DA + CB) * mod25519(DA + CB));
      z3 = mod25519(x1 * mod25519(mod25519(DA - CB) * mod25519(DA - CB)));
      x2 = mod25519(AA * BB);
      z2 = mod25519(E * mod25519(AA + 121665n * E));
    }
    if (swap) { t = x2; x2 = x3; x3 = t; t = z2; z2 = z3; z3 = t; }
    var u = mod25519(x2 * inv25519(z2));
    return U.bigIntToBytesLE(u, 32);
  }
  var X25519_BASE = (function () {
    var b = new Uint8Array(32); b[0] = 9; return b;
  })();
  function x25519Base(scalarBytes) { return x25519(scalarBytes, X25519_BASE); }

  /* ======================================================================
   * Ed25519 (RFC 8032) — BigInt 扩展坐标实现
   * ====================================================================== */
  var L_ED = (1n << 252n) + 27742317777372353535851937790883648493n;
  var D_ED = mod25519(-121665n * (function () {
    // inv(121666)
    var a = 121666n, m = P25519, e = m - 2n, r = 1n;
    while (e > 0n) { if (e & 1n) r = (r * a) % m; a = (a * a) % m; e >>= 1n; }
    return r;
  })());
  var I_ED = powmod25519(2n, (P25519 - 1n) / 4n);

  function edAdd(P, Q) {
    var X1 = P[0], Y1 = P[1], Z1 = P[2], T1 = P[3];
    var X2 = Q[0], Y2 = Q[1], Z2 = Q[2], T2 = Q[3];
    var A = mod25519((Y1 - X1) * (Y2 - X2));
    var B = mod25519((Y1 + X1) * (Y2 + X2));
    var C = mod25519(T1 * 2n * D_ED * T2);
    var D = mod25519(Z1 * 2n * Z2);
    var E = mod25519(B - A);
    var F = mod25519(D - C);
    var G = mod25519(D + C);
    var H = mod25519(B + A);
    return [mod25519(E * F), mod25519(G * H), mod25519(F * G), mod25519(E * H)];
  }
  function edDouble(P) {
    var X1 = P[0], Y1 = P[1], Z1 = P[2];
    var A = mod25519(X1 * X1);
    var B = mod25519(Y1 * Y1);
    var C = mod25519(2n * Z1 * Z1);
    var H = mod25519(A + B);
    var E = mod25519(H - mod25519((X1 + Y1) * (X1 + Y1)));
    var G = mod25519(A - B); // a = -1
    var F = mod25519(C + G);
    return [mod25519(E * F), mod25519(G * H), mod25519(F * G), mod25519(E * H)];
  }
  var ED_IDENTITY = [0n, 1n, 1n, 0n];
  function edScalarMult(scalarBytesLE, P) {
    var n = U.bytesToBigIntLE(scalarBytesLE);
    var R = ED_IDENTITY, Q = P;
    while (n > 0n) {
      if (n & 1n) R = edAdd(R, Q);
      Q = edDouble(Q);
      n >>= 1n;
    }
    return R;
  }
  function edBasePoint() {
    var y = mod25519(4n * (function () {
      var a = 5n, m = P25519, e = m - 2n, r = 1n;
      while (e > 0n) { if (e & 1n) r = (r * a) % m; a = (a * a) % m; e >>= 1n; }
      return r;
    })());
    var x = recoverX(y, 0);
    return [x, y, 1n, mod25519(x * y)];
  }
  var ED_B = null;
  function recoverX(y, signBit) {
    var y2 = mod25519(y * y);
    var x2 = mod25519((y2 - 1n) * inv25519(mod25519(D_ED * y2 + 1n)));
    if (x2 === 0n && signBit) throw new Error('Ed25519: 无效的点编码');
    var x = powmod25519(x2, (P25519 + 3n) / 8n);
    if (mod25519(x * x - x2) !== 0n) {
      x = mod25519(x * I_ED);
      if (mod25519(x * x - x2) !== 0n) throw new Error('Ed25519: 点不在曲线上');
    }
    if ((x & 1n) !== BigInt(signBit)) x = mod25519(-x);
    return x;
  }
  function edDecodePoint(b) {
    if (b.length !== 32) throw new Error('Ed25519: 公钥长度错误');
    var yb = new Uint8Array(b);
    var sign = (yb[31] >> 7) & 1;
    yb[31] &= 0x7f;
    var y = U.bytesToBigIntLE(yb);
    var x = recoverX(y, sign);
    return [x, y, 1n, mod25519(x * y)];
  }
  function edEncodePoint(P) {
    var zi = inv25519(P[2]);
    var x = mod25519(P[0] * zi);
    var y = mod25519(P[1] * zi);
    var out = U.bigIntToBytesLE(y, 32);
    if (x & 1n) out[31] |= 0x80;
    return out;
  }
  function edPointEqual(P, Q) {
    // X1*Z2 == X2*Z1 && Y1*Z2 == Y2*Z1
    return mod25519(P[0] * Q[2]) === mod25519(Q[0] * P[2]) &&
           mod25519(P[1] * Q[2]) === mod25519(Q[1] * P[2]);
  }
  function clampEdScalar(b) {
    b[0] &= 248; b[31] &= 127; b[31] |= 64;
  }
  function hashModL(data) {
    return digest('sha512', data).then(function (h) {
      return U.bytesToBigIntLE(h) % L_ED;
    });
  }

  function ed25519Sign(msg, seed32) {
    if (!ED_B) ED_B = edBasePoint();
    return digest('sha512', seed32).then(function (h) {
      var aBytes = new Uint8Array(h.subarray(0, 32));
      var prefix = h.subarray(32, 64);
      clampEdScalar(aBytes);
      var A = edScalarMult(aBytes, ED_B);
      var encA = edEncodePoint(A);
      return hashModL(U.concat(prefix, msg)).then(function (r) {
        var R = edScalarMult(U.bigIntToBytesLE(r, 32), ED_B);
        var encR = edEncodePoint(R);
        return hashModL(U.concat(encR, encA, msg)).then(function (k) {
          var a = U.bytesToBigIntLE(aBytes);
          var S = (r + k * a) % L_ED;
          return U.concat(encR, U.bigIntToBytesLE(S, 32));
        });
      });
    });
  }

  function ed25519Verify(msg, sig64, pub32) {
    if (!ED_B) ED_B = edBasePoint();
    try {
      if (sig64.length !== 64) return Promise.resolve(false);
      var R = edDecodePoint(sig64.subarray(0, 32));
      var A = edDecodePoint(pub32);
      var S = U.bytesToBigIntLE(sig64.subarray(32, 64));
      if (S >= L_ED) return Promise.resolve(false);
      return hashModL(U.concat(sig64.subarray(0, 32), pub32, msg)).then(function (k) {
        var sB = edScalarMult(sig64.subarray(32, 64), ED_B);
        var kA = edScalarMult(U.bigIntToBytesLE(k, 32), A);
        var rhs = edAdd(R, kA);
        return edPointEqual(sB, rhs);
      });
    } catch (e) {
      return Promise.resolve(false);
    }
  }

  function ed25519PublicFromSeed(seed32) {
    if (!ED_B) ED_B = edBasePoint();
    return digest('sha512', seed32).then(function (h) {
      var aBytes = new Uint8Array(h.subarray(0, 32));
      clampEdScalar(aBytes);
      return edEncodePoint(edScalarMult(aBytes, ED_B));
    });
  }

  /* ======================================================================
   * bcrypt_pbkdf — 移植 OpenBSD（Blowfish 盒子表 + KDF），SHA-512 用 WebCrypto
   * 源码：bcrypt-pbkdf npm 包 (ISC/BSD，Joyent/Devi Mandiri 移植)
   * ====================================================================== */
  var BLF_J = 0;
  var Blowfish = function () {
    this.S = [
      new Uint32Array([
        0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
        0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
        0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
        0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
        0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
        0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
        0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
        0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
        0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
        0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
        0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
        0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
        0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
        0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
        0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
        0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
        0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3, 0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
        0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
        0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
        0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
        0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
        0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
        0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4, 0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
        0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
        0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
        0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
        0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
        0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
        0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
        0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
        0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
        0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664, 0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a]),
      new Uint32Array([
        0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
        0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
        0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
        0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
        0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
        0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
        0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
        0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
        0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
        0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
        0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c, 0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
        0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
        0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
        0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
        0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
        0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
        0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
        0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802, 0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
        0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
        0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
        0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
        0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
        0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
        0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
        0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
        0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105, 0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
        0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
        0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
        0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
        0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
        0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
        0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7]),
      new Uint32Array([
        0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
        0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
        0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
        0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
        0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
        0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
        0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
        0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
        0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
        0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
        0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
        0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
        0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
        0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
        0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
        0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
        0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
        0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
        0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
        0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
        0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
        0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
        0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
        0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
        0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
        0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
        0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
        0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
        0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
        0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
        0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
        0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837, 0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0]),
      new Uint32Array([
        0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
        0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b, 0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
        0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
        0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
        0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4, 0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
        0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
        0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
        0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
        0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
        0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
        0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a, 0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
        0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
        0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
        0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680, 0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
        0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
        0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
        0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370, 0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
        0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
        0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
        0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
        0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
        0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
        0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
        0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
        0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
        0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
        0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
        0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
        0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
        0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
        0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
        0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f, 0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6])
    ];
    this.P = new Uint32Array([
      0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
      0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
      0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b]);
  };

  function blF(S, x8, i) {
    return (((S[0][x8[i + 3]] + S[1][x8[i + 2]]) ^ S[2][x8[i + 1]]) + S[3][x8[i]]);
  }
  Blowfish.prototype.encipher = function (x, x8) {
    if (x8 === undefined) {
      x8 = new Uint8Array(x.buffer);
      if (x.byteOffset !== 0) x8 = x8.subarray(x.byteOffset);
    }
    x[0] ^= this.P[0];
    for (var i = 1; i < 16; i += 2) {
      x[1] ^= blF(this.S, x8, 0) ^ this.P[i];
      x[0] ^= blF(this.S, x8, 4) ^ this.P[i + 1];
    }
    var t = x[0];
    x[0] = x[1] ^ this.P[17];
    x[1] = t;
  };
  function stream2word(data, databytes) {
    var i, temp = 0;
    for (i = 0; i < 4; i++, BLF_J++) {
      if (BLF_J >= databytes) BLF_J = 0;
      temp = (temp << 8) | data[BLF_J];
    }
    return temp;
  }
  Blowfish.prototype.expand0state = function (key, keybytes) {
    var d = new Uint32Array(2), i, k;
    var d8 = new Uint8Array(d.buffer);
    for (i = 0, BLF_J = 0; i < 18; i++) this.P[i] ^= stream2word(key, keybytes);
    BLF_J = 0;
    for (i = 0; i < 18; i += 2) {
      this.encipher(d, d8);
      this.P[i] = d[0]; this.P[i + 1] = d[1];
    }
    for (i = 0; i < 4; i++) {
      for (k = 0; k < 256; k += 2) {
        this.encipher(d, d8);
        this.S[i][k] = d[0]; this.S[i][k + 1] = d[1];
      }
    }
  };
  Blowfish.prototype.expandstate = function (data, databytes, key, keybytes) {
    var d = new Uint32Array(2), i, k;
    var d8 = new Uint8Array(d.buffer);
    for (i = 0, BLF_J = 0; i < 18; i++) this.P[i] ^= stream2word(key, keybytes);
    for (i = 0, BLF_J = 0; i < 18; i += 2) {
      d[0] ^= stream2word(data, databytes);
      d[1] ^= stream2word(data, databytes);
      this.encipher(d, d8);
      this.P[i] = d[0]; this.P[i + 1] = d[1];
    }
    for (i = 0; i < 4; i++) {
      for (k = 0; k < 256; k += 2) {
        d[0] ^= stream2word(data, databytes);
        d[1] ^= stream2word(data, databytes);
        this.encipher(d, d8);
        this.S[i][k] = d[0]; this.S[i][k + 1] = d[1];
      }
    }
    BLF_J = 0;
  };
  Blowfish.prototype.enc = function (data, blocks) {
    for (var i = 0; i < blocks; i++) this.encipher(data.subarray(i * 2));
  };

  function bcryptHash(sha2pass, sha2salt, out) {
    var state = new Blowfish(),
      cdata = new Uint32Array(8), i,
      ciphertext = new Uint8Array([79, 120, 121, 99, 104, 114, 111, 109, 97, 116, 105, 99, 66, 108, 111,
        119, 102, 105, 115, 104, 83, 119, 97, 116, 68, 121, 110, 97, 109, 105, 116, 101]);
    state.expandstate(sha2salt, 64, sha2pass, 64);
    for (i = 0; i < 64; i++) {
      state.expand0state(sha2salt, 64);
      state.expand0state(sha2pass, 64);
    }
    for (i = 0; i < 8; i++) cdata[i] = stream2word(ciphertext, ciphertext.length);
    for (i = 0; i < 64; i++) state.enc(cdata, cdata.byteLength / 8);
    for (i = 0; i < 8; i++) {
      out[4 * i + 3] = cdata[i] >>> 24;
      out[4 * i + 2] = cdata[i] >>> 16;
      out[4 * i + 1] = cdata[i] >>> 8;
      out[4 * i + 0] = cdata[i];
    }
  }

  function sha512Into(dst, src) {
    return digest('sha512', src).then(function (h) { dst.set(h); });
  }

  // pass/salt/key: Uint8Array；返回 Promise
  function bcryptPbkdf(pass, salt, key, rounds) {
    var sha2pass = new Uint8Array(64),
      sha2salt = new Uint8Array(64),
      out = new Uint8Array(32),
      tmpout = new Uint8Array(32),
      countsalt = new Uint8Array(salt.length + 4),
      i, j, amt, stride, dest, count,
      keylen = key.length, origkeylen = key.length;
    for (i = 0; i < salt.length; i++) countsalt[i] = salt[i];
    return sha512Into(sha2pass, pass).then(function loop() {
      if (rounds < 1 || pass.length === 0 || salt.length === 0 || keylen === 0 ||
        keylen > 1024 || salt.length > (1 << 20)) {
        return Promise.reject(new Error('bcrypt_pbkdf 参数错误'));
      }
      stride = Math.floor((keylen + 31) / 32);
      amt = Math.floor((keylen + stride - 1) / stride);

      function runCount() {
        if (keylen <= 0) return Promise.resolve();
        countsalt[salt.length + 0] = count >>> 24;
        countsalt[salt.length + 1] = count >>> 16;
        countsalt[salt.length + 2] = count >>> 8;
        countsalt[salt.length + 3] = count;
        return sha512Into(sha2salt, countsalt.subarray(0, salt.length + 4)).then(function () {
          bcryptHash(sha2pass, sha2salt, tmpout);
          out.set(tmpout);
          var r = 1;
          function round() {
            if (r >= rounds) return Promise.resolve();
            return sha512Into(sha2salt, tmpout).then(function () {
              bcryptHash(sha2pass, sha2salt, tmpout);
              for (j = 0; j < 32; j++) out[j] ^= tmpout[j];
              r++;
              return round();
            });
          }
          return round().then(function () {
            var used = Math.min(amt, keylen);
            for (i = 0; i < used; i++) {
              dest = i * stride + (count - 1);
              if (dest >= origkeylen) break;
              key[dest] = out[i];
            }
            keylen -= i;
            count++;
            return runCount();
          });
        });
      }
      count = 1;
      return runCount();
    });
  }

  /* ======================================================================
   * MD5（RFC 1321）纯 JS —— 仅用于老式加密 PEM 的 EVP_BytesToKey
   * ====================================================================== */
  function md5(data) {
    function rl(n, c) { return (n << c) | (n >>> (32 - c)); }
    function cmn(q, a, b, x, s, t) {
      a = (((a + q) + x) + t) | 0;
      return ((a << s) | (a >>> (32 - s))) + b;
    }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }

    var bytes = data instanceof Uint8Array ? data : U.strToBytes(data);
    var origLen = bytes.length;
    var padLen = (origLen % 64 < 56) ? (56 - origLen % 64) : (120 - origLen % 64);
    var msg = new Uint8Array(origLen + padLen + 8);
    msg.set(bytes);
    msg[origLen] = 0x80;
    var bitLen = origLen * 8;
    var lo = bitLen >>> 0, hi = Math.floor(bitLen / 0x100000000);
    new DataView(msg.buffer).setUint32(msg.length - 8, lo, true);
    new DataView(msg.buffer).setUint32(msg.length - 4, hi, true);

    var a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
    for (var off = 0; off < msg.length; off += 64) {
      var x = new Int32Array(16);
      for (var j = 0; j < 16; j++) x[j] = new DataView(msg.buffer, off + j * 4, 4).getInt32(0, true);
      var oa = a, ob = b, oc = c, od = d;
      a = ff(a, b, c, d, x[0], 7, -680876936); d = ff(d, a, b, c, x[1], 12, -389564586);
      c = ff(c, d, a, b, x[2], 17, 606105819); b = ff(b, c, d, a, x[3], 22, -1044525330);
      a = ff(a, b, c, d, x[4], 7, -176418897); d = ff(d, a, b, c, x[5], 12, 1200080426);
      c = ff(c, d, a, b, x[6], 17, -1473231341); b = ff(b, c, d, a, x[7], 22, -45705983);
      a = ff(a, b, c, d, x[8], 7, 1770035416); d = ff(d, a, b, c, x[9], 12, -1958414417);
      c = ff(c, d, a, b, x[10], 17, -42063); b = ff(b, c, d, a, x[11], 22, -1990404162);
      a = ff(a, b, c, d, x[12], 7, 1804603682); d = ff(d, a, b, c, x[13], 12, -40341101);
      c = ff(c, d, a, b, x[14], 17, -1502002290); b = ff(b, c, d, a, x[15], 22, 1236535329);
      a = gg(a, b, c, d, x[1], 5, -165796510); d = gg(d, a, b, c, x[6], 9, -1069501632);
      c = gg(c, d, a, b, x[11], 14, 643717713); b = gg(b, c, d, a, x[0], 20, -373897302);
      a = gg(a, b, c, d, x[5], 5, -701558691); d = gg(d, a, b, c, x[10], 9, 38016083);
      c = gg(c, d, a, b, x[15], 14, -660478335); b = gg(b, c, d, a, x[4], 20, -405537848);
      a = gg(a, b, c, d, x[9], 5, 568446438); d = gg(d, a, b, c, x[14], 9, -1019803690);
      c = gg(c, d, a, b, x[3], 14, -187363961); b = gg(b, c, d, a, x[8], 20, 1163531501);
      a = gg(a, b, c, d, x[13], 5, -1444681467); d = gg(d, a, b, c, x[2], 9, -51403784);
      c = gg(c, d, a, b, x[7], 14, 1735328473); b = gg(b, c, d, a, x[12], 20, -1926607734);
      a = hh(a, b, c, d, x[5], 4, -378558); d = hh(d, a, b, c, x[8], 11, -2022574463);
      c = hh(c, d, a, b, x[11], 16, 1839030562); b = hh(b, c, d, a, x[14], 23, -35309556);
      a = hh(a, b, c, d, x[1], 4, -1530992060); d = hh(d, a, b, c, x[4], 11, 1272893353);
      c = hh(c, d, a, b, x[7], 16, -155497632); b = hh(b, c, d, a, x[10], 23, -1094730640);
      a = hh(a, b, c, d, x[13], 4, 681279174); d = hh(d, a, b, c, x[0], 11, -358537222);
      c = hh(c, d, a, b, x[3], 16, -722521979); b = hh(b, c, d, a, x[6], 23, 76029189);
      a = hh(a, b, c, d, x[9], 4, -640364487); d = hh(d, a, b, c, x[12], 11, -421815835);
      c = hh(c, d, a, b, x[15], 16, 530742520); b = hh(b, c, d, a, x[2], 23, -995338651);
      a = ii(a, b, c, d, x[0], 6, -198630844); d = ii(d, a, b, c, x[7], 10, 1126891415);
      c = ii(c, d, a, b, x[14], 15, -1416354905); b = ii(b, c, d, a, x[5], 21, -57434055);
      a = ii(a, b, c, d, x[12], 6, 1700485571); d = ii(d, a, b, c, x[3], 10, -1894986606);
      c = ii(c, d, a, b, x[10], 15, -1051523); b = ii(b, c, d, a, x[1], 21, -2054922799);
      a = ii(a, b, c, d, x[8], 6, 1873313359); d = ii(d, a, b, c, x[15], 10, -30611744);
      c = ii(c, d, a, b, x[6], 15, -1560198380); b = ii(b, c, d, a, x[13], 21, 1309151649);
      a = ii(a, b, c, d, x[4], 6, -145523070); d = ii(d, a, b, c, x[11], 10, -1120210379);
      c = ii(c, d, a, b, x[2], 15, 718787259); b = ii(b, c, d, a, x[9], 21, -343485551);
      a = (a + oa) | 0; b = (b + ob) | 0; c = (c + oc) | 0; d = (d + od) | 0;
    }
    var out = new Uint8Array(16);
    var dv = new DataView(out.buffer);
    dv.setInt32(0, a, true); dv.setInt32(4, b, true);
    dv.setInt32(8, c, true); dv.setInt32(12, d, true);
    return Promise.resolve(out);
  }

  WSSH.crypto = {
    randomBytes: randomBytes,
    digest: digest,
    digestParts: digestParts,
    hmac: hmac,
    md5: md5,
    aesCTR: aesCTR,
    aesGCMEncrypt: aesGCMEncrypt,
    aesGCMDecrypt: aesGCMDecrypt,
    aesCBCEncrypt: aesCBCEncrypt,
    aesCBCDecrypt: aesCBCDecrypt,
    pbkdf2: pbkdf2,
    EC_INFO: EC_INFO,
    ecdhGenerate: ecdhGenerate,
    ecdhAgree: ecdhAgree,
    derToRS: derToRS,
    rsToDer: rsToDer,
    ecdsaVerify: ecdsaVerify,
    ecdsaSign: ecdsaSign,
    rsaVerify: rsaVerify,
    rsaSign: rsaSign,
    x25519: x25519,
    x25519Base: x25519Base,
    ed25519Sign: ed25519Sign,
    ed25519Verify: ed25519Verify,
    ed25519PublicFromSeed: ed25519PublicFromSeed,
    bcryptPbkdf: bcryptPbkdf
  };
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
