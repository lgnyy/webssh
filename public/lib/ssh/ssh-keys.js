/*!
 * ssh-keys.js - 私钥解析与签名
 * 支持：
 *   - OpenSSH 新格式 (BEGIN OPENSSH PRIVATE KEY)：ed25519 / ecdsa / rsa，
 *     口令使用 bcrypt-pbkdf + aes{128,256}-ctr/gcm
 *   - PEM：RSA PKCS#1、PKCS#8（含 PBES2 加密）、EC SEC1、Ed25519 PKCS#8
 *   - 老式加密 PEM (Proc-Type + DEK-Info: AES-*-CBC, EVP_BytesToKey/MD5)
 */
(function (global) {
  'use strict';
  var WSSH = global.WSSH || (global.WSSH = {});
  var U = WSSH.util;
  var C = WSSH.crypto;

  /* ================= DER 解析 ================= */
  function derNodes(buf) {
    var nodes = [], off = 0;
    while (off < buf.length) {
      var start = off;
      var tag = buf[off++];
      var len = buf[off++];
      if (len & 0x80) {
        var n = len & 0x7f;
        len = 0;
        while (n--) len = (len << 8) | buf[off++];
      }
      var content = buf.subarray(off, off + len);
      off += len;
      nodes.push({ tag: tag, content: content, hdrLen: off - start - len });
    }
    return nodes;
  }
  function derFirst(buf) {
    var ns = derNodes(buf);
    if (ns.length !== 1) throw new Error('DER: 期望单个 TLV');
    return ns[0];
  }
  function derChildren(node) { return derNodes(node.content); }
  function derInt(node) {
    return U.bytesToBigIntBE(node.content);
  }
  var OID = {
    RSA: '1.2.840.113549.1.1.1',
    EC: '1.2.840.10045.2.1',
    ED25519: '1.3.101.112',
    P256: '1.2.840.10045.3.1.7',
    P384: '1.3.132.0.34',
    P521: '1.3.132.0.35',
    PBES2: '1.2.840.113549.1.5.13',
    PBKDF2: '1.2.840.113549.1.5.12',
    HMAC_SHA1: '1.2.840.113549.2.7',
    HMAC_SHA256: '1.2.840.113549.2.9',
    HMAC_SHA384: '1.2.840.113549.2.10',
    HMAC_SHA512: '1.2.840.113549.2.11',
    AES128_CBC: '2.16.840.1.101.3.4.1.2',
    AES192_CBC: '2.16.840.1.101.3.4.1.22',
    AES256_CBC: '2.16.840.1.101.3.4.1.42'
  };
  function derOid(node) {
    var b = node.content;
    var vals = [];
    var v = 0, first = true, cur = 0;
    for (var i = 0; i < b.length; i++) {
      cur = (cur << 7) | (b[i] & 0x7f);
      if (!(b[i] & 0x80)) {
        if (first) {
          vals.push(Math.floor(cur / 40));
          vals.push(cur % 40);
          first = false;
        } else vals.push(cur);
        cur = 0;
      }
    }
    return vals.join('.');
  }

  /* ================= 私钥对象 ================= */
  // k: { type, algoNames, pubBlob, sign }
  function keyEd25519(seed, pub, comment) {
    return {
      type: 'ed25519',
      comment: comment || '',
      algoNames: ['ssh-ed25519'],
      pubBlob: function (algo) {
        var w = new U.Writer();
        w.string('ssh-ed25519').string(pub);
        return w.buffer();
      },
      sign: function (algo, data) { return C.ed25519Sign(data, seed); }
    };
  }
  function keyRSA(params, comment) {
    return {
      type: 'rsa',
      comment: comment || '',
      algoNames: ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'],
      pubBlob: function (algo) {
        var w = new U.Writer();
        w.string(algo).mpint(params.e).mpint(params.n);
        return w.buffer();
      },
      sign: function (algo, data) {
        var hash = { 'rsa-sha2-256': 'sha256', 'rsa-sha2-512': 'sha512', 'ssh-rsa': 'sha1' }[algo];
        if (!hash) throw new Error('RSA 不支持的签名算法: ' + algo);
        return C.rsaSign(hash, data, params);
      }
    };
  }
  function keyECDSA(nistName, d, Q, comment) {
    var hashByCurve = { nistp256: 'sha256', nistp384: 'sha384', nistp521: 'sha512' };
    var info = C.EC_INFO[nistName];
    return {
      type: 'ecdsa',
      nistName: nistName,
      comment: comment = comment || '',
      algoNames: ['ecdsa-sha2-' + nistName],
      pubBlob: function (algo) {
        var w = new U.Writer();
        w.string('ecdsa-sha2-' + nistName).string(nistName).string(Q);
        return w.buffer();
      },
      sign: function (algo, data) {
        var size = info.size;
        var x = Q.subarray(1, 1 + size);
        var y = Q.subarray(1 + size, 1 + 2 * size);
        var jwk = {
          x: U.base64UrlEncode(x),
          y: U.base64UrlEncode(y),
          d: U.base64UrlEncode(U.bigIntToBytesBE(d, size))
        };
        // WebCrypto ECDSA 输出定长 IEEE P1363 r||s；按曲线选哈希；
        // SSH 线网要求 string(mpint r) + string(mpint s)
        var hash = hashByCurve[nistName];
        var jwk2 = { kty: 'EC', crv: info.crv, x: jwk.x, y: jwk.y, d: jwk.d, ext: true };
        return global.crypto.subtle.importKey('jwk', jwk2, { name: 'ECDSA', namedCurve: info.crv }, false, ['sign'])
          .then(function (ck) {
            return global.crypto.subtle.sign({ name: 'ECDSA', hash: { name: hash === 'sha256' ? 'SHA-256' : hash === 'sha384' ? 'SHA-384' : 'SHA-512' } }, ck, data);
          }).then(function (raw) {
            var rs = new Uint8Array(raw);
            var w = new U.Writer();
            w.mpint(U.bytesToBigIntBE(rs.subarray(0, size)));
            w.mpint(U.bytesToBigIntBE(rs.subarray(size, size * 2)));
            return w.buffer();
          });
      }
    };
  }

  /* ================= OpenSSH 新格式 ================= */
  function parseOpenSSHFormat(bytes, passphrase) {
    var magic = U.strToBytes('openssh-key-v1');
    var magicFull = U.strToBytes('openssh-key-v1\u0000');
    var i = 0;
    // 前 15 字节应为 "openssh-key-v1\0"
    if (bytes.length < magicFull.length) throw new Error('不是有效的 OpenSSH 私钥');
    for (i = 0; i < magicFull.length; i++) if (bytes[i] !== magicFull[i]) throw new Error('不是有效的 OpenSSH 私钥');
    var r = new U.Reader(bytes.subarray(magicFull.length));
    var cipherName = U.bytesToStr(r.string());
    var kdfName = U.bytesToStr(r.string());
    var kdfOptions = r.string();
    var nkeys = r.uint32();
    if (nkeys < 1) throw new Error('OpenSSH 私钥中没有密钥');
    var pubBlob = r.string();
    var privEnc = r.string();

    var keyLen, ivLen, isGCM = false;
    switch (cipherName) {
      case 'none': keyLen = 0; ivLen = 0; break;
      case 'aes128-ctr': keyLen = 16; ivLen = 16; break;
      case 'aes256-ctr': keyLen = 32; ivLen = 16; break;
      case 'aes128-gcm@openssh.com': keyLen = 16; ivLen = 12; isGCM = true; break;
      case 'aes256-gcm@openssh.com': keyLen = 32; ivLen = 12; isGCM = true; break;
      default: throw new Error('OpenSSH 私钥使用了不支持的加密算法: ' + cipherName);
    }

    function buildFromPlain(priv) {
      var pr = new U.Reader(priv);
      var c1 = pr.uint32(), c2 = pr.uint32();
      if (c1 !== c2) {
        if (kdfName === 'none') throw new Error('OpenSSH 私钥校验失败');
        throw new Error('私钥口令错误（校验值不匹配）');
      }
      var keyType = U.bytesToStr(pr.string());
      var key;
      if (keyType === 'ssh-ed25519') {
        var pub = pr.string();
        var priv64 = pr.string();
        var comment = U.bytesToStr(pr.string());
        var seed = priv64.subarray(0, 32);
        if (priv64.length !== 64 || !U.equal(pub, priv64.subarray(32, 64))) {
          throw new Error('Ed25519 私钥内部公钥不匹配');
        }
        // 与外部公钥块再核对一次
        var pr2 = new U.Reader(pubBlob);
        var t2 = U.bytesToStr(pr2.string());
        var pubOut = pr2.string();
        if (t2 !== 'ssh-ed25519' || !U.equal(pubOut, pub)) throw new Error('Ed25519 公钥块不匹配');
        key = keyEd25519(seed, pub, comment);
      } else if (keyType === 'ssh-rsa') {
        var n = pr.mpint(), e = pr.mpint(), d = pr.mpint();
        var qi = pr.mpint(), p = pr.mpint(), q = pr.mpint();
        var commentR = U.bytesToStr(pr.string());
        var dp = (d % (p - 1n) + (p - 1n)) % (p - 1n);
        var dq = (d % (q - 1n) + (q - 1n)) % (q - 1n);
        key = keyRSA({ n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi }, commentR);
        // 核对 e,n 与公钥块
        var prr = new U.Reader(pubBlob);
        var tt = U.bytesToStr(prr.string());
        var pe = prr.mpint(), pn = prr.mpint();
        if (tt !== 'ssh-rsa' || pe !== e || pn !== n) throw new Error('RSA 公钥块不匹配');
      } else if (keyType.indexOf('ecdsa-sha2-') === 0) {
        var curve = U.bytesToStr(pr.string());
        var Q = pr.string();
        var dEC = pr.mpint();
        var commentE = U.bytesToStr(pr.string());
        key = keyECDSA(curve, dEC, Q, commentE);
      } else {
        throw new Error('不支持的私钥类型: ' + keyType);
      }
      return key;
    }

    if (cipherName === 'none' || kdfName === 'none') {
      return Promise.resolve(buildFromPlain(privEnc));
    }
    if (!passphrase) return Promise.reject(new Error('该私钥已加密，请输入私钥口令'));
    if (kdfName !== 'bcrypt') return Promise.reject(new Error('不支持的私钥 KDF: ' + kdfName));

    var kr = new U.Reader(kdfOptions);
    var salt = kr.string();
    var rounds = kr.uint32();
    var derived = new Uint8Array(keyLen + ivLen);
    return C.bcryptPbkdf(U.strToBytes(passphrase), salt, derived, rounds).then(function () {
      var key = derived.subarray(0, keyLen);
      var iv = derived.subarray(keyLen, keyLen + ivLen);
      if (isGCM) {
        var nonce = new Uint8Array(12);
        nonce.set(iv);
        // OpenSSH GCM 私钥：初始 invocation counter = 1
        var dv = new DataView(nonce.buffer);
        dv.setUint32(8, 1);
        return C.aesGCMDecrypt(key, nonce, privEnc).then(buildFromPlain);
      }
      return C.aesCTR(key, iv, privEnc, false).then(buildFromPlain);
    });
  }

  /* ================= PKCS#1 RSA ================= */
  function parsePKCS1(buf, comment) {
    var seq = derFirst(buf);
    var items = derChildren(seq);
    // version, n, e, d, p, q, dp, dq, qi
    if (items.length < 9) throw new Error('RSA PKCS#1 字段不足');
    return keyRSA({
      n: derInt(items[1]),
      e: derInt(items[2]),
      d: derInt(items[3]),
      p: derInt(items[4]),
      q: derInt(items[5]),
      dp: derInt(items[6]),
      dq: derInt(items[7]),
      qi: derInt(items[8])
    }, comment || '');
  }

  /* ================= EC SEC1 ================= */
  function parseSEC1(buf, curveOid, comment) {
    var seq = derFirst(buf);
    var items = derChildren(seq);
    // INTEGER version(1), OCTET d, [0] curve, [1] publicPoint
    var d = U.bytesToBigIntBE(items[1].content);
    var oid = curveOid;
    var Q = null;
    for (var i = 2; i < items.length; i++) {
      if (items[i].tag === 0xa0) {
        var inner = derNodes(items[i].content);
        if (inner.length && inner[0].tag === 0x06) oid = derOid(inner[0]);
      } else if (items[i].tag === 0xa1) {
        var bit = derFirst(items[i].content);
        Q = bit.content.subarray(1); // 跳过 unused-bits 字节
      }
    }
    var nist = oidToNist(oid);
    if (!Q) throw new Error('EC 私钥缺少公钥点 Q');
    return keyECDSA(nist, d, Q, comment || '');
  }

  function oidToNist(oid) {
    if (oid === OID.P256) return 'nistp256';
    if (oid === OID.P384) return 'nistp384';
    if (oid === OID.P521) return 'nistp521';
    return null;
  }

  /* ================= PKCS#8 ================= */
  function parsePKCS8(buf, comment) {
    var top = derFirst(buf);
    var parts = derChildren(top);
    // INTEGER version, SEQ algid, OCTET STRING priv
    var algId = derChildren(parts[1]);
    var oid = derOid(algId[0]);
    var inner = parts[2].content;
    if (oid === OID.RSA) {
      return parsePKCS1(inner, comment);
    }
    if (oid === OID.EC) {
      var curve = derOid(algId[1]);
      return parseSEC1(inner, curve, comment);
    }
    if (oid === OID.ED25519) {
      // CurvePrivateKey ::= OCTET STRING "0x04 0x22 0x04 0x20 || 32-byte seed"
      var oct = derFirst(inner);
      var seed = oct.content;
      if (seed.length !== 34 || seed[0] !== 0x04 || seed[1] !== 0x22) {
        // 某些实现直接包 32 字节
        if (seed.length === 32) {
          return C.ed25519PublicFromSeed(seed).then(function (pub) {
            return keyEd25519(seed, pub, comment || '');
          });
        }
        throw new Error('Ed25519 PKCS#8 内部结构错误');
      }
      var seed32 = seed.subarray(2);
      return C.ed25519PublicFromSeed(seed32).then(function (pub) {
        return keyEd25519(seed32, pub, comment || '');
      });
    }
    throw new Error('PKCS#8 中不支持的密钥算法 OID: ' + oid);
  }

  /* ================= PBES2 加密 PKCS#8 ================= */
  function parseEncryptedPKCS8(buf, passphrase) {
    if (!passphrase) return Promise.reject(new Error('该私钥已加密，请输入私钥口令'));
    var top = derFirst(buf);
    var parts = derChildren(top);
    var params = derChildren(parts[0]);
    var pbesOid = derOid(params[0]);
    if (pbesOid !== OID.PBES2) return Promise.reject(new Error('仅支持 PBES2 加密的 PKCS#8 私钥'));
    var pbesParams = derChildren(params[1]);
    // kdf: PBKDF2 params
    var kdf = derChildren(pbesParams[0]);
    if (derOid(kdf[0]) !== OID.PBKDF2) return Promise.reject(new Error('未知的 PKCS#8 KDF'));
    var kdfParamNodes = derChildren(kdf[1]);
    var salt = kdfParamNodes[0].content;
    var iters = Number(derInt(kdfParamNodes[1]));
    var prfOid = OID.HMAC_SHA256; // 默认
    var dkLen;
    for (var i = 2; i < kdfParamNodes.length; i++) {
      if (kdfParamNodes[i].tag === 0x02) dkLen = Number(derInt(kdfParamNodes[i]));
      if (kdfParamNodes[i].tag === 0x30) prfOid = derOid(derChildren(kdfParamNodes[i])[0]);
    }
    var hashName = {
      '1.2.840.113549.2.7': 'sha1',
      '1.2.840.113549.2.9': 'sha256',
      '1.2.840.113549.2.10': 'sha384',
      '1.2.840.113549.2.11': 'sha512'
    }[prfOid];
    if (!hashName) return Promise.reject(new Error('未知的 PBKDF2 PRF: ' + prfOid));

    // encryption scheme
    var enc = derChildren(pbesParams[1]);
    var encOid = derOid(enc[0]);
    var iv = enc[1].content;
    var cipherKeyLen, cipherName;
    if (encOid === OID.AES128_CBC) { cipherKeyLen = 16; cipherName = 'aes128'; }
    else if (encOid === OID.AES192_CBC) { cipherKeyLen = 24; cipherName = 'aes192'; }
    else if (encOid === OID.AES256_CBC) { cipherKeyLen = 32; cipherName = 'aes256'; }
    else return Promise.reject(new Error('PBES2 中不支持的加密算法: ' + encOid));

    var ciphertext = parts[1].content;
    return C.pbkdf2(U.strToBytes(passphrase), salt, iters, dkLen || cipherKeyLen, hashName)
      .then(function (dk) {
        return C.aesCBCDecrypt(dk.subarray(0, cipherKeyLen), iv, ciphertext);
      })
      .then(function (plain) {
        try {
          return parsePKCS8(plain, '');
        } catch (e) {
          if (/口令|password/i.test(e.message)) throw e;
          throw new Error('私钥口令错误或内容损坏（解密后 DER 无效）');
        }
      });
  }

  /* ================= 老式加密 PEM (AES-CBC + EVP_BytesToKey) ================= */
  // EVP_BytesToKey(MD5, 1 轮)：D_i = MD5(D_{i-1} || password || salt8)
  // 老式 PEM 只用它推导密钥本身（IV 由 DEK-Info 给出），salt 固定前 8 字节
  function evpBytesToKey(password, salt8, keyLen) {
    var pw = U.strToBytes(password);
    var out = new Uint8Array(keyLen);
    var pos = 0;
    function round(n, prevD) {
      if (n === 0) return Promise.resolve();
      return C.md5(U.concat(prevD, pw, salt8)).then(function (nd) {
        out.set(nd.subarray(0, Math.min(16, out.length - pos)), pos);
        pos += nd.length;
        return round(n - 1, nd);
      });
    }
    return round(Math.ceil(keyLen / 16), new Uint8Array(0)).then(function () { return out; });
  }

  function parseLegacyEncryptedPEM(der, headers, passphrase) {
    if (!passphrase) return Promise.reject(new Error('该私钥已加密，请输入私钥口令'));
    var dek = headers['DEK-Info'] || headers['dek-info'];
    if (!dek) return Promise.reject(new Error('加密 PEM 缺少 DEK-Info 头'));
    var parts = dek.split(',').map(function (s) { return s.trim(); });
    var alg = parts[0].toUpperCase();
    var ivHex = parts[1];
    var iv = new Uint8Array(ivHex.replace(/\s/g, '').match(/.{2}/g).map(function (h) { return parseInt(h, 16); }));
    var map = {
      'AES-128-CBC': 16,
      'AES-192-CBC': 24,
      'AES-256-CBC': 32
    };
    var keyLen = map[alg];
    if (!keyLen) {
      return Promise.reject(new Error('老式加密 PEM 使用了不支持的算法 ' + alg + '，请转换：ssh-keygen -p -m PEM -Z aes256'));
    }
    // DEK-Info 给出完整 IV（16 字节）；KDF salt 只取前 8 字节
    var salt = iv.subarray(0, 8);
    return evpBytesToKey(passphrase, salt, keyLen).then(function (key) {
      return C.aesCBCDecrypt(key, iv, der).catch(function () {
        throw new Error('私钥口令错误或内容损坏');
      });
    }).then(function (plain) {
      try {
        return parsePEMDer(plain, passphrase, '');
      } catch (e) {
        if (/口令错误/.test(e.message)) throw e;
        throw new Error('私钥口令错误或内容损坏');
      }
    });
  }

  /* ================= PEM 入口 ================= */
  function parsePEMDer(der, passphrase, comment) {
    var top = derNodes(der)[0];
    if (top.tag !== 0x30) throw new Error('无法识别的 DER 私钥结构 (tag=' + top.tag + ')');
    var ch = derChildren(top);
    // EncryptedPrivateKeyInfo: SEQ{ SEQ{ OID ... }, OCTET STRING data }
    if (ch.length === 2 && ch[0].tag === 0x30 && ch[1].tag === 0x04) {
      var sub = derChildren(ch[0]);
      if (sub.length >= 1 && sub[0].tag === 0x06) {
        return parseEncryptedPKCS8(der, passphrase);
      }
    }
    // PrivateKeyInfo(PKCS#8): SEQ{ INTEGER 0, SEQ algid, OCTET STRING priv }
    if (ch.length >= 3 && ch[0].tag === 0x02 && ch[1].tag === 0x30 && ch[2].tag === 0x04) {
      return parsePKCS8(der, comment || '');
    }
    // RSAPrivateKey(PKCS#1): version,n,e,d,p,q,dp,dq,qi 全是 INTEGER
    if (ch.length >= 9 && ch[1].tag === 0x02) {
      return parsePKCS1(der, comment || '');
    }
    // ECPrivateKey(SEC1): SEQ{ INTEGER 1, OCTET STRING d, ... }
    if (ch.length >= 2 && ch[0].tag === 0x02 && ch[1].tag === 0x04) {
      return parseSEC1(der, null, comment || '');
    }
    throw new Error('无法识别的 DER 私钥结构');
  }

  function parsePEM(text, passphrase, filename) {
    var text2 = text.replace(/\r\n/g, '\n');
    var blocks = [];
    var re = /-----BEGIN ([^-]+)-----\n([\s\S]*?)\n-----END \1-----/g;
    var m;
    while ((m = re.exec(text2)) !== null) {
      blocks.push({ label: m[1].trim(), body: m[2] });
    }
    if (!blocks.length) throw new Error('未找到 PEM/OpenSSH 私钥块');
    var b = blocks[0];
    var label = b.label;

    if (label === 'OPENSSH PRIVATE KEY') {
      var der = U.base64Decode(b.body);
      return parseOpenSSHFormat(der, passphrase);
    }

    // 头部（Proc-Type / DEK-Info）
    var headers = {};
    var body = b.body;
    var lines = body.split('\n');
    var hdrEnd = 0;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (line === '') { hdrEnd = i + 1; break; }
      var colon = line.indexOf(':');
      if (colon > 0) headers[line.substr(0, colon).trim()] = line.substr(colon + 1).trim();
      else break;
    }
    var base64Body = lines.slice(headers['Proc-Type'] ? hdrEnd : 0).join('\n');
    var derBytes = U.base64Decode(base64Body);
    var comment = filename || '';

    if (headers['Proc-Type']) {
      return parseLegacyEncryptedPEM(derBytes, headers, passphrase);
    }

    if (label === 'RSA PRIVATE KEY') return Promise.resolve(parsePKCS1(derBytes, comment));
    if (label === 'EC PRIVATE KEY') return Promise.resolve(parseSEC1(derBytes, null, comment));
    if (label === 'PRIVATE KEY') return Promise.resolve(parsePKCS8(derBytes, comment));
    if (label === 'ENCRYPTED PRIVATE KEY') return parseEncryptedPKCS8(derBytes, passphrase);
    if (label === 'DSA PRIVATE KEY') return Promise.reject(new Error('DSA 私钥不受支持（现代 SSH 服务器默认已禁用 DSA）'));
    return Promise.reject(new Error('不支持的私钥类型: ' + label));
  }

  function parsePrivateKey(input, passphrase, filename) {
    if (input instanceof Uint8Array) input = U.bytesToStr(input);
    if (typeof input !== 'string') return Promise.reject(new Error('私钥必须是文本内容'));
    try {
      return parsePEM(input, passphrase, filename);
    } catch (e) {
      return Promise.reject(e);
    }
  }

  /* ================= 公钥 blob 解析（指纹/主机密钥用） ================= */
  function parsePubBlob(blob) {
    var r = new U.Reader(blob);
    var type = U.bytesToStr(r.string());
    if (type === 'ssh-rsa' || type === 'rsa-sha2-256' || type === 'rsa-sha2-512') {
      var e = r.mpint(), n = r.mpint();
      return { type: type, n: n, e: e };
    }
    if (type === 'ssh-ed25519') {
      return { type: type, A: r.string() };
    }
    if (type.indexOf('ecdsa-sha2-') === 0) {
      var curve = U.bytesToStr(r.string());
      var Q = r.string();
      return { type: type, curve: curve, Q: Q };
    }
    throw new Error('不支持的主机公钥类型: ' + type);
  }

  WSSH.keys = {
    parsePrivateKey: parsePrivateKey,
    parsePubBlob: parsePubBlob,
    OID: OID
  };
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
