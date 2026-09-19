/*!
 * ssh-client.js - 纯浏览器 SSH 传输层/连接层
 * 参考 Node.js ssh2 模块的协议流程，全部密码学基于浏览器 WebCrypto + ssh-crypto.js
 * * 报文格式、密钥交换、NEWKEYS 切换、密码/公钥/keyboard-interactive 认证、
 * session channel(pty + shell)、窗口调整与 rekey。
 */
(function (global) {
  'use strict';
  var WSSH = global.WSSH || (global.WSSH = {});
  var U = WSSH.util;
  var C = WSSH.crypto;
  var K = WSSH.keys;

  var MSG = {
    DISCONNECT: 1, IGNORE: 2, UNIMPLEMENTED: 3, DEBUG: 4,
    SERVICE_REQUEST: 5, SERVICE_ACCEPT: 6, EXT_INFO: 7,
    KEXINIT: 20, NEWKEYS: 21,
    KEX_ECDH_INIT: 30, KEX_ECDH_REPLY: 31,
    USERAUTH_REQUEST: 50, USERAUTH_FAILURE: 51, USERAUTH_SUCCESS: 52,
    USERAUTH_BANNER: 53, USERAUTH_INFO_REQUEST: 60, USERAUTH_INFO_RESPONSE: 61,
    GLOBAL_REQUEST: 80, REQUEST_SUCCESS: 81, REQUEST_FAILURE: 82,
    CHANNEL_OPEN: 90, CHANNEL_OPEN_CONFIRMATION: 91, CHANNEL_OPEN_FAILURE: 92,
    CHANNEL_WINDOW_ADJUST: 93, CHANNEL_DATA: 94, CHANNEL_EXTENDED_DATA: 95,
    CHANNEL_EOF: 96, CHANNEL_CLOSE: 97, CHANNEL_REQUEST: 98,
    CHANNEL_SUCCESS: 99, CHANNEL_FAILURE: 100
  };

  var DEFAULT_KEX = [
    'curve25519-sha256', 'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'
  ];
  var DEFAULT_HOSTKEY = [
    'ssh-ed25519',
    'rsa-sha2-512', 'rsa-sha2-256',
    'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256',
    'ssh-rsa'
  ];
  var DEFAULT_CIPHER = [
    'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
    'aes256-ctr', 'aes192-ctr', 'aes128-ctr'
  ];
  var DEFAULT_MAC = [
    'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com',
    'hmac-sha2-512', 'hmac-sha2-256'
  ];

  var CIPHER_INFO = {
    'aes128-ctr': { key: 16, iv: 16, block: 16, mode: 'ctr' },
    'aes192-ctr': { key: 24, iv: 16, block: 16, mode: 'ctr' },
    'aes256-ctr': { key: 32, iv: 16, block: 16, mode: 'ctr' },
    'aes128-gcm@openssh.com': { key: 16, iv: 12, block: 16, mode: 'gcm' },
    'aes256-gcm@openssh.com': { key: 32, iv: 12, block: 16, mode: 'gcm' }
  };
  var MAC_INFO = {
    'hmac-sha2-256': { key: 32, len: 32, hash: 'sha256', etm: false },
    'hmac-sha2-512': { key: 64, len: 64, hash: 'sha512', etm: false },
    'hmac-sha2-256-etm@openssh.com': { key: 32, len: 32, hash: 'sha256', etm: true },
    'hmac-sha2-512-etm@openssh.com': { key: 64, len: 64, hash: 'sha512', etm: true }
  };

  function SSHClient() {
    this._inBuf = new Uint8Array(0);
    this._inWaiter = null;
    this._outChain = Promise.resolve();
    this._seqOut = 0;
    this._seqIn = 0;
    this._state = 'init';
    this._channels = {};
    this._chanSeq = 0;
    this._closed = false;
  }

  /* ================= 连接入口 ================= */
  SSHClient.prototype.connect = function (opts) {
    var self = this;
    self.opts = opts;
    self.stream = opts.stream;
    self.username = opts.username || 'root';
    self._failed = false;
    self._authenticated = false;
    self._serverHostAlgos = null;
    // 绑定底层流（WebSocket 包装器）事件
    self.stream.onmessage = function (data) { self._feed(data); };
    self.stream.onclose = function () { self._onStreamClose(); };
    self.stream.onerror = function (e) {
      self._fail(e instanceof Error ? e : new Error('底层连接发生错误'));
    };
    self.clientIdent = 'SSH-2.0-WSSH_1.0';
    self.lists = {
      kex: (opts.algorithms && opts.algorithms.kex) || DEFAULT_KEX.slice(),
      hostkey: (opts.algorithms && opts.algorithms.serverHostKey) || DEFAULT_HOSTKEY.slice(),
      cipher: (opts.algorithms && opts.algorithms.cipher) || DEFAULT_CIPHER.slice(),
      mac: (opts.algorithms && opts.algorithms.mac) || DEFAULT_MAC.slice()
    };
    self._kexCS = null;
    self._kexSC = null;
    self._newKeysIn = null;
    self._newKeysOut = null;
    self._sessionId = null;
    self._kexSecret = null;
    self._kexReplyResolve = null;
    self._newKeysResolve = null;
    self._serviceResolve = null;
    self._authResolve = null;
    self._kbdResolve = null;
    self._chanReplies = {};

    return self._run();
  };

  SSHClient.prototype._fail = function (err) {
    if (this._failed) return;
    this._failed = true;
    if (this._readyReject && !this._authenticated) {
      var rj = this._readyReject;
      this._readyReject = null;
      this._readyResolve = null;
      rj(err);
    } else if (this.opts.onClose) {
      this.opts.onClose(err);
    }
    Object.keys(this._chanReplies).forEach((function (map) {
      return function (k) {
        var r = map[k]; delete map[k]; r({ type: -1, error: err });
      };
    })(this._chanReplies));
    this._closed = true;
  };

  SSHClient.prototype._onStreamClose = function () {
    this._closed = true;
    // 唤醒可能正在等待数据的读循环，使其按“已关闭”退出
    if (this._inWaiter) {
      var w = this._inWaiter;
      this._inWaiter = null;
      w();
    }
    this._fail(new Error('连接已关闭'));
  };

  SSHClient.prototype.disconnect = function (reasonText) {
    if (this._closed) return Promise.resolve();
    var self = this;
    var w = new U.Writer();
    w.byte(MSG.DISCONNECT).uint32(11).string(reasonText || 'Bye Bye').string('en');
    return self._sendPayload(w.buffer()).then(function () {
      self._closed = true;
      try { self.stream.close && self.stream.close(); } catch (e) { }
    }).catch(function () {
      self._closed = true;
      try { self.stream.close && self.stream.close(); } catch (e) { }
    });
  };

  /* ================= 字节流入队/读取 ================= */
  SSHClient.prototype._feed = function (data) {
    if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
    if (this._inBuf.length) {
      this._inBuf = U.concat(this._inBuf, data);
    } else {
      this._inBuf = data;
    }
    if (this._inWaiter) {
      var w = this._inWaiter;
      this._inWaiter = null;
      w();
    }
  };

  SSHClient.prototype._need = function (n) {
    var self = this;
    if (self._inBuf.length >= n) return Promise.resolve();
    return new Promise(function (resolve) {
      self._inWaiter = resolve;
    }).then(function () {
      if (self._closed) throw new Error('连接已关闭');
      if (self._inBuf.length < n) return self._need(n);
    });
  };

  SSHClient.prototype._consume = function (n) {
    var out = this._inBuf.subarray(0, n);
    this._inBuf = this._inBuf.subarray(n);
    return out;
  };

  /* ================= 报文发送（加密 + MAC） ================= */
  SSHClient.prototype._enqueue = function (fn) {
    var next = this._outChain.then(fn, fn);
    // 断链不中断后续
    this._outChain = next.catch(function () { });
    return next;
  };

  function makeGcmNonce(iv, seq) {
    // RFC 5647（OpenSSH 实现）：12 字节 IV，末 8 字节（下标 4..11）为 64 位大端
    // 计数器，从派生 IV 开始每包 +1；NEWKEYS 后 seq 从 0 连续编号，故 nonce=iv+seq。
    // 注意是加法不是异或（低位有进位时两者不同）。
    var n = new Uint8Array(12);
    n.set(iv);
    var acc = seq >>> 0;
    for (var i = 11; i >= 4; i--) {
      acc += n[i];
      n[i] = acc & 0xff;
      acc >>>= 8;
    }
    return n;
  }
  // AES-CTR 计数器（16 字节，末 8 字节大端）= 派生 IV + NEWKEYS 以来累计的块数。
  // OpenSSH/ssh2 的 CTR 密钥流从派生 IV 开始连续不中断，与报文绝对序号无关。
  function makeCtrNonce(iv, blockOff) {
    var n = new Uint8Array(16);
    n.set(iv);
    var acc = blockOff >>> 0;
    for (var i = 15; i >= 8; i--) {
      acc += n[i];
      n[i] = acc & 0xff;
      acc >>>= 8;
    }
    return n;
  }
  function seqBytes(seq) {
    var b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, seq >>> 0);
    return b;
  }
  // AES-CTR 128 位计数器 +1（大端，整块递增）
  function incCounter(n) {
    var o = new Uint8Array(n);
    for (var i = o.length - 1; i >= 0; i--) {
      var v = o[i] + 1;
      o[i] = v & 0xff;
      if (v <= 0xff) break;
    }
    return o;
  }

  SSHClient.prototype._sendPayload = function (payload) {
    var self = this;
    return self._enqueue(async function () {
      var cs = self._newKeysOut;
      var info = cs ? CIPHER_INFO[cs.cipher] : null;
      var isEtm = !!(cs && cs.mac && MAC_INFO[cs.mac].etm);
      // EtM 的 CTR：长度字段不加密，仅 body 按 block 对齐；
      // 非 EtM/GCM/未加密：长度+body 整体按 block 对齐
      var blockSize = !cs ? 8 : info.block;
      var padLen;
      // GCM(RFC5647) 与 EtM：长度字段明文，只要求 body（1+payload+pad）按块对齐
      if (cs && (info.mode === 'gcm' || (info.mode === 'ctr' && isEtm))) {
        padLen = blockSize - ((1 + payload.length) % blockSize);
      } else {
        padLen = blockSize - ((4 + 1 + payload.length) % blockSize);
      }
      if (padLen < 4) padLen += blockSize;
      var padding = C.randomBytes(padLen);
      var body = U.concat(new Uint8Array([padLen]), payload, padding);
      var lenBytes = new Uint8Array(4);
      new DataView(lenBytes.buffer).setUint32(0, body.length);

      var seq = self._seqOut;
      self._seqOut++;
      var frame;

      if (!cs) {
        frame = U.concat(lenBytes, body);
      } else if (info.mode === 'gcm') {
        // RFC 5647：packet_length 明文发送并作为 AAD；GCM 只加密 body；tag 16 字节。
        // nonce 从派生 IV 起按“NEWKEYS 后的报文序号”递增（首个加密报文为 0）
        var relPkt = seq - self._seqOutAtNew;
        var nonce = makeGcmNonce(cs.iv, relPkt);
        var encBodyG = await C.aesGCMEncrypt(cs.key, nonce, body, lenBytes); // 密文 || 16 字节 tag
        frame = U.concat(lenBytes, encBodyG);
      } else if (isEtm) {
        // RFC 7366：长度明文发送，仅加密 body；MAC 覆盖 seq+明文长度+密文 body
        var ctrOffE = self._outCtrBlocks;
        var encBodyE = await C.aesCTR(cs.key, makeCtrNonce(cs.iv, ctrOffE), body, true);
        self._outCtrBlocks = ctrOffE + body.length / 16;
        var miE = MAC_INFO[cs.mac];
        var macE = await C.hmac(miE.hash, cs.macKey, U.concat(seqBytes(seq), lenBytes, encBodyE));
        frame = U.concat(lenBytes, encBodyE, macE);
      } else {
        // 普通 CTR：长度与 body 一起加密；MAC 覆盖 seq+明文长度+明文 body
        var plainAll = U.concat(lenBytes, body);
        var ctrOffN = self._outCtrBlocks;
        var encAll = await C.aesCTR(cs.key, makeCtrNonce(cs.iv, ctrOffN), plainAll, true);
        self._outCtrBlocks = ctrOffN + plainAll.length / 16;
        var mac = new Uint8Array(0);
        if (cs.mac) {
          var mi = MAC_INFO[cs.mac];
          mac = await C.hmac(mi.hash, cs.macKey, U.concat(seqBytes(seq), plainAll));
        }
        frame = mac.length ? U.concat(encAll, mac) : encAll;
      }
      self.stream.send(frame);
    });
  };

  /* ================= 报文接收（解密 + MAC 校验） ================= */
  SSHClient.prototype._recvPacket = async function () {
    var self = this;
    // NEWKEYS 已收到但慢验签导致 _doKex 尚未装好接收密钥：等待其完成，
    // 否则会把随后的加密报文误当明文解析
    if (self._newKeysInReceived && !self._newKeysInApplied) {
      await new Promise(function (resolve) { self._newKeysAppliedResolve = resolve; });
    }
    var sc = self._newKeysIn;

    if (!sc) {
      await self._need(4);
      var pktLen = new DataView(self._inBuf.buffer, self._inBuf.byteOffset, 4).getUint32(0);
      await self._need(4 + pktLen);
      var frame0 = self._consume(4 + pktLen);
      var padLen0 = frame0[4];
      self._seqIn++;
      return frame0.subarray(5, 5 + (pktLen - padLen0 - 1));
    }

    var info = CIPHER_INFO[sc.cipher];
    var seq = self._seqIn;

    if (info.mode === 'gcm') {
      // RFC 5647：前 4 字节为明文 packet_length（同时是 GCM AAD），
      // 随后 glen 字节 GCM 密文 body 与 16 字节 tag；glen 必须是 16 的倍数
      await self._need(4);
      var gLenB = self._inBuf.subarray(0, 4);
      var glen = new DataView(gLenB.buffer, gLenB.byteOffset, 4).getUint32(0);
      if (glen < 16 || glen > 360000 || (glen & 15) !== 0) {
        throw new Error('收到非法的 SSH 包长度: ' + glen);
      }
      await self._need(4 + glen + 16);
      var gframe = self._consume(4 + glen + 16);
      var gAad = gframe.subarray(0, 4);
      var gCtTag = gframe.subarray(4, 4 + glen + 16);
      var nn = makeGcmNonce(sc.iv, seq - self._seqInAtNew);
      var gbody;
      try {
        gbody = await C.aesGCMDecrypt(sc.key, nn, gCtTag, gAad);
      } catch (e) {
        throw new Error('GCM 认证失败（密钥或数据损坏）');
      }
      self._seqIn++;
      var gpad = gbody[0];
      if (gpad < 4 || gpad > glen - 1) throw new Error('SSH 包 padding 非法');
      return gbody.subarray(1, gbody.length - gpad);
    }

    var mi = sc.mac ? MAC_INFO[sc.mac] : null;

    if (mi && mi.etm) {
      // RFC 7366 EtM + CTR：packet_length 为明文，先读长度，再收密文 body，先验 MAC 再解密
      await self._need(4);
      var eLen = new DataView(this._inBuf.buffer, this._inBuf.byteOffset, 4).getUint32(0);
      if (eLen < 8 || eLen > 360000 || (eLen % info.block) !== 0) {
        throw new Error('收到非法的 SSH 包长度: ' + eLen);
      }
      await self._need(4 + eLen + mi.len);
      var eframe = self._consume(4 + eLen + mi.len);
      var eLenB = eframe.subarray(0, 4);
      var eEncBody = eframe.subarray(4, 4 + eLen);
      var eMacRecv = eframe.subarray(4 + eLen, 4 + eLen + mi.len);
      var eMacCalc = await C.hmac(mi.hash, sc.macKey, U.concat(seqBytes(seq), eLenB, eEncBody));
      if (!U.equal(eMacCalc, eMacRecv)) throw new Error('MAC 校验失败');
      var eOff = self._inCtrBlocks;
      var ebody = await C.aesCTR(sc.key, makeCtrNonce(sc.iv, eOff), eEncBody, false);
      self._inCtrBlocks = eOff + eLen / 16;
      self._seqIn++;
      var epad = ebody[0];
      if (epad < 4 || epad > eLen - 1) throw new Error('SSH 包 padding 非法');
      return ebody.subarray(1, ebody.length - epad);
    }

    // 普通 CTR：packet_length 已被加密。先在当前连续计数器处解第一个 16 字节
    // 分组窥视长度，剩余密文从计数器 +1 继续解密，整包完成后推进累计块数
    await self._need(16);
    var ctrBase = makeCtrNonce(sc.iv, self._inCtrBlocks);
    var firstPlain = await C.aesCTR(sc.key, ctrBase, this._inBuf.subarray(0, 16).slice(), false);
    var cLen = new DataView(firstPlain.buffer, firstPlain.byteOffset, 4).getUint32(0);
    if (cLen < 8 || cLen > 360000 || ((cLen + 4) % info.block) !== 0) {
      throw new Error('收到非法的 SSH 包长度: ' + cLen);
    }
    await self._need(4 + cLen + (mi ? mi.len : 0));
    var frame = self._consume(4 + cLen + (mi ? mi.len : 0));
    var restEnc = frame.subarray(16, 4 + cLen);
    var restPlain = restEnc.length
      ? await C.aesCTR(sc.key, incCounter(ctrBase), restEnc.slice(), false)
      : new Uint8Array(0);
    var plainAll = U.concat(firstPlain, restPlain); // 共 4 + cLen 字节
    var body = plainAll.subarray(4, 4 + cLen);
    var pad = body[0];
    if (pad < 4 || pad > cLen - 1) throw new Error('SSH 包 padding 非法');
    self._inCtrBlocks += (4 + cLen) / 16;

    if (mi) {
      var macRecv = frame.subarray(4 + cLen, 4 + cLen + mi.len);
      var macCalc = await C.hmac(mi.hash, sc.macKey, U.concat(seqBytes(seq), plainAll));
      if (!U.equal(macCalc, macRecv)) throw new Error('MAC 校验失败');
    }
    self._seqIn++;
    return body.subarray(1, body.length - pad);
  };

  /* ================= 主流程 ================= */
  SSHClient.prototype._run = async function () {
    var self = this;
    // 1. 版本协商
    self.stream.send(U.strToBytes(self.clientIdent + '\r\n'));
    var serverIdent = await self._readIdent();
    self.serverIdent = serverIdent;
    if (serverIdent.indexOf('SSH-2.0') !== 0) throw new Error('服务器不支持 SSH 协议 2.0: ' + serverIdent);

    // 2. 首次密钥交换（客户端先发 KEXINIT），读循环在后台驱动整个状态机
    self._state = 'kex';
    self._ready = new Promise(function (resolve, reject) {
      self._readyResolve = resolve;
      self._readyReject = reject;
    });
    self._readLoop().catch(function (e) { self._fail(e); });
    self._sendKexInit();
    return self._ready;
  };

  SSHClient.prototype._readIdent = async function () {
    var line;
    while (true) {
      var idx = -1;
      for (var i = 0; i < this._inBuf.length; i++) if (this._inBuf[i] === 0x0a) { idx = i; break; }
      if (idx >= 0) {
        line = U.bytesToStr(this._consume(idx + 1)).replace(/[\r\n]+$/, '');
        // SSH 2.0 之前可能有其他 banner 行，取最后一个 SSH- 开头行之前……实际服务器首行即 ident
        if (line.indexOf('SSH-') === 0) return line;
        if (this.opts.onBanner) this.opts.onBanner(line + '\n');
        continue;
      }
      await this._need(1);
    }
  };

  SSHClient.prototype._readLoop = async function () {
    var self = this;
    while (!self._closed) {
      var payload = await self._recvPacket();
      await self._dispatch(payload);
    }
  };

  SSHClient.prototype._sendKexInit = function () {
    var w = new U.Writer();
    w.byte(MSG.KEXINIT);
    w.bytes(C.randomBytes(16));
    w.nameList(this.lists.kex);
    w.nameList(this.lists.hostkey);
    w.nameList(this.lists.cipher);
    w.nameList(this.lists.cipher);
    w.nameList(this.lists.mac);
    w.nameList(this.lists.mac);
    w.nameList(['none']); // compression c2s
    w.nameList(['none']); // compression s2c
    w.nameList([]).nameList([]);
    w.bool(false);
    w.uint32(0);
    this._icPayload = w.buffer();
    this._sendPayload(this._icPayload);
  };

  /* ================= 报文分发 ================= */
  SSHClient.prototype._dispatch = async function (payload) {
    var self = this;
    var type = payload[0];
    var body = payload.subarray(1);

    switch (type) {
      case MSG.DISCONNECT: {
        var dr = new U.Reader(body);
        var code = dr.uint32();
        var desc = U.bytesToStr(dr.string());
        self._closed = true;
        try { self.stream.close && self.stream.close(); } catch (e) { }
        self._fail(new Error('服务器断开连接 (' + code + '): ' + desc));
        return;
      }
      case MSG.IGNORE:
      case MSG.UNIMPLEMENTED:
      case MSG.DEBUG:
        return;
      case MSG.EXT_INFO:
        return; // nr-ext-info 等扩展，忽略即可
      case MSG.KEXINIT:
        // 注意：不能 await _doKex，否则读循环被阻塞，KEX_ECDH_REPLY/NEWKEYS
        // 将永远没有机会被读取（死锁）。让交换过程浮动执行，读循环继续收包。
        if (self._kexRunning) return; // 自己发起的交换过程中收到的重复 KEXINIT
        self._isPayload = payload;
        if (!self._icPayload) self._sendKexInit();
        self._doKex(body).catch(function (e) { self._fail(e); });
        return;
      case MSG.KEX_ECDH_REPLY:
        if (self._kexReplyResolve) {
          var r = self._kexReplyResolve; self._kexReplyResolve = null;
          r(payload);
        }
        return;
      case MSG.NEWKEYS:
        // 可能在 _doKex 完成主机签名验证之前就到达（慢验签时的竞态），
        // 此时 _pendingIn/resolve 尚未建立：先打标志，由 _doKex 补处理。
        self._newKeysInReceived = true;
        self._seqInAtNew = self._seqIn;
        self._inCtrBlocks = 0;
        if (self._pendingIn) {
          self._newKeysIn = self._pendingIn;
          self._newKeysInApplied = true;
        }
        if (self._newKeysResolve) {
          var nr = self._newKeysResolve; self._newKeysResolve = null;
          nr();
        }
        if (self._newKeysAppliedResolve) {
          var ar = self._newKeysAppliedResolve; self._newKeysAppliedResolve = null;
          ar();
        }
        return;
      case MSG.SERVICE_ACCEPT:
        if (self._serviceResolve) {
          var sr = self._serviceResolve; self._serviceResolve = null;
          sr(U.bytesToStr(new U.Reader(body).string()));
        }
        return;
      case MSG.USERAUTH_BANNER:
        if (self.opts.onBanner) {
          self.opts.onBanner(U.bytesToStr(new U.Reader(body).string()) + '\n');
        }
        return;
      case MSG.USERAUTH_SUCCESS:
        self._state = 'connected';
        self._authenticated = true;
        if (self._authResolve) {
          var ar = self._authResolve; self._authResolve = null;
          ar(null);
        }
        if (self._readyResolve) {
          var rd = self._readyResolve;
          self._readyResolve = self._readyReject = null;
          rd(self);
        }
        return;
      case MSG.USERAUTH_FAILURE: {
        var fr = new U.Reader(body);
        var methods = U.bytesToStr(fr.string()).split(',').filter(Boolean);
        var partial = fr.remain() >= 1 ? fr.bool() : false;
        if (self._kbdResolve) {
          var kr = self._kbdResolve; self._kbdResolve = null;
          kr(null); // keyboard-interactive 结束但未成功
        }
        if (self._authResolve) {
          var ar2 = self._authResolve; self._authResolve = null;
          ar2({ methods: methods, partial: partial });
        }
        return;
      }
      case MSG.USERAUTH_INFO_REQUEST: {
        // byte 60, string name, string instruction, string lang, uint32 n, (string prompt, bool echo)*
        var ir = new U.Reader(body);
        var name = U.bytesToStr(ir.string());
        var instruction = U.bytesToStr(ir.string());
        U.bytesToStr(ir.string()); // lang
        var n = ir.uint32();
        var prompts = [];
        for (var i = 0; i < n; i++) {
          prompts.push({ text: U.bytesToStr(ir.string()), echo: ir.bool() });
        }
        if (self.opts.onKeyboardInteractive) {
          self.opts.onKeyboardInteractive(name, instruction, prompts).then(async function (answers) {
            var w2 = new U.Writer();
            w2.byte(MSG.USERAUTH_INFO_RESPONSE).uint32(answers.length);
            answers.forEach(function (a) { w2.string(U.strToBytes(a)); });
            await self._sendPayload(w2.buffer());
          }).catch(function (e) { self._fail(e); });
        }
        return;
      }
      case MSG.GLOBAL_REQUEST: {
        var gr = new U.Reader(body);
        U.bytesToStr(gr.string());
        var wantReply = gr.bool();
        if (wantReply) {
          await self._sendPayload(new Uint8Array([MSG.REQUEST_FAILURE]));
        }
        return;
      }
      case MSG.CHANNEL_OPEN: {
        // 不接受服务器反向通道
        var or2 = new U.Reader(body);
        U.bytesToStr(or2.string());
        var theirChan = or2.uint32();
        var w3 = new U.Writer();
        w3.byte(MSG.CHANNEL_OPEN_FAILURE).uint32(theirChan).uint32(3) // ADMINISTRATIVELY_PROHIBITED
          .string('not allowed').string('');
        await self._sendPayload(w3.buffer());
        return;
      }
      case MSG.CHANNEL_OPEN_CONFIRMATION:
      case MSG.CHANNEL_OPEN_FAILURE:
      case MSG.CHANNEL_WINDOW_ADJUST:
      case MSG.CHANNEL_DATA:
      case MSG.CHANNEL_EXTENDED_DATA:
      case MSG.CHANNEL_EOF:
      case MSG.CHANNEL_CLOSE:
      case MSG.CHANNEL_REQUEST:
      case MSG.CHANNEL_SUCCESS:
      case MSG.CHANNEL_FAILURE:
        await self._handleChannel(type, body);
        return;
      default:
        // 未知消息：忽略
        return;
    }
  };

  /* ================= 密钥交换 ================= */
  SSHClient.prototype._doKex = async function (serverInitBody) {
    var self = this;
    self._kexRunning = true;
    self._newKeysInReceived = false;
    self._newKeysInApplied = false;
    try {
      var sr = new U.Reader(U.concat(new Uint8Array([MSG.KEXINIT]), serverInitBody));
      sr.byte(); // 20
      sr.bytes(16); // cookie
      var sKex = U.bytesToStr(sr.string()).split(',');
      var sHost = U.bytesToStr(sr.string()).split(',');
      self._serverHostAlgos = sHost;
      var sCipher = U.bytesToStr(sr.string()).split(',');
      var sCipher2 = U.bytesToStr(sr.string()).split(',');
      var sMac = U.bytesToStr(sr.string()).split(',');
      var sMac2 = U.bytesToStr(sr.string()).split(',');

      var kexName = pickOne(self.lists.kex, sKex);
      var hostName = pickOne(self.lists.hostkey, sHost);
      var cipherCS = pickOne(self.lists.cipher, sCipher);
      var cipherSC = pickOne(self.lists.cipher, sCipher2);
      var macCSraw = pickOne(self.lists.mac, sMac);
      var macSCraw = pickOne(self.lists.mac, sMac2);
      if (!kexName) throw new Error('与服务器没有共同的密钥交换算法');
      if (!hostName) throw new Error('与服务器没有共同的主机密钥算法');
      if (!cipherCS || !cipherSC) throw new Error('与服务器没有共同的加密算法');
      // GCM 模式下 MAC 被忽略
      var macCS = CIPHER_INFO[cipherCS].mode === 'gcm' ? null : macCSraw;
      var macSC = CIPHER_INFO[cipherSC].mode === 'gcm' ? null : macSCraw;

      // 生成客户端临时密钥对
      var kexImpl, eph, qc, sharedBytes, hashAlg;
      if (kexName === 'curve25519-sha256' || kexName === 'curve25519-sha256@libssh.org') {
        kexImpl = 'x25519'; hashAlg = 'sha256';
        var priv = C.randomBytes(32);
        qc = C.x25519Base(priv);
        var qsBytes = null;
      } else {
        var m = kexName.match(/^ecdh-sha2-(nistp\d+)$/);
        if (!m) throw new Error('不支持的 KEX: ' + kexName);
        kexImpl = 'nist';
        var nist = m[1];
        hashAlg = { nistp256: 'sha256', nistp384: 'sha384', nistp521: 'sha512' }[nist];
        eph = await C.ecdhGenerate(nist);
        qc = eph.pubRaw; // 04||X||Y
      }

      // KEX_ECDH_INIT
      var iw = new U.Writer();
      iw.byte(MSG.KEX_ECDH_INIT).string(qc);
      await self._sendPayload(iw.buffer());

      // 等 KEX_ECDH_REPLY
      var replyP = new Promise(function (resolve) { self._kexReplyResolve = resolve; });
      var reply = await replyP;
      var rr = new U.Reader(reply.subarray(1));
      var ksBlob = rr.string();
      var qs = rr.string();
      var sigBlob = rr.string();

      // 计算共享密钥 K（mpint 编码）
      // 注意（OpenSSH/ssh2 事实约定）：X25519 输出虽是小端，但 K 的 mpint
      // 直接对原始 32 字节做大端规范化（等价 BN_bin2bn(raw,32)），不做 LE→BE
      // 反转——双方字节完全一致，协议只关心序列化结果。
      var Kbig;
      if (kexImpl === 'x25519') {
        var shared = C.x25519(priv, qs);
        Kbig = U.bytesToBigIntBE(shared);
      } else {
        var sharedX = await C.ecdhAgree(eph.privateKey, qs, nist);
        Kbig = U.bytesToBigIntBE(sharedX);
      }
      // K 的完整 wire mpint（uint32 长度前缀 + 大端有符号内容），
      // 派生密钥（RFC 4253 7.2）与交换哈希里用的都是这个完整形式
      var kmpw = new U.Writer();
      kmpw.mpint(Kbig);
      var Kmp = kmpw.buffer();

      // 构造交换哈希 H
      var hw = new U.Writer();
      hw.string(U.strToBytes(self.clientIdent));
      hw.string(U.strToBytes(self.serverIdent));
      hw.string(self._icPayload);
      hw.string(self._isPayload);
      hw.string(ksBlob);
      hw.string(qc);
      hw.string(qs);
      hw.mpint(Kbig);
      var H = await C.digest(hashAlg, hw.buffer());

      // 首次交换建立 session id
      if (!self._sessionId) self._sessionId = H;
      self._kexSecret = Kbig;

      // 主机密钥校验
      var hostInfo = parseHostKey(ksBlob);
      var fpBytes = await C.digest('sha256', ksBlob);
      hostInfo.fingerprint = 'SHA256:' + U.base64Encode(fpBytes).replace(/=+$/, '');
      hostInfo.kexHash = hashAlg;
      var trusted = true;
      if (self.opts.onHostKey) {
        trusted = await self.opts.onHostKey(hostInfo);
      }
      if (!trusted) throw new Error('服务器主机密钥未被信任，连接中止');

      await verifyHostSignature(hostInfo, sigBlob, H);

      // 派生密钥（RFC 4253 7.2 字母顺序：A=IV(c2s) B=IV(s2c)
      // C=KEY(c2s) D=KEY(s2c) E=MAC(c2s) F=MAC(s2c)）
      function dk(ch, len) { return deriveKey(Kmp, H, self._sessionId, ch, len, hashAlg); }
      var ciCS = CIPHER_INFO[cipherCS];
      var ciSC = CIPHER_INFO[cipherSC];
      var ivCS = await dk('A', ciCS.iv);
      var ivSC = await dk('B', ciSC.iv);
      var keyCS = await dk('C', ciCS.key);
      var keySC = await dk('D', ciSC.key);
      var macCSKey = macCS ? await dk('E', MAC_INFO[macCS].key) : null;
      var macSCKey = macSC ? await dk('F', MAC_INFO[macSC].key) : null;

      self._pendingOut = {
        cipher: cipherCS, iv: ivCS, key: keyCS,
        mac: macCS, macKey: macCSKey
      };
      self._pendingIn = {
        cipher: cipherSC, iv: ivSC, key: keySC,
        mac: macSC, macKey: macSCKey
      };

      // 发送 NEWKEYS 后切换发送方向
      await self._sendPayload(new Uint8Array([MSG.NEWKEYS]));
      self._newKeysOut = self._pendingOut;
      self._seqOutAtNew = self._seqOut;
      self._outCtrBlocks = 0;

      // 服务器 NEWKEYS 可能在验签阶段就已到达（慢验签竞态），补上接收方向切换
      if (self._newKeysInReceived) {
        self._newKeysIn = self._pendingIn;
        self._newKeysInApplied = true;
        if (self._newKeysAppliedResolve) {
          var ar2 = self._newKeysAppliedResolve; self._newKeysAppliedResolve = null;
          ar2();
        }
      } else {
        await new Promise(function (resolve) { self._newKeysResolve = resolve; });
      }

      self._icPayload = null;
      self._isPayload = null;
      self._kexRunning = false;

      if (self._state === 'kex') {
        // 首次交换：请求 ssh-userauth 服务并认证
        await self._requestServiceAndAuth();
      }
    } catch (e) {
      self._kexRunning = false;
      throw e;
    }
  };

  function pickOne(clientList, serverList) {
    var set = {};
    serverList.forEach(function (x) { set[x] = true; });
    for (var i = 0; i < clientList.length; i++) if (set[clientList[i]]) return clientList[i];
    return null;
  }

  // RFC 4253 7.2：派生密钥
  function deriveKey(Kmp, H, sessionId, ch, needLen, hashAlg) {
    function h(data) { return C.digest(hashAlg, data); }
    return h(U.concat(Kmp, H, U.strToBytes(ch), sessionId)).then(function (k1) {
      if (k1.length >= needLen) return k1.subarray(0, needLen);
      return h(U.concat(Kmp, H, k1)).then(function (k2) {
        return U.concat(k1, k2).subarray(0, needLen);
      });
    });
  }

  function parseHostKey(blob) {
    var info = K.parsePubBlob(blob);
    info.blob = blob;
    return info;
  }

  async function verifyHostSignature(info, sigBlob, H) {
    var sr = new U.Reader(sigBlob);
    var sigAlg = U.bytesToStr(sr.string());
    var sig = sr.string();
    var ok = false;
    if (info.type === 'ssh-ed25519' && sigAlg === 'ssh-ed25519') {
      ok = await C.ed25519Verify(H, sig, info.A);
    } else if ((info.type === 'ssh-rsa' || info.type.indexOf('rsa-sha2') === 0) &&
      (sigAlg === 'ssh-rsa' || sigAlg === 'rsa-sha2-256' || sigAlg === 'rsa-sha2-512')) {
      var hash = sigAlg === 'rsa-sha2-512' ? 'sha512' : sigAlg === 'rsa-sha2-256' ? 'sha256' : 'sha1';
      ok = await C.rsaVerify(hash, H, sig, info.n, info.e);
    } else if (info.type.indexOf('ecdsa-sha2-') === 0 && sigAlg === info.type) {
      var esr = new U.Reader(sig);
      var rb = esr.mpintBytes();
      var sb = esr.mpintBytes();
      var size = C.EC_INFO[info.curve].size;
      var rs = U.concat(padLeft(rb, size), padLeft(sb, size));
      var x = info.Q.subarray(1, 1 + size);
      var y = info.Q.subarray(1 + size, 1 + 2 * size);
      ok = await C.ecdsaVerify(info.curve, H, rs, {
        x: U.base64UrlEncode(x),
        y: U.base64UrlEncode(y)
      });
    } else {
      throw new Error('不支持的主机密钥签名组合: ' + info.type + ' / ' + sigAlg);
    }
    if (!ok) throw new Error('主机密钥签名验证失败（可能遭遇中间人攻击）');
  }
  function padLeft(b, len) {
    if (b.length >= len) return b.length === len ? b : b.subarray(b.length - len);
    var o = new Uint8Array(len);
    o.set(b, len - b.length);
    return o;
  }

  /* ================= 服务请求 + 认证 ================= */
  SSHClient.prototype._requestServiceAndAuth = async function () {
    var self = this;

    var sp = new Promise(function (resolve) { self._serviceResolve = resolve; });
    var w = new U.Writer();
    w.byte(MSG.SERVICE_REQUEST).string('ssh-userauth');
    await self._sendPayload(w.buffer());
    await sp;

    self._state = 'auth';

    // 先 method=none 探测服务器支持的认证方式
    var result = await self._authNone();
    if (result === null) return; // none 直接成功（几乎不可能）
    var methods = result.methods;

    if (self.opts.privateKey) {
      var keyObj = self.opts.privateKey;
      var algos = keyObj.algoNames.filter(function (a) {
        return methods.indexOf('publickey') >= 0 &&
          self._serverPubkeyAllowed(a);
      });
      // 至少尝试密钥自身类型（有些服务器不在 none 响应中返回完整列表）
      if (methods.indexOf('publickey') < 0) throw new Error('服务器不允许公钥认证，允许: ' + methods.join(','));
      if (!algos.length) {
        // RSA 降级匹配
        algos = keyObj.algoNames.filter(function (a) {
          if (keyObj.type === 'rsa') return a === 'rsa-sha2-256' || a === 'rsa-sha2-512';
          return false;
        });
      }
      var ok2 = false;
      for (var ai = 0; ai < algos.length; ai++) {
        var alg = algos[ai];
        var pubBlob = keyObj.pubBlob(alg);
        var sw = new U.Writer();
        sw.string(self._sessionId).byte(MSG.USERAUTH_REQUEST)
          .string(self.username).string('ssh-connection').string('publickey')
          .bool(true).string(alg).string(pubBlob);
        var sigData = sw.buffer();
        var rawSig = await keyObj.sign(alg, sigData);
        // SSH 线网格式：string(签名算法名) + string(裸签名)
        var sigBlob = new U.Writer();
        sigBlob.string(alg).string(rawSig);
        var req = new U.Writer();
        req.byte(MSG.USERAUTH_REQUEST).string(self.username).string('ssh-connection').string('publickey')
          .bool(true).string(alg).string(pubBlob).string(sigBlob.buffer());
        var rr2 = await self._sendAuthAndWait(req.buffer());
        if (rr2 === null) { ok2 = true; break; }
        methods = rr2.methods;
      }
      if (!ok2) throw new Error('公钥认证失败');
      return;
    }

    if (!self.opts.password) throw new Error('没有可用的认证凭据');

    // password
    var pw = new U.Writer();
    pw.byte(MSG.USERAUTH_REQUEST).string(self.username).string('ssh-connection').string('password')
      .bool(false).string(self.opts.password);
    var pr = await self._sendAuthAndWait(pw.buffer());
    if (pr === null) return;
    methods = pr.methods;

    // keyboard-interactive 兜底（自动用密码应答）
    if (methods.indexOf('keyboard-interactive') >= 0) {
      self.opts.onKeyboardInteractive = self.opts.onKeyboardInteractive || async function (n, ins, prompts) {
        return prompts.map(function () { return self.opts.password; });
      };
      var kw = new U.Writer();
      kw.byte(MSG.USERAUTH_REQUEST).string(self.username).string('ssh-connection').string('keyboard-interactive')
        .string('').string('');
      var kr2 = await self._sendAuthAndWait(kw.buffer());
      if (kr2 === null) return;
    }
    throw new Error('密码认证失败，服务器允许: ' + methods.join(','));
  };

  SSHClient.prototype._serverPubkeyAllowed = function (algo) {
    // 服务器 KEXINIT 的 server_host_key_algorithms 同时声明可接受的公钥算法
    if (!this._serverHostAlgos) {
      // _isPayload 在首次交换后已清空，从 lists 无法取；宽松放行
      return true;
    }
    return this._serverHostAlgos.indexOf(algo) >= 0;
  };

  SSHClient.prototype._authNone = function () {
    var w = new U.Writer();
    w.byte(MSG.USERAUTH_REQUEST).string(this.username).string('ssh-connection').string('none');
    return this._sendAuthAndWait(w.buffer());
  };

  // 返回 null=SUCCESS，否则 {methods:[...]}
  SSHClient.prototype._sendAuthAndWait = function (payload) {
    var self = this;
    return new Promise(function (resolve) {
      self._authResolve = resolve;
      self._sendPayload(payload);
    });
  };

  /* ================= Channel / Shell ================= */
  SSHClient.prototype.openShell = function (opts, cbs) {
    var self = this;
    var localId = self._chanSeq++;
    var ch = {
      localId: localId,
      remoteId: -1,
      window: 2 * 1024 * 1024,
      maxPacket: 32768,
      remoteWindow: 0,
      recvBuf: [],
      recvUnacked: 0,
      cbs: cbs || {},
      closed: false,
      opts: opts
    };
    self._channels[localId] = ch;

    ch.sendData = function (data) {
      if (ch.closed) return Promise.resolve();
      if (typeof data === 'string') data = U.strToBytes(data);
      var chunks = [];
      var off = 0;
      while (off < data.length) {
        var n = Math.min(ch.maxPacket - 100, data.length - off, 30000);
        chunks.push(data.subarray(off, off + n));
        off += n;
      }
      return chunks.reduce(function (p, c) {
        return p.then(function () {
          var w = new U.Writer();
          w.byte(MSG.CHANNEL_DATA).uint32(ch.remoteId).string(c);
          return self._sendPayload(w.buffer());
        });
      }, Promise.resolve());
    };

    ch.resize = function (cols, rows, width, height) {
      if (ch.closed || ch.remoteId < 0) return Promise.resolve();
      var w = new U.Writer();
      w.byte(MSG.CHANNEL_REQUEST).uint32(ch.remoteId).string('window-change').bool(false)
        .uint32(cols).uint32(rows).uint32(width || 0).uint32(height || 0);
      return self._sendPayload(w.buffer());
    };

    ch.close = function () {
      if (ch.closed) return Promise.resolve();
      var w = new U.Writer();
      w.byte(MSG.CHANNEL_CLOSE).uint32(ch.remoteId);
      return self._sendPayload(w.buffer());
    };

    return (async function () {
      // 1. 打开 session
      var openP = self._waitChanReply('open-' + localId);
      var ow = new U.Writer();
      ow.byte(MSG.CHANNEL_OPEN).string('session').uint32(localId)
        .uint32(ch.window).uint32(ch.maxPacket);
      await self._sendPayload(ow.buffer());
      var openRes = await openP;
      if (openRes.type !== MSG.CHANNEL_OPEN_CONFIRMATION) throw new Error('打开会话通道失败');
      ch.remoteId = openRes.senderChannel;
      ch.remoteWindow = openRes.remoteWindow;

      // 2. pty-req
      var termModes = buildTerminalModes();
      var ptyP = self._waitChanReply('req-' + localId);
      var pw = new U.Writer();
      pw.byte(MSG.CHANNEL_REQUEST).uint32(ch.remoteId).string('pty-req').bool(true)
        .string(opts.term || 'xterm-256color')
        .uint32(opts.cols || 80).uint32(opts.rows || 24)
        .uint32(opts.width || 0).uint32(opts.height || 0)
        .string(termModes);
      await self._sendPayload(pw.buffer());
      if ((await ptyP).type !== MSG.CHANNEL_SUCCESS) throw new Error('pty-req 被拒绝');

      // 3. shell
      var shP = self._waitChanReply('req-' + localId);
      var sw = new U.Writer();
      sw.byte(MSG.CHANNEL_REQUEST).uint32(ch.remoteId).string('shell').bool(true);
      await self._sendPayload(sw.buffer());
      if ((await shP).type !== MSG.CHANNEL_SUCCESS) throw new Error('shell 请求被拒绝');

      return ch;
    })().catch(function (e) {
      delete self._channels[localId];
      throw e;
    });
  };

  /* ================= SFTP subsystem 通道 ================= */
  SSHClient.prototype.openSftp = function (cbs) {
    var self = this;
    var localId = self._chanSeq++;
    var ch = {
      localId: localId,
      remoteId: -1,
      window: 2 * 1024 * 1024,
      maxPacket: 32768,
      remoteWindow: 0,
      recvBuf: [],
      recvUnacked: 0,
      cbs: cbs || {},
      closed: false
    };
    self._channels[localId] = ch;

    ch.sendData = function (data) {
      if (ch.closed) return Promise.resolve();
      if (typeof data === 'string') data = U.strToBytes(data);
      var chunks = [];
      var off = 0;
      while (off < data.length) {
        var n = Math.min(ch.maxPacket - 100, data.length - off, 30000);
        chunks.push(data.subarray(off, off + n));
        off += n;
      }
      return chunks.reduce(function (p, c) {
        return p.then(function () {
          var w = new U.Writer();
          w.byte(MSG.CHANNEL_DATA).uint32(ch.remoteId).string(c);
          return self._sendPayload(w.buffer());
        });
      }, Promise.resolve());
    };

    ch.close = function () {
      if (ch.closed) return Promise.resolve();
      var w = new U.Writer();
      w.byte(MSG.CHANNEL_CLOSE).uint32(ch.remoteId);
      return self._sendPayload(w.buffer());
    };

    return (async function () {
      // 1. 打开 session 通道
      var openP = self._waitChanReply('open-' + localId);
      var ow = new U.Writer();
      ow.byte(MSG.CHANNEL_OPEN).string('session').uint32(localId)
        .uint32(ch.window).uint32(ch.maxPacket);
      await self._sendPayload(ow.buffer());
      var openRes = await openP;
      if (openRes.type !== MSG.CHANNEL_OPEN_CONFIRMATION) throw new Error('打开 SFTP 通道失败');
      ch.remoteId = openRes.senderChannel;
      ch.remoteWindow = openRes.remoteWindow;

      // 2. 请求 sftp subsystem
      var subP = self._waitChanReply('req-' + localId);
      var sw = new U.Writer();
      sw.byte(MSG.CHANNEL_REQUEST).uint32(ch.remoteId).string('subsystem').bool(true)
        .string('sftp');
      await self._sendPayload(sw.buffer());
      var subRes = await subP;
      if (subRes.type !== MSG.CHANNEL_SUCCESS) throw new Error('sftp subsystem 请求被拒绝');

      return ch;
    })().catch(function (e) {
      delete self._channels[localId];
      throw e;
    });
  };

  SSHClient.prototype._waitChanReply = function (key) {
    var self = this;
    return new Promise(function (resolve) {
      self._chanReplies[key] = resolve;
    });
  };

  SSHClient.prototype._handleChannel = async function (type, body) {
    var self = this;
    var r = new U.Reader(body);
    var recipient = r.uint32();
    var ch = self._channels[recipient];

    switch (type) {
      case MSG.CHANNEL_OPEN_CONFIRMATION: {
        var sender = r.uint32();
        var win = r.uint32();
        r.uint32(); // max packet
        var key = 'open-' + recipient;
        if (self._chanReplies[key]) {
          var rs = self._chanReplies[key]; delete self._chanReplies[key];
          rs({ type: type, senderChannel: sender, remoteWindow: win });
        }
        return;
      }
      case MSG.CHANNEL_OPEN_FAILURE: {
        var reason = r.uint32();
        var desc = U.bytesToStr(r.string());
        var key2 = 'open-' + recipient;
        if (self._chanReplies[key2]) {
          var rs2 = self._chanReplies[key2]; delete self._chanReplies[key2];
          rs2({ type: type, reason: reason, desc: desc });
        }
        return;
      }
      case MSG.CHANNEL_WINDOW_ADJUST: {
        if (ch) ch.remoteWindow += r.uint32();
        return;
      }
      case MSG.CHANNEL_DATA:
      case MSG.CHANNEL_EXTENDED_DATA: {
        if (!ch) return;
        if (type === MSG.CHANNEL_EXTENDED_DATA) r.uint32(); // code (1=stderr)
        var data = r.string();
        if (ch.cbs.onData) ch.cbs.onData(data, type === MSG.CHANNEL_EXTENDED_DATA);
        ch.recvUnacked += data.length;
        if (ch.recvUnacked >= ch.window / 2) {
          var bytes = ch.recvUnacked;
          ch.recvUnacked = 0;
          var w = new U.Writer();
          w.byte(MSG.CHANNEL_WINDOW_ADJUST).uint32(ch.remoteId).uint32(bytes);
          await self._sendPayload(w.buffer());
        }
        return;
      }
      case MSG.CHANNEL_EOF:
        if (ch && ch.cbs.onEOF) ch.cbs.onEOF();
        return;
      case MSG.CHANNEL_CLOSE: {
        if (ch) {
          ch.closed = true;
          // 回复 CLOSE
          var wc = new U.Writer();
          wc.byte(MSG.CHANNEL_CLOSE).uint32(ch.remoteId);
          await self._sendPayload(wc.buffer());
          if (ch.cbs.onClose) ch.cbs.onClose();
          delete self._channels[ch.localId];
        }
        return;
      }
      case MSG.CHANNEL_REQUEST: {
        var reqType = U.bytesToStr(r.string());
        var wantReply = r.bool();
        if (ch && reqType === 'exit-status') {
          ch.exitCode = r.uint32();
          if (ch.cbs.onExit) ch.cbs.onExit(ch.exitCode, null);
        }
        if (ch && reqType === 'exit-signal') {
          var sigName = U.bytesToStr(r.string());
          if (ch.cbs.onExit) ch.cbs.onExit(null, sigName);
        }
        // pty/shell 的 SUCCESS/FAILURE 用 99/100 单独消息
        return;
      }
      case MSG.CHANNEL_SUCCESS:
      case MSG.CHANNEL_FAILURE: {
        if (!ch) return;
        var key3 = 'req-' + ch.localId;
        if (self._chanReplies[key3]) {
          var rs3 = self._chanReplies[key3]; delete self._chanReplies[key3];
          rs3({ type: type });
        }
        return;
      }
    }
  };

  function buildTerminalModes() {
    var w = new U.Writer();
    w.byte(128).uint32(38400); // TTY_OP_ISPEED
    w.byte(129).uint32(38400); // TTY_OP_OSPEED
    w.byte(0);                // TTY_OP_END
    return w.buffer();
  }

  WSSH.SSHClient = SSHClient;
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
