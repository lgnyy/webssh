/*!
 * ssh-util.js - SSH 报文读写、mpint 编码与通用工具
 * 纯浏览器环境运行（同时兼容 Node 便于测试），挂载到全局 WSSH 命名空间
 */
(function (global) {
  'use strict';
  var WSSH = global.WSSH || (global.WSSH = {});

  var te = new (global.TextEncoder || function () {})();
  var td = new (global.TextDecoder || function () {})();

  function strToBytes(s) { return te.encode(s); }
  function bytesToStr(b) { return td.decode(b); }

  function concat(/* arrays */) {
    var total = 0, i;
    for (i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < arguments.length; i++) {
      out.set(arguments[i], off);
      off += arguments[i].length;
    }
    return out;
  }

  function equal(a, b) {
    if (a.length !== b.length) return false;
    var r = 0;
    for (var i = 0; i < a.length; i++) r |= a[i] ^ b[i];
    return r === 0;
  }

  /* ---------- base64 ---------- */
  function base64Encode(bytes) {
    var s = '', i, len = bytes.length;
    for (i = 0; i < len; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return global.btoa(s);
  }
  function base64Decode(str) {
    str = str.replace(/\s+/g, '');
    var bin = global.atob(str);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function base64UrlEncode(bytes) {
    return base64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return base64Decode(str);
  }

  function hex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
    return s;
  }

  /* ---------- BigInt <-> bytes ---------- */
  function bytesToBigIntBE(b) {
    var n = 0n, i;
    for (i = 0; i < b.length; i++) n = (n << 8n) | BigInt(b[i]);
    return n;
  }
  function bytesToBigIntLE(b) {
    var n = 0n, i;
    for (i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
    return n;
  }
  function bigIntToBytesBE(n, len) {
    var hexStr = n.toString(16);
    if (hexStr.length & 1) hexStr = '0' + hexStr;
    var raw = new Uint8Array(hexStr.length / 2);
    for (var i = 0; i < raw.length; i++) raw[i] = parseInt(hexStr.substr(i * 2, 2), 16);
    if (len !== undefined) {
      if (raw.length > len) {
        // 去掉前导零
        var off = raw.length - len;
        for (i = 0; i < off; i++) if (raw[i] !== 0) throw new Error('bigIntToBytesBE: 超出指定长度');
        return raw.slice(off);
      }
      if (raw.length < len) {
        var pad = new Uint8Array(len);
        pad.set(raw, len - raw.length);
        return pad;
      }
    }
    return raw;
  }
  function bigIntToBytesLE(n, len) {
    var be = bigIntToBytesBE(n, len);
    var le = new Uint8Array(be.length);
    for (var i = 0; i < be.length; i++) le[i] = be[be.length - 1 - i];
    return le;
  }

  /*
   * SSH mpint: 有符号大整数，无符号大数按大端，最高位为 1 时前补 0x00，0 为空串
   */
  function mpintFromBigInt(n) {
    if (n === 0n) return new Uint8Array(0);
    var be = bigIntToBytesBE(n);
    if (be[0] & 0x80) {
      var out = new Uint8Array(be.length + 1);
      out.set(be, 1);
      return out;
    }
    return be;
  }
  function mpintToBigInt(b) {
    if (!b.length) return 0n;
    var n = bytesToBigIntBE(b);
    if (b[0] & 0x80) n -= 1n << BigInt(b.length * 8);
    return n;
  }

  /* ---------- SSH 报文 Writer ---------- */
  function Writer(size) {
    this._buf = new Uint8Array(size || 256);
    this._off = 0;
  }
  Writer.prototype._ensure = function (n) {
    if (this._off + n <= this._buf.length) return;
    var size = this._buf.length * 2;
    while (size < this._off + n) size *= 2;
    var nb = new Uint8Array(size);
    nb.set(this._buf);
    this._buf = nb;
  };
  Writer.prototype.byte = function (v) {
    this._ensure(1);
    this._buf[this._off++] = v & 0xff;
    return this;
  };
  Writer.prototype.bool = function (v) { return this.byte(v ? 1 : 0); };
  Writer.prototype.uint32 = function (v) {
    this._ensure(4);
    var dv = new DataView(this._buf.buffer, this._off);
    dv.setUint32(0, v >>> 0);
    this._off += 4;
    return this;
  };
  Writer.prototype.bytes = function (b) {
    this._ensure(b.length);
    this._buf.set(b, this._off);
    this._off += b.length;
    return this;
  };
  Writer.prototype.string = function (b) {
    if (typeof b === 'string') b = strToBytes(b);
    this.uint32(b.length).bytes(b);
    return this;
  };
  Writer.prototype.mpint = function (n) {
    var b = typeof n === 'bigint' ? mpintFromBigInt(n) : n;
    return this.string(b);
  };
  Writer.prototype.nameList = function (arr) {
    return this.string(arr.join(','));
  };
  Writer.prototype.buffer = function () { return this._buf.slice(0, this._off); };

  /* ---------- SSH 报文 Reader ---------- */
  function Reader(buf) {
    this.buf = buf;
    this.off = 0;
    this.dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  Reader.prototype.remain = function () { return this.buf.length - this.off; };
  Reader.prototype.eof = function () { return this.off >= this.buf.length; };
  Reader.prototype.byte = function () { return this.buf[this.off++]; };
  Reader.prototype.bool = function () { return this.byte() !== 0; };
  Reader.prototype.uint32 = function () {
    var v = this.dv.getUint32(this.off);
    this.off += 4;
    return v;
  };
  Reader.prototype.bytes = function (n) {
    var b = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return b;
  };
  Reader.prototype.string = function () {
    var len = this.uint32();
    return this.bytes(len);
  };
  Reader.prototype.stringStr = function () { return bytesToStr(this.string()); };
  Reader.prototype.mpint = function () { return mpintToBigInt(this.string()); };
  Reader.prototype.mpintBytes = function () { return this.string(); };

  /* 生成 SSH name-list 报文段（用于 KEXINIT） */
  function nameList(arr) {
    var w = new Writer();
    w.nameList(arr);
    return w.buffer();
  }

  WSSH.util = {
    strToBytes: strToBytes,
    bytesToStr: bytesToStr,
    concat: concat,
    equal: equal,
    base64Encode: base64Encode,
    base64Decode: base64Decode,
    base64UrlEncode: base64UrlEncode,
    base64UrlDecode: base64UrlDecode,
    hex: hex,
    bytesToBigIntBE: bytesToBigIntBE,
    bytesToBigIntLE: bytesToBigIntLE,
    bigIntToBytesBE: bigIntToBytesBE,
    bigIntToBytesLE: bigIntToBytesLE,
    mpintFromBigInt: mpintFromBigInt,
    mpintToBigInt: mpintToBigInt,
    Writer: Writer,
    Reader: Reader,
    nameList: nameList
  };
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
