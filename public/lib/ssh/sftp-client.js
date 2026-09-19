/*!
 * sftp-client.js - SFTP v3 协议层（基于 SSH session subsystem 通道）
 * 挂载到全局 WSSH.SftpClient
 * 依赖: WSSH.util (Writer/Reader/concat)
 */
(function (global) {
  'use strict';
  var WSSH = global.WSSH || (global.WSSH = {});
  var U = WSSH.util;

  // SFTP 消息类型 (draft-ietf-secsh-filexfer-02)
  var FX_INIT = 1, FX_VERSION = 2, FX_OPEN = 3, FX_CLOSE = 4,
    FX_READ = 5, FX_WRITE = 6, FX_LSTAT = 7, FX_FSTAT = 8,
    FX_SETSTAT = 9, FX_FSETSTAT = 10, FX_OPENDIR = 11,
    FX_READDIR = 12, FX_REMOVE = 13, FX_MKDIR = 14, FX_RMDIR = 15,
    FX_REALPATH = 16, FX_STAT = 17, FX_RENAME = 18, FX_READLINK = 19,
    FX_SYMLINK = 20;
  var FX_STATUS = 101, FX_HANDLE = 102, FX_DATA = 103,
    FX_NAME = 104, FX_ATTRS = 105;

  // 文件属性标志
  var ATTR_SIZE = 0x01, ATTR_UIDGID = 0x02, ATTR_PERM = 0x04,
    ATTR_TIME = 0x08, ATTR_EXTENDED = 0x80000000;

  // 文件类型
  var TYPE_REGULAR = 1, TYPE_DIRECTORY = 2, TYPE_SYMLINK = 3,
    TYPE_SPECIAL = 4, TYPE_UNKNOWN = 5;

  // 打开标志
  var FXF_READ = 0x01, FXF_WRITE = 0x02, FXF_APPEND = 0x04,
    FXF_CREAT = 0x08, FXF_TRUNC = 0x10, FXF_EXCL = 0x20;

  // 状态码
  var SSH_FX_OK = 0, SSH_FX_EOF = 1, SSH_FX_NO_SUCH_FILE = 2,
    SSH_FX_PERMISSION_DENIED = 3, SSH_FX_FAILURE = 4;

  function SftpClient(channel) {
    var self = this;
    self._ch = channel;
    self._reqId = 0;
    self._pending = {};
    self._inBuf = new Uint8Array(0);
    self._initDone = false;

    channel.cbs.onData = function (data) { self._feed(data); };
    channel.cbs.onClose = function () { self._failAll(new Error('SFTP 通道已关闭')); };
  }

  /* ---- 底层收发 ---- */

  SftpClient.prototype._feed = function (data) {
    if (!(data instanceof Uint8Array)) data = new Uint8Array(data);
    this._inBuf = this._inBuf.length ? U.concat(this._inBuf, data) : data;
    this._tryParse();
  };

  SftpClient.prototype._tryParse = function () {
    var self = this;
    while (self._inBuf.length >= 4) {
      var dv = new DataView(self._inBuf.buffer, self._inBuf.byteOffset, self._inBuf.byteLength);
      var pktLen = dv.getUint32(0);
      if (self._inBuf.length < 4 + pktLen) break; // 不完整，等更多数据
      var pkt = self._inBuf.subarray(4, 4 + pktLen);
      self._inBuf = self._inBuf.subarray(4 + pktLen);
      self._handlePacket(pkt);
    }
  };

  SftpClient.prototype._handlePacket = function (pkt) {
    var r = new U.Reader(pkt);
    var type = r.byte();

    // VERSION 响应没有 request id：byte type + uint32 version + extensions
    if (type === FX_VERSION) {
      var ver = r.uint32();
      if (this._initResolve) {
        var rfn = this._initResolve; this._initResolve = null;
        rfn(ver);
      }
      return;
    }

    // 其他响应都有 request id：byte type + uint32 id + body
    var id = r.uint32();

    var handler = this._pending[id];
    if (!handler) return;
    delete this._pending[id];

    switch (type) {
      case FX_STATUS: {
        var code = r.uint32();
        var msg = U.bytesToStr(r.string());
        r.string(); // lang
        if (code === SSH_FX_OK) {
          handler.resolve(null);
        } else if (code === SSH_FX_EOF) {
          handler.resolve({ eof: true });
        } else {
          var err = new Error('SFTP 错误(' + code + '): ' + msg);
          err.code = code;
          handler.reject(err);
        }
        break;
      }
      case FX_HANDLE: {
        var handle = r.string();
        handler.resolve(handle);
        break;
      }
      case FX_DATA: {
        var data = r.string();
        handler.resolve(data);
        break;
      }
      case FX_NAME: {
        var count = r.uint32();
        var entries = [];
        for (var i = 0; i < count; i++) {
          var filename = U.bytesToStr(r.string());
          var longname = U.bytesToStr(r.string());
          var attrs = parseAttrs(r);
          entries.push({ filename: filename, longname: longname, attrs: attrs });
        }
        handler.resolve({ entries: entries });
        break;
      }
      case FX_ATTRS: {
        var a = parseAttrs(r);
        handler.resolve(a);
        break;
      }
      default:
        handler.reject(new Error('未知 SFTP 响应类型: ' + type));
    }
  };

  SftpClient.prototype._send = function (type, bodyFn) {
    var self = this;
    var id = ++self._reqId;
    var w = new U.Writer();
    w.byte(type).uint32(id);
    if (bodyFn) bodyFn(w);
    var payload = w.buffer();

    // SFTP 包帧: uint32(length) + payload
    var pkt = new U.Writer();
    pkt.uint32(payload.length).bytes(payload);
    var pktBuf = pkt.buffer();

    return new Promise(function (resolve, reject) {
      self._pending[id] = { resolve: resolve, reject: reject };
      self._ch.sendData(pktBuf).catch(function (e) { delete self._pending[id]; reject(e); });
    });
  };

  SftpClient.prototype._failAll = function (err) {
    var pending = this._pending;
    this._pending = {};
    Object.keys(pending).forEach(function (k) { pending[k].reject(err); });
    if (this._initResolve) { var r = this._initResolve; this._initResolve = null; r(); }
  };

  /* ---- 公开接口 ---- */

  SftpClient.prototype.init = function () {
    var self = this;
    return new Promise(function (resolve, reject) {
      self._initResolve = resolve;
      self._initReject = reject;
      var w = new U.Writer();
      w.byte(FX_INIT).uint32(3); // version 3
      var payload = w.buffer();
      var pkt = new U.Writer();
      pkt.uint32(payload.length).bytes(payload);
      self._ch.sendData(pkt.buffer()).catch(reject);
    });
  };

  SftpClient.prototype.realpath = function (path) {
    return this._send(FX_REALPATH, function (w) { w.string(path); })
      .then(function (res) {
        if (res && res.entries && res.entries[0]) return res.entries[0].filename;
        return null;
      });
  };

  SftpClient.prototype.stat = function (path) {
    return this._send(FX_STAT, function (w) { w.string(path); });
  };

  SftpClient.prototype.opendir = function (path) {
    return this._send(FX_OPENDIR, function (w) { w.string(path); });
  };

  SftpClient.prototype.readdir = function (handle) {
    return this._send(FX_READDIR, function (w) { w.string(handle); });
  };

  SftpClient.prototype.mkdir = function (path, mode) {
    return this._send(FX_MKDIR, function (w) {
      w.string(path);
      // attrs: 只设 permissions
      w.uint32(ATTR_PERM);
      w.uint32(mode || 0o755);
    });
  };

  SftpClient.prototype.rmdir = function (path) {
    return this._send(FX_RMDIR, function (w) { w.string(path); });
  };

  // 递归删除非空目录（先删子项，再删自身）
  SftpClient.prototype.removeDirAll = async function (path) {
    var self = this;
    var realPath = await self.realpath(path);
    var entries = await self.readDirAll(realPath);
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var childPath = (realPath === '/' ? '/' + e.filename : realPath + '/' + e.filename);
      var isDirEntry = false;
      if (e.attrs && e.attrs.type != null) {
        isDirEntry = (e.attrs.type === TYPE_DIRECTORY);
      } else if (e.longname && e.longname[0] === 'd') {
        isDirEntry = true;
      }
      // 符号链接到目录：按文件删除（不递归进入链接）
      var isLinkEntry = false;
      if (e.longname && e.longname[0] === 'l') isLinkEntry = true;
      else if (e.attrs && e.attrs.type === TYPE_SYMLINK) isLinkEntry = true;
      if (isDirEntry && !isLinkEntry) {
        await self.removeDirAll(childPath);
      } else {
        await self.remove(childPath);
      }
    }
    await self.rmdir(realPath);
  };

  SftpClient.prototype.remove = function (path) {
    return this._send(FX_REMOVE, function (w) { w.string(path); });
  };

  SftpClient.prototype.rename = function (oldPath, newPath) {
    return this._send(FX_RENAME, function (w) { w.string(oldPath); w.string(newPath); });
  };

  SftpClient.prototype.openFile = function (path, flags, mode) {
    return this._send(FX_OPEN, function (w) {
      w.string(path);
      w.uint32(flags);
      // attrs
      if (mode != null) {
        w.uint32(ATTR_PERM);
        w.uint32(mode);
      } else {
        w.uint32(0); // 无属性
      }
    });
  };

  SftpClient.prototype.readFile = function (handle, offset, length) {
    return this._send(FX_READ, function (w) {
      w.string(handle);
      writeUint64(w, offset);
      w.uint32(length);
    });
  };

  SftpClient.prototype.writeFile = function (handle, offset, data) {
    return this._send(FX_WRITE, function (w) {
      w.string(handle);
      writeUint64(w, offset);
      w.string(data);
    });
  };

  SftpClient.prototype.closeFile = function (handle) {
    return this._send(FX_CLOSE, function (w) { w.string(handle); });
  };

  SftpClient.prototype.close = function () {
    if (this._ch && !this._ch.closed) return this._ch.close();
    return Promise.resolve();
  };

  /* ---- 高级封装：readFileAll / writeFileAll ---- */

  SftpClient.prototype.readFileAll = async function (path) {
    var self = this;
    var handle = await self.openFile(path, FXF_READ, null);
    var chunks = [];
    var offset = 0;
    var chunkSize = 32768;
    while (true) {
      var res;
      try {
        res = await self.readFile(handle, offset, chunkSize);
      } catch (e) {
        await self.closeFile(handle);
        throw e;
      }
      if (res && res.eof) break;
      chunks.push(res);
      offset += res.length;
    }
    await self.closeFile(handle);
    return U.concat.apply(null, chunks);
  };

  SftpClient.prototype.writeFileAll = async function (path, data, mode) {
    var self = this;
    var flags = FXF_WRITE | FXF_CREAT | FXF_TRUNC;
    var handle = await self.openFile(path, flags, mode || 0o644);
    var offset = 0;
    var chunkSize = 32768;
    while (offset < data.length) {
      var end = Math.min(offset + chunkSize, data.length);
      await self.writeFile(handle, offset, data.subarray(offset, end));
      offset = end;
    }
    await self.closeFile(handle);
  };

  SftpClient.prototype.readDirAll = async function (path) {
    var self = this;
    var realPath = await self.realpath(path);
    var handle = await self.opendir(realPath);
    var allEntries = [];
    while (true) {
      var res;
      try {
        res = await self.readdir(handle);
      } catch (e) {
        await self.closeFile(handle);
        throw e;
      }
      if (res && res.eof) break;
      if (res && res.entries) {
        allEntries = allEntries.concat(res.entries);
      } else break;
    }
    await self.closeFile(handle);
    // 过滤 . 和 ..
    return allEntries.filter(function (e) { return e.filename !== '.' && e.filename !== '..'; });
  };

  /* ---- 工具函数 ---- */

  function writeUint64(w, val) {
    // BigInt 安全写入 uint64；普通 number 也能处理 < 2^53
    if (typeof val === 'bigint') {
      var be = U.bigIntToBytesBE(val, 8);
      w.bytes(be);
    } else {
      var hi = Math.floor(val / 0x100000000);
      var lo = val >>> 0;
      w.uint32(hi).uint32(lo);
    }
  }

  function parseAttrs(r) {
    var flags = r.uint32();
    var a = { flags: flags };
    if (flags & ATTR_SIZE) {
      // uint64: hi*2^32 + lo
      var hi = r.uint32();
      var lo = r.uint32();
      a.size = hi * 0x100000000 + lo;
    }
    if (flags & ATTR_UIDGID) {
      a.uid = r.uint32();
      a.gid = r.uint32();
    }
    if (flags & ATTR_PERM) {
      a.permissions = r.uint32();
      //a.type = (a.permissions >>> 12) & 0xf;
      var ifmt = a.permissions & 0xF000;
      if (ifmt === 0x8000) a.type = TYPE_REGULAR;
      else if (ifmt === 0x4000) a.type = TYPE_DIRECTORY;
      else if (ifmt === 0xA000) a.type = TYPE_SYMLINK;
      else if (ifmt === 0x0000) a.type = TYPE_UNKNOWN;
      else a.type = TYPE_SPECIAL;
    }
    if (flags & ATTR_TIME) {
      a.atime = r.uint32();
      a.mtime = r.uint32();
    }
    if (flags & ATTR_EXTENDED) {
      var extCount = r.uint32();
      a.extended = {};
      for (var i = 0; i < extCount; i++) {
        var type = U.bytesToStr(r.string());
        var data = U.bytesToStr(r.string());
        a.extended[type] = data;
      }
    }
    return a;
  }

  // 常量导出（供 sftp-app.js 使用）
  SftpClient.TYPE_REGULAR = TYPE_REGULAR;
  SftpClient.TYPE_DIRECTORY = TYPE_DIRECTORY;
  SftpClient.TYPE_SYMLINK = TYPE_SYMLINK;
  SftpClient.TYPE_UNKNOWN = TYPE_UNKNOWN;

  WSSH.SftpClient = SftpClient;
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
