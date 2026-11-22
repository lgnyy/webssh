/*!
 * editor-app.js - SFTP 文件编辑器（独立窗口）
 *  由 sftp-app.js 通过 window.open('editor.html?path=...') 打开，
 *  借助 window.opener 的 postMessage 协议读写远端文件（不直接持有 SFTP 连接）。
 */
(function () {
  'use strict';

  var params = new URLSearchParams(window.location.search);
  var remotePath = params.get('path') || '';
  var fileName = params.get('name') || (remotePath ? remotePath.split('/').pop() : '未命名');
  var MAX_EDIT_SIZE = 5 * 1024 * 1024; // 5MB

  var els = {
    fileName: document.getElementById('file-name'),
    dirtyFlag: document.getElementById('dirty-flag'),
    filePath: document.getElementById('file-path'),
    btnSave: document.getElementById('btn-save'),
    btnReload: document.getElementById('btn-reload'),
    btnClose: document.getElementById('btn-close'),
    statusMsg: document.getElementById('status-msg'),
    cursorPos: document.getElementById('cursor-pos'),
    fileSize: document.getElementById('file-size'),
    overlay: document.getElementById('overlay'),
    overlayMsg: document.getElementById('overlay-msg'),
    overlayClose: document.getElementById('overlay-close')
  };

  els.fileName.textContent = fileName;
  els.filePath.textContent = remotePath;
  els.filePath.title = remotePath;

  /* ================= CodeMirror 初始化 ================= */
  var cm = CodeMirror.fromTextArea(document.getElementById('editor'), {
    lineNumbers: true,
    mode: detectMode(fileName),
    theme: 'material-darker',
    matchBrackets: true,
    autoCloseBrackets: true,
    styleActiveLine: true,
    indentUnit: 2,
    tabSize: 2,
    indentWithTabs: false,
    lineWrapping: false,
    extraKeys: {
      'Ctrl-S': saveFile,
      'Cmd-S': saveFile,
      'Ctrl-F': 'findPersistent',
      'Cmd-F': 'findPersistent',
      'Ctrl-G': 'jumpToLine',
      'Alt-G': 'jumpToLine'
    }
  });

  var loaded = false;
  var dirty = false;

  /* ================= 语言识别 ================= */
  function detectMode(name) {
    var lower = String(name || '').toLowerCase();
    var ext = lower.lastIndexOf('.') >= 0 ? lower.split('.').pop() : '';
    if (lower === 'dockerfile' || lower.indexOf('dockerfile.') === 0) return 'dockerfile';
    if (lower === 'makefile' || ext === 'mk') return 'shell';
    var map = {
      sh: 'shell', bash: 'shell', zsh: 'shell', ksh: 'shell', profile: 'shell', env: 'shell',
      js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript', ts: 'javascript', json: 'application/json',
      xml: 'xml', svg: 'xml', plist: 'xml',
      css: 'css', scss: 'css', less: 'css',
      html: 'htmlmixed', htm: 'htmlmixed', vue: 'htmlmixed',
      php: 'php',
      py: 'python',
      md: 'markdown', markdown: 'markdown',
      yml: 'yaml', yaml: 'yaml',
      sql: 'sql',
      go: 'go',
      nginx: 'nginx', conf: 'nginx',
      properties: 'properties', ini: 'properties', cfg: 'properties', toml: 'properties'
    };
    if (ext && map[ext]) return map[ext];
    if (lower.indexOf('nginx') >= 0) return 'nginx';
    return null;
  }

  /* ================= 与 SFTP 窗口通信 ================= */
  var callSeq = 0;
  var pending = {};

  window.addEventListener('message', function (ev) {
    var d = ev.data;
    if (!d || d.type !== 'sftp-editor-result') return;
    var p = pending[d.id];
    if (!p) return;
    delete pending[d.id];
    clearTimeout(p.timer);
    if (d.ok) p.resolve(d.result);
    else p.reject(new Error(d.error || 'SFTP 操作失败'));
  });

  function openerCall(method, payload) {
    return new Promise(function (resolve, reject) {
      if (!window.opener) {
        reject(new Error('与 SFTP 窗口的连接已断开'));
        return;
      }
      var id = ++callSeq;
      var timer = setTimeout(function () {
        delete pending[id];
        reject(new Error('操作超时'));
      }, 60000);
      pending[id] = { resolve: resolve, reject: reject, timer: timer };

      var msg = { type: 'sftp-editor-call', id: id, method: method, path: remotePath };
      if (payload) {
        for (var k in payload) {
          if (Object.prototype.hasOwnProperty.call(payload, k)) msg[k] = payload[k];
        }
      }
      try {
        window.opener.postMessage(msg, '*');
      } catch (e) {
        delete pending[id];
        clearTimeout(timer);
        reject(e);
      }
    });
  }

  /* ================= 读取 / 保存 ================= */
  async function loadFile() {
    if (!remotePath) {
      fail('缺少文件路径，无法打开');
      return;
    }
    if (!window.opener) {
      fail('请从 SFTP 文件列表双击文件打开编辑器');
      return;
    }
    setBusy(true);
    setStatus('正在读取文件…');
    try {
      var res = await openerCall('read');
      var raw = res && res.data;
      var bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw || []);

      if (bytes.length > MAX_EDIT_SIZE) {
        throw new Error('文件过大（' + fmtSize(bytes.length) + '），无法在编辑器中打开');
      }
      if (isBinary(bytes)) {
        throw new Error('二进制文件不支持编辑');
      }

      var sep = detectLineSeparator(bytes);
      var text = new TextDecoder('utf-8').decode(bytes);

      cm.setOption('lineSeparator', sep); // 必须在 setValue 之前设置才能正确分行
      cm.setValue(text);
      cm.clearHistory();

      loaded = true;
      setDirty(false);
      els.fileSize.textContent = fmtSize(bytes.length) + ' · UTF-8 · ' + (sep === '\r\n' ? 'CRLF' : 'LF');
      setStatus('已加载 ' + fmtSize(bytes.length), 'ok');
      cm.focus();
    } catch (e) {
      loaded = false;
      els.btnSave.disabled = true;
      setStatus('读取失败: ' + e.message, 'err');
      fail('无法打开该文件：<br>' + escapeHtml(e.message));
    } finally {
      setBusy(false);
    }
  }

  async function saveFile() {
    if (!loaded) return;
    if (!window.opener) {
      setStatus('与 SFTP 窗口的连接已断开，无法保存', 'err');
      return;
    }
    var out = new TextEncoder().encode(cm.getValue());
    els.btnSave.disabled = true;
    setStatus('正在保存…');
    try {
      await openerCall('write', { data: out });
      setDirty(false);
      els.fileSize.textContent = fmtSize(out.length) + ' · UTF-8 · ' + (cm.getOption('lineSeparator') === '\r\n' ? 'CRLF' : 'LF');
      setStatus('已保存 (' + fmtSize(out.length) + ')', 'ok');
    } catch (e) {
      setStatus('保存失败: ' + e.message, 'err');
    } finally {
      els.btnSave.disabled = !loaded;
    }
  }

  /* ================= 工具函数 ================= */
  function isBinary(bytes) {
    var n = Math.min(bytes.length, 8192);
    for (var i = 0; i < n; i++) {
      if (bytes[i] === 0) return true;
    }
    return false;
  }

  function detectLineSeparator(bytes) {
    var crlf = 0, lf = 0;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] === 10) {
        lf++;
        if (i > 0 && bytes[i - 1] === 13) crlf++;
      }
    }
    return (lf > 0 && crlf / lf > 0.5) ? '\r\n' : null;
  }

  function fmtSize(bytes) {
    if (bytes == null) return '-';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' K';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' M';
    return (bytes / 1073741824).toFixed(1) + ' G';
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function setStatus(text, kind) {
    els.statusMsg.textContent = text;
    els.statusMsg.className = kind || '';
  }

  function setDirty(v) {
    dirty = v;
    els.dirtyFlag.classList.toggle('show', v);
    document.title = (v ? '● ' : '') + fileName + ' - 编辑器';
  }

  function setBusy(v) {
    els.btnReload.disabled = v;
    els.btnSave.disabled = v || !loaded;
  }

  function fail(html) {
    els.overlayMsg.innerHTML = html;
    els.overlay.classList.add('show');
  }

  /* ================= 交互 ================= */
  els.btnSave.addEventListener('click', saveFile);

  els.btnReload.addEventListener('click', function () {
    if (dirty && !confirm('放弃未保存的修改并重新加载？')) return;
    setDirty(false);
    loadFile();
  });

  els.btnClose.addEventListener('click', function () { window.close(); });
  els.overlayClose.addEventListener('click', function () { window.close(); });

  cm.on('change', function () {
    if (!loaded) return;
    if (!dirty) setDirty(true);
  });

  cm.on('cursorActivity', function () {
    var c = cm.getCursor();
    els.cursorPos.textContent = '行 ' + (c.line + 1) + ', 列 ' + (c.ch + 1);
  });

  window.addEventListener('beforeunload', function (ev) {
    if (dirty) {
      ev.preventDefault();
      ev.returnValue = '';
    }
  });

  /* ================= 主题同步 ================= */
  function applyTheme(theme) {
    var light = theme === 'light';
    document.documentElement.setAttribute('data-theme', light ? 'light' : 'dark');
    cm.setOption('theme', light ? 'eclipse' : 'material-darker');
  }

  (function initTheme() {
    var t = 'dark';
    try { t = localStorage.getItem('wssh.theme') || 'dark'; } catch (e) { }
    applyTheme(t);
  })();

  window.addEventListener('storage', function (ev) {
    if (ev.key === 'wssh.theme') applyTheme(ev.newValue || 'dark');
  });
  window.addEventListener('message', function (ev) {
    if (ev.data && ev.data.type === 'theme') applyTheme(ev.data.theme);
  });

  /* ================= 启动 ================= */
  loadFile();
})();
