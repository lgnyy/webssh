/*!
 * app.js - WebSSH 页面逻辑 (可配置服务器列表 + SFTP 面板)
 */
(function () {
  'use strict';

  /* ================= DOM ================= */
  let $ = function (id) { return document.getElementById(id); };
  let els = {
    wsurl: $('wsurl'),
    svraddr: $('svraddr'),
    username: $('username'),
    tabPassword: $('tab-password'),
    tabKey: $('tab-key'),
    password: $('password'),
    keyfile: $('keyfile'),
    keypassphrase: $('keypassphrase'),
    fPassword: $('f-password'),
    fKeyfile: $('f-keyfile'),
    fKeypass: $('f-keypass'),
    btnConnect: $('btn-connect'),
    btnConfig: $('btn-config'),
    status: $('status'),
    statusText: $('status-text'),
    hkBar: $('hostkey-bar'),
    hkTitle: $('hk-title'),
    hkType: $('hk-type'),
    hkFp: $('hk-fp'),
    hkRemember: $('hk-remember'),
    btnHkTrust: $('btn-hk-trust'),
    btnHkReject: $('btn-hk-reject'),
    terminalWrap: $('terminal-wrap'),
    terminal: $('terminal'),
    tip: $('tip'),
    // SFTP 面板
    btnSftp: $('btn-sftp'),
    leftCol: $('left-col'),
    sftpPanel: $('sftp-panel'),
    sftpFrame: $('sftp-frame'),
    sftpSplitter: $('sftp-splitter'),
    // 端口转发面板
    btnFwd: $('btn-fwd'),
    fwdPanel: $('fwd-panel'),
    fwdFrame: $('fwd-frame'),
    // 配置弹窗
    configOverlay: $('config-overlay'),
    configClose: $('config-close'),
    srvList: $('srv-list'),
    btnAddSrv: $('btn-add-srv'),
    btnSaveConfig: $('btn-save-config'),
    btnCancelConfig: $('btn-cancel-config')
  };

  /* ================= 状态 ================= */
  let authMode = 'key';
  let selectedKeyFile = null;
  let connecting = false;
  let connected = false;
  let manualClose = false;
  let ws = null;
  let client = null;
  let channel = null;
  let term = null;
  let fitAddon = null;
  let resizeTimer = null;

  // 服务器配置列表
  let serverList = [];   // [{ name, addr, user }]

  // SFTP 状态
  let sftpEnabled = false;
  let sftpClient = null;

  // 端口转发状态
  let fwdEnabled = false;
  let fwdChannels = {}; // id -> channel（本地转发 direct-tcpip）
  // 远程转发状态
  let remoteFwdListeners = {}; // listenerId -> { bindAddr, bindPort }
  let remoteFwdChannels = {};  // connId -> channel

  /* ================= localStorage ================= */
  const SRV_KEY = 'wssh.servers';

  function storeGet(k) {
    try { return window.localStorage.getItem(k); } catch (e) { return null; }
  }
  function storeSet(k, v) {
    try { window.localStorage.setItem(k, v); } catch (e) { }
  }
  function storeDel(k) {
    try { window.localStorage.removeItem(k); } catch (e) { }
  }

  /* ================= 服务器配置管理 ================= */

  // 加载配置
  function loadServerList() {
    let raw = storeGet(SRV_KEY);
    if (raw) {
      try {
        let arr = JSON.parse(raw);
        if (Array.isArray(arr)) {
          serverList = arr.filter(function (it) {
            return it && typeof it === 'object';
          }).map(function (it) {
            return {
              name: String(it.name || ''),
              addr: String(it.addr || ''),
              user: String(it.user || '')
            };
          });
        }
      } catch (e) { serverList = []; }
    }
    // 如果没有配置，给一个默认示例
    if (serverList.length === 0) {
      serverList = [
        { name: '本地服务器', addr: '127.0.0.1:22', user: 'root' },
        { name: '示例主机', addr: 'example.com:22', user: 'ubuntu' }
      ];
    }
  }

  // 保存配置
  function saveServerList() {
    storeSet(SRV_KEY, JSON.stringify(serverList));
  }

  // 刷新下拉列表
  function refreshSvrSelect(keepSelected) {
    let prev = keepSelected ? els.svraddr.value : '';
    els.svraddr.innerHTML = '';
    let emptyOpt = document.createElement('option');
    emptyOpt.value = '';
    emptyOpt.textContent = '-- 请选择服务器 --';
    els.svraddr.appendChild(emptyOpt);

    serverList.forEach(function (srv, idx) {
      if (!srv.addr) return;
      let opt = document.createElement('option');
      opt.value = srv.addr;
      opt.textContent = (srv.name || srv.addr) + (srv.user ? ' (' + srv.user + ')' : '');
      opt.dataset.index = idx;
      els.svraddr.appendChild(opt);
    });

    if (prev) els.svraddr.value = prev;
  }

  // 选中服务器时，自动填充用户名
  els.svraddr.addEventListener('change', function () {
    let idx = els.svraddr.selectedOptions[0] && els.svraddr.selectedOptions[0].dataset.index;
    if (idx !== undefined && serverList[idx]) {
      let srv = serverList[idx];
      if (srv.user) {
        els.password.value = '';
        els.username.value = srv.user;
      }
    }
  });

  // 打开配置弹窗
  function openConfig() {
    renderSrvEditor();
    els.configOverlay.classList.add('show');
  }
  // 关闭
  function closeConfig() {
    els.configOverlay.classList.remove('show');
  }

  // 渲染编辑器（表格行）
  function renderSrvEditor() {
    els.srvList.innerHTML = '';
    if (serverList.length === 0) {
      let empty = document.createElement('div');
      empty.className = 'hint';
      empty.style.textAlign = 'center';
      empty.style.padding = '12px';
      empty.textContent = '还没有服务器，点击下方"添加服务器"开始。';
      els.srvList.appendChild(empty);
    }
    serverList.forEach(function (srv, idx) {
      let item = document.createElement('div');
      item.className = 'srv-item';

      let nameInput = document.createElement('input');
      nameInput.type = 'text';
      nameInput.className = 'srv-name';
      nameInput.placeholder = '名称（显示用）';
      nameInput.value = srv.name || '';

      let addrInput = document.createElement('input');
      addrInput.type = 'text';
      addrInput.className = 'srv-addr';
      addrInput.placeholder = 'host:port 或 host';
      addrInput.value = srv.addr || '';

      let userInput = document.createElement('input');
      userInput.type = 'text';
      userInput.className = 'srv-user';
      userInput.placeholder = '用户名（可空）';
      userInput.value = srv.user || '';

      let delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'srv-del';
      delBtn.title = '删除此服务器';
      delBtn.innerHTML = '×';
      delBtn.addEventListener('click', function () {
        serverList.splice(idx, 1);
        renderSrvEditor();
      });

      item.appendChild(nameInput);
      item.appendChild(addrInput);
      item.appendChild(userInput);
      item.appendChild(delBtn);
      els.srvList.appendChild(item);
    });
  }

  // 从编辑器收集数据（点击保存时）
  function collectSrvFromEditor() {
    let items = els.srvList.querySelectorAll('.srv-item');
    let newList = [];
    for (let i = 0; i < items.length; i++) {
      let item = items[i];
      let name = item.querySelector('.srv-name').value.trim();
      let addr = item.querySelector('.srv-addr').value.trim();
      let user = item.querySelector('.srv-user').value.trim();
      if (!addr) continue;
      newList.push({ name: name || addr, addr: addr, user: user });
    }
    return newList;
  }

  // 事件绑定
  els.btnConfig.addEventListener('click', openConfig);
  els.configClose.addEventListener('click', closeConfig);
  els.btnCancelConfig.addEventListener('click', closeConfig);
  els.configOverlay.addEventListener('click', function (ev) {
    if (ev.target === els.configOverlay) closeConfig();
  });
  els.btnAddSrv.addEventListener('click', function () {
    serverList.push({ name: '', addr: '', user: '' });
    renderSrvEditor();
    els.srvList.scrollTop = els.srvList.scrollHeight;
  });
  els.btnSaveConfig.addEventListener('click', function () {
    serverList = collectSrvFromEditor();
    saveServerList();
    refreshSvrSelect(true);
    closeConfig();
  });

  /* ================= 状态提示 ================= */
  function setStatus(mode, text) {
    els.status.className = mode || '';
    els.statusText.textContent = text;
  }

  /* ================= 认证方式 tab 切换 ================= */
  function setAuthMode(mode) {
    authMode = mode;
    let keyMode = mode === 'key';
    els.tabPassword.classList.toggle('active', !keyMode);
    els.tabKey.classList.toggle('active', keyMode);
    els.fPassword.style.display = keyMode ? 'none' : '';
    els.fKeyfile.style.display = keyMode ? '' : 'none';
    els.fKeypass.style.display = keyMode ? '' : 'none';
  }
  els.tabPassword.addEventListener('click', function () { setAuthMode('password'); });
  els.tabKey.addEventListener('click', function () { setAuthMode('key'); });
  els.keyfile.addEventListener('change', function () {
    selectedKeyFile = els.keyfile.files && els.keyfile.files[0] ? els.keyfile.files[0] : null;
  });

  /* ================= 左侧面板控制（SFTP + 端口转发） ================= */
  // 根据 sftpEnabled / fwdEnabled 刷新左侧列可见性与分隔条
  function refreshLeftCol() {
    let anyOpen = sftpEnabled || fwdEnabled;
    els.leftCol.style.display = anyOpen ? 'flex' : 'none';
    els.sftpSplitter.style.display = anyOpen ? 'block' : 'none';
    if (anyOpen) {
      let savedW = storeGet('wssh.sftpW');
      if (savedW && /^(\d+(px|%))$/.test(savedW)) {
        els.leftCol.style.flex = '0 0 ' + savedW;
      } else {
        els.leftCol.style.flex = '';
      }
    }
    // SFTP 与转发面板各自显示/隐藏，并在只有一个时占满整列
    let count = (sftpEnabled ? 1 : 0) + (fwdEnabled ? 1 : 0);
    if (sftpEnabled) {
      els.sftpPanel.classList.remove('hidden');
      els.sftpPanel.style.flex = count > 1 ? '1 1 50%' : '1 1 auto';
    } else {
      els.sftpPanel.classList.add('hidden');
    }
    if (fwdEnabled) {
      els.fwdPanel.classList.remove('hidden');
      els.fwdPanel.style.flex = count > 1 ? '1 1 50%' : '1 1 auto';
    } else {
      els.fwdPanel.classList.add('hidden');
    }
    scheduleResize(true);
  }

  function toggleSftp() {
    if (!connected) {
      setStatus('error', '请先建立 SSH 连接');
      return;
    }
    sftpEnabled = !sftpEnabled;
    if (sftpEnabled) {
      els.btnSftp.classList.add('active');
      els.sftpFrame.src = 'sftp.html';
    } else {
      els.btnSftp.classList.remove('active');
      els.sftpFrame.src = 'about:blank';
    }
    refreshLeftCol();
  }
  els.btnSftp.addEventListener('click', toggleSftp);

  function toggleFwd() {
    if (!connected) {
      setStatus('error', '请先建立 SSH 连接');
      return;
    }
    fwdEnabled = !fwdEnabled;
    if (fwdEnabled) {
      els.btnFwd.classList.add('active');
      // 只在 iframe 未加载时设置 src（复用已有 iframe 保留历史）
      if (!els.fwdFrame.src || els.fwdFrame.src === 'about:blank') {
        els.fwdFrame.src = 'portforward.html';
      }
    } else {
      els.btnFwd.classList.remove('active');
      // 不重载 iframe，保留历史
    }
    refreshLeftCol();
  }
  els.btnFwd.addEventListener('click', toggleFwd);

  /* ---- 左侧列分隔条拖拽（调整宽度） ---- */
  (function setupSplitter() {
    let dragging = false;
    let startX = 0;
    let startW = 0;

    els.sftpSplitter.addEventListener('mousedown', function (ev) {
      if (!sftpEnabled && !fwdEnabled) return;
      ev.preventDefault();
      dragging = true;
      els.sftpSplitter.classList.add('dragging');
      startX = ev.clientX;
      // 用 px 计算更稳定
      startW = els.leftCol.getBoundingClientRect().width;
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    });
    document.addEventListener('mousemove', function (ev) {
      if (!dragging) return;
      // 拖拽分隔条：向右拖 = 增大左侧列
      let delta = ev.clientX - startX;
      let newW = startW + delta;
      let mainW = els.leftCol.parentElement.getBoundingClientRect().width;
      let minW = 240, maxW = Math.max(minW, mainW * 0.8);
      if (newW < minW) newW = minW;
      if (newW > maxW) newW = maxW;
      els.leftCol.style.flex = '0 0 ' + newW + 'px';
      scheduleResize(false);
    });
    document.addEventListener('mouseup', function () {
      if (!dragging) return;
      dragging = false;
      els.sftpSplitter.classList.remove('dragging');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      // 持久化宽度
      let w = els.leftCol.getBoundingClientRect().width;
      if (w) storeSet('wssh.sftpW', Math.round(w) + 'px');
      scheduleResize(true);
    });
  })();

  // 供 iframe (sftp.html) 调用：获取/创建 SFTP 客户端
  window._wssh_getSftpClient = async function () {
    if (!connected || !client) throw new Error('SSH 未连接');
    if (!sftpClient || sftpClient._ch.closed) {
      let ch = await client.openSftp({
        onClose: function () { sftpClient = null; }
      });
      sftpClient = new WSSH.SftpClient(ch);
      await sftpClient.init();
    }
    return sftpClient;
  };

  // 跨域 fallback：iframe (sftp.html) 通过 postMessage 调用 SFTP 方法
  // 协议：{type:'sftp-call', id, method, args} → {type:'sftp-result', id, ok, result|error}
  window.addEventListener('message', async function (ev) {
    let data = ev.data;
    if (!data || data.type !== 'sftp-call') return;
    let msgId = data.id;
    let reply = function (ok, payload) {
      let resp = { type: 'sftp-result', id: msgId, ok: ok };
      if (ok) resp.result = payload;
      else resp.error = payload;
      try { ev.source.postMessage(resp, '*'); } catch (e) { }
    };
    try {
      let sftp = await window._wssh_getSftpClient();
      if (typeof sftp[data.method] !== 'function') {
        throw new Error('未知 SFTP 方法: ' + data.method);
      }
      let result = await sftp[data.method].apply(sftp, data.args || []);
      reply(true, result);
    } catch (e) {
      reply(false, e.message);
    }
  });

  // 供 iframe 调用：获取当前连接信息
  window._wssh_getConnInfo = function () {
    return {
      username: els.username.value.trim(),
      wsurl: els.wsurl.value.trim(),
      svraddr: els.svraddr.value.trim()
    };
  };

  /* ================= 端口转发通道管理 ================= */
  let fwdSeq = 0;

  // 打开一条端口转发通道，返回 forwardId
  window._wssh_openForward = async function (destHost, destPort) {
    if (!connected || !client) throw new Error('SSH 未连接');
    let id = ++fwdSeq;
    let ch = await client.openDirectTcpip(
      { destHost: destHost, destPort: destPort, originHost: '127.0.0.1', originPort: 0 },
      {
        onData: function (data) {
          // 推送数据到 iframe（以十六进制字符串传输，避免二进制跨域序列化问题）
          let hex = WSSH.util.hex(data);
          try {
            els.fwdFrame.contentWindow.postMessage(
              { type: 'fwd-event', id: id, event: 'data', hex: hex }, '*');
          } catch (e) { }
        },
        onClose: function () {
          delete fwdChannels[id];
          try {
            els.fwdFrame.contentWindow.postMessage(
              { type: 'fwd-event', id: id, event: 'close' }, '*');
          } catch (e) { }
        }
      }
    );
    fwdChannels[id] = ch;
    return id;
  };

  function hexToBytes(hex) {
    hex = String(hex).replace(/[^0-9a-fA-F]/g, '');
    let arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++) {
      arr[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return arr;
  }

  window._wssh_sendForward = async function (id, hex) {
    let ch = fwdChannels[id];
    if (!ch || ch.closed) throw new Error('转发通道不存在或已关闭');
    await ch.sendData(hexToBytes(hex));
  };

  window._wssh_closeForward = function (id) {
    let ch = fwdChannels[id];
    if (ch) {
      delete fwdChannels[id];
      try { ch.close(); } catch (e) { }
    }
  };

  /* ================= 远程转发（Remote Forwarding） ================= */
  let remoteFwdSeq = 0;
  let remoteConnSeq = 0;

  // 向转发 iframe 推送事件 
  function postFwdEvent(evt) {
    try { els.fwdFrame.contentWindow.postMessage(evt, '*'); } catch (e) { }
  }

  // 服务器侧监听端口收到新连接时回调
  function handleForwardedTcpip(ch, info) {
    let connId = ++remoteConnSeq;
    remoteFwdChannels[connId] = ch;

    let notified = false;
    function notifyClose(reason) {
      if (notified) return;
      notified = true;
      delete remoteFwdChannels[connId];
      postFwdEvent({
        type: 'fwd-event', remote: true, connId: String(connId),
        event: 'close', reason: reason || ''
      });
    }

    ch.cbs.onData = function (data) {
      postFwdEvent({ type: 'fwd-event', remote: true, connId: String(connId), event: 'data', hex: WSSH.util.hex(data) });
    };
    ch.cbs.onEOF = function () {
      // EOF 是半关闭：对端不再发数据，但通道仍可向对端发送，不删除通道
      postFwdEvent({
        type: 'fwd-event', remote: true, connId: String(connId), event: 'eof'
      });
    };
    ch.cbs.onClose = function () {
      notifyClose('close');
    };

    postFwdEvent({
      type: 'fwd-event', remote: true, connId: connId, event: 'open',
      info: {
        connectedAddr: info.connectedAddr,
        connectedPort: info.connectedPort,
        originAddr: info.originAddr,
        originPort: info.originPort
      }
    });
  }

  // 启动远程端口转发：请求服务器在 bindAddr:bindPort 监听
  window._wssh_startRemoteForward = async function (bindAddr, bindPort) {
    if (!connected || !client) throw new Error('SSH 未连接');
    let res = await client.requestTcpipForward(bindAddr || '', bindPort || 0);
    if (!res || typeof res.port !== 'number') {
      throw new Error('服务器未返回有效的监听端口');
    }
    let listenerId = ++remoteFwdSeq;
    remoteFwdListeners[listenerId] = { bindAddr: bindAddr || '', bindPort: res.port };
    return { listenerId: listenerId, port: res.port };
  };

  // 停止远程端口转发
  window._wssh_stopRemoteForward = async function (listenerId) {
    let l = remoteFwdListeners[listenerId];
    if (!l) {
      // 记录丢失：尝试取消所有已知监听
      let keys = Object.keys(remoteFwdListeners);
      if (keys.length === 0) {
        postFwdEvent({ type: 'fwd-event', remote: true, event: 'reset' });
        return;
      }
      for (let k of keys) {
        let it = remoteFwdListeners[k];
        try {
          await client.cancelTcpipForward(it.bindAddr, it.bindPort);
        } catch (e) {
          console.warn('cancel failed', it, e);
        }
        delete remoteFwdListeners[k];
      }
      postFwdEvent({ type: 'fwd-event', remote: true, event: 'reset' });
      return;
    }
    // 先关闭所有已建立的远程连接通道（ch.close() 会同步触发 onClose 通知 UI）
    let closePromises = Object.keys(remoteFwdChannels).map(function (cid) {
      let ch = remoteFwdChannels[cid];
      delete remoteFwdChannels[cid];
      if (!ch || ch.closed) return Promise.resolve();
      try { return ch.close(); } catch (e) { return Promise.resolve(); }
    });
    await Promise.all(closePromises);

    // 再发送 cancel-tcpip-forward，等待服务器确认端口已停止监听
    await client.cancelTcpipForward(l.bindAddr, l.bindPort);
    delete remoteFwdListeners[listenerId];
  };

  window._wssh_sendRemote = async function (connId, hex) {
    let ch = remoteFwdChannels[connId];
    if (!ch || ch.closed) throw new Error('远程连接不存在或已关闭');
    await ch.sendData(hexToBytes(hex));
  };

  window._wssh_closeRemote = function (connId) {
    let ch = remoteFwdChannels[connId];
    if (ch) {
      delete remoteFwdChannels[connId];
      try { ch.close(); } catch (e) { }
    }
  };

  // iframe 通过 postMessage 调用转发方法
  // 协议：{type:'fwd-call', id, method, args} → {type:'fwd-result', id, ok, result|error}
  window.addEventListener('message', async function (ev) {
    let data = ev.data;
    if (!data || data.type !== 'fwd-call') return;
    let msgId = data.id;
    let reply = function (ok, payload) {
      let resp = { type: 'fwd-result', id: msgId, ok: ok };
      if (ok) resp.result = payload;
      else resp.error = payload;
      try { ev.source.postMessage(resp, '*'); } catch (e) { }
    };
    try {
      let result;
      if (data.method === 'open') {
        result = await window._wssh_openForward(data.args[0], data.args[1]);
      } else if (data.method === 'send') {
        await window._wssh_sendForward(data.args[0], data.args[1]);
        result = null;
      } else if (data.method === 'close') {
        window._wssh_closeForward(data.args[0]);
        result = null;
      } else if (data.method === 'startRemote') {
        result = await window._wssh_startRemoteForward(data.args[0], data.args[1]);
      } else if (data.method === 'stopRemote') {
        await window._wssh_stopRemoteForward(data.args[0]);
        result = null;
      } else if (data.method === 'sendRemote') {
        await window._wssh_sendRemote(data.args[0], data.args[1]);
        result = null;
      } else if (data.method === 'closeRemote') {
        window._wssh_closeRemote(data.args[0]);
        result = null;
      } else {
        throw new Error('未知转发方法: ' + data.method);
      }
      reply(true, result);
    } catch (e) {
      reply(false, e.message);
    }
  });

  /* ================= xterm 初始化 ================= */
  function initTerminal() {
    term = new Terminal({
      cursorBlink: true,
      fontFamily: 'Consolas, "Cascadia Mono", "Courier New", monospace',
      fontSize: 14,
      scrollback: 5000,
      theme: {
        background: '#11111b',
        foreground: '#cdd6f4',
        cursor: '#f5e0dc',
        selectionBackground: '#585b70'
      }
    });
    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(els.terminal);
    try { fitAddon.fit(); } catch (e) { }

    term.onData(function (data) {
      if (channel && !channel.closed) channel.sendData(data);
    });

    if (window.ResizeObserver) {
      let ro = new ResizeObserver(function () { scheduleResize(false); });
      ro.observe(els.terminalWrap);
    }
    window.addEventListener('resize', function () { scheduleResize(false); });
  }

  function scheduleResize(sendNow) {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      if (!term) return;
      try { fitAddon.fit(); } catch (e) { return; }
      if (channel && !channel.closed) {
        channel.resize(term.cols, term.rows,
          els.terminalWrap.clientWidth, els.terminalWrap.clientHeight);
      }
    }, sendNow ? 0 : 120);
  }

  /* ================= WebSocket 包装 ================= */
  function openWebSocket(url) {
    return new Promise(function (resolve, reject) {
      let sock;
      try {
        sock = new WebSocket(url);
      } catch (e) {
        reject(new Error('WebSocket 地址无效: ' + url));
        return;
      }
      sock.binaryType = 'arraybuffer';
      let settled = false;
      let timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        try { sock.close(); } catch (e) { }
        reject(new Error('连接超时（10 秒），请确认 websocat 已启动: ' + url));
      }, 10000);

      let stream = {
        send: function (data) {
          if (sock.readyState === 1) sock.send(data);
        },
        close: function () {
          try { sock.close(); } catch (e) { }
        }
      };

      sock.onopen = function () {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(stream);
      };
      sock.onmessage = function (ev) {
        if (stream.onmessage) stream.onmessage(new Uint8Array(ev.data));
      };
      sock.onclose = function () {
        if (stream.onclose) stream.onclose();
      };
      sock.onerror = function () {
        if (stream.onerror) stream.onerror(new Error('WebSocket 连接错误'));
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(new Error('无法连接到 ' + url + '，请确认 websocat 已启动'));
        }
      };
    });
  }

  /* ================= 主机密钥确认 ================= */
  function hostPortId(wsUrl) {
    try {
      let u = new URL(wsUrl);
      return u.host;
    } catch (e) {
      return wsUrl;
    }
  }

  function confirmHostKey(wsUrl, info) {
    let storeKey = 'wssh.hk.' + hostPortId(wsUrl) + '.' + info.type;
    let saved = storeGet(storeKey);
    if (saved && saved === info.fingerprint) {
      return Promise.resolve(true);
    }

    return new Promise(function (resolve) {
      let answered = false;
      els.hkType.textContent = info.type + (info.comment ? ' (' + info.comment + ')' : '');
      els.hkFp.textContent = info.fingerprint;
      if (saved) {
        els.hkTitle.textContent = '警告：服务器主机密钥与本机保存的不一致（可能主机重装或遭遇中间人攻击），请核对！';
        els.hkRemember.checked = false;
      } else {
        els.hkTitle.textContent = '首次连接，请核对服务器主机密钥指纹：';
        els.hkRemember.checked = true;
      }
      els.hkBar.style.display = 'flex';

      function cleanup(trust) {
        if (answered) return;
        answered = true;
        els.hkBar.style.display = 'none';
        els.btnHkTrust.removeEventListener('click', onTrust);
        els.btnHkReject.removeEventListener('click', onReject);
        if (trust && els.hkRemember.checked) storeSet(storeKey, info.fingerprint);
        if (trust && !els.hkRemember.checked) storeDel(storeKey);
        resolve(trust);
      }
      function onTrust() { cleanup(true); }
      function onReject() { cleanup(false); }
      els.btnHkTrust.addEventListener('click', onTrust);
      els.btnHkReject.addEventListener('click', onReject);
    });
  }

  /* ================= UI 状态切换 ================= */
  function setFormConnectedUI(on) {
    //[els.wsurl, els.svraddr, els.username, els.password, els.keyfile, els.keypassphrase,
    //  els.tabPassword, els.tabKey, els.btnConfig].forEach(function (el) { el.disabled = on; });
    let ellist = [$('f-wsurl'), $('f-svraddr'), $('f-user'), $('f-auth-mode')];
    if (authMode === 'key') {
        ellist.push($('f-keyfile'), $('f-keypass'));
    }else{
        ellist.push($('f-password'));
    }
    ellist.forEach(function (el) { 
        el.style.display = on ? 'none' : ''; 
    });
    if (on) {
      els.btnConnect.textContent = '断 开';
      els.btnConnect.classList.add('disconnect');
    } else {
      els.btnConnect.textContent = '连 接';
      els.btnConnect.classList.remove('disconnect');
    }
  }

  function readKeyFile(file) {
    return new Promise(function (resolve, reject) {
      let fr = new FileReader();
      fr.onload = function () { resolve(fr.result); };
      fr.onerror = function () { reject(new Error('读取私钥文件失败')); };
      fr.readAsText(file);
    });
  }

  /* ================= 连接主流程 ================= */
  async function doConnect() {
    let wsUrl = els.wsurl.value.trim();
    let svrAddr = els.svraddr.value.trim();
    let username = els.username.value.trim();
    if (!wsUrl) { setStatus('error', '请填写 WebSocket 地址'); return; }
    if (!username) { setStatus('error', '请填写用户名'); return; }
    if (!/^wss?:\/\//.test(wsUrl)) { setStatus('error', '地址需以 ws:// 或 wss:// 开头'); return; }
    let wsUrl2 = (svrAddr) ? (wsUrl + "?peeraddr=" + svrAddr) : wsUrl;

    let privateKey = null;
    let password = '';
    let keyText = '';
    if (authMode === 'key') {
      if (!selectedKeyFile) { setStatus('error', '请选择私钥文件'); return; }
      setStatus('connecting', '正在解析私钥…');
      try {
        keyText = typeof(selectedKeyFile) == 'string'? selectedKeyFile : await readKeyFile(selectedKeyFile);
        privateKey = await WSSH.keys.parsePrivateKey(
          keyText, els.keypassphrase.value || '', selectedKeyFile.name);
      } catch (e) {
        setStatus('error', e.message);
        return;
      }
    } else {
      password = els.password.value;
      if (!password) { setStatus('error', '请填写密码'); return; }
    }

    connecting = true;
    manualClose = false;
    els.btnConnect.disabled = true;
    setStatus('connecting', '正在连接 ' + wsUrl2 + ' …');
    els.tip.style.display = 'none';

    try {
      let stream = await openWebSocket(wsUrl2);
      ws = stream;
      setStatus('connecting', 'SSH 握手与认证中…');

      client = new WSSH.SSHClient();
      await client.connect({
        stream: stream,
        username: username,
        password: password,
        privateKey: privateKey,
        onHostKey: function (info) { return confirmHostKey(svrAddr || wsUrl, info); },
        onBanner: function (msg) { if (term) term.write(msg); },
        onForwardedTcpip: function (ch, info) { handleForwardedTcpip(ch, info); },
        onClose: function (err) { handleRemoteClose(err || null); }
      });

      try { fitAddon.fit(); } catch (e) { }
      channel = await client.openShell(
        {
          term: 'xterm-256color',
          cols: term.cols || 80,
          rows: term.rows || 24,
          width: els.terminalWrap.clientWidth || 0,
          height: els.terminalWrap.clientHeight || 0
        },
        {
          onData: function (data) {
            term.write(data);
          },
          onExit: function (code, signal) {
            let why = signal ? ('被信号 ' + signal + ' 终止') : ('退出码 ' + code);
            term.write('\r\n\x1b[90m[远端会话结束：' + why + ']\x1b[0m\r\n');
          },
          onClose: function () {
            handleRemoteClose(null);
          }
        }
      );

      connected = true;
      connecting = false;
      setStatus('connected', '已连接：' + username + '@' + hostPortId(svrAddr || wsUrl));
      setFormConnectedUI(true);
      els.btnConnect.disabled = false;
      term.focus();
      scheduleResize(true);

      storeSet('wssh.wsurl', wsUrl);
      storeSet('wssh.svraddr', svrAddr);
      storeSet('wssh.user', username);
      if (typeof(selectedKeyFile) != 'string'){
        storeSet('wssh.key', keyText);
      }
    } catch (e) {
      connecting = false;
      els.btnConnect.disabled = false;
      setStatus('error', '连接失败：' + e.message);
      if (term) term.write('\r\n\x1b[31m[错误] ' + e.message + '\x1b[0m\r\n');
      cleanupConnection();
    }
  }

  // 关闭所有左侧面板（SFTP + 转发）并清理通道
  function closeAllPanels() {
    if (sftpEnabled) {
      sftpEnabled = false;
      els.btnSftp.classList.remove('active');
      els.sftpFrame.src = 'about:blank';
    }
    sftpClient = null;

    if (fwdEnabled) {
      // 注意：只隐藏面板，不重载 iframe，保留历史连接列表
      fwdEnabled = false;
      els.btnFwd.classList.remove('active');
      // 给 iframe 发 reset 事件（标记所有 open 连接为 closed）
      postFwdEvent({ type: 'fwd-event', remote: true, event: 'reset' });
      // 注意：这里不设 els.fwdFrame.src = 'about:blank'
    }

    Object.keys(fwdChannels).forEach(function (id) {
      try { fwdChannels[id].close(); } catch (e) { }
    });
    fwdChannels = {};
    Object.keys(remoteFwdChannels).forEach(function (id) {
      try { remoteFwdChannels[id].close(); } catch (e) { }
    });
    remoteFwdChannels = {};

    // 取消所有远程端口转发监听（异步执行，不阻塞 UI 关闭）
    let listeners = remoteFwdListeners;
    remoteFwdListeners = {};
    if (client && !client._closed && Object.keys(listeners).length > 0) {
      (async function () {
        for (let k of Object.keys(listeners)) {
          let it = listeners[k];
          try {
            await client.cancelTcpipForward(it.bindAddr, it.bindPort);
          } catch (e) {
            console.warn('cancel remote forward failed', it, e);
          }
        }
      })();
    }

    refreshLeftCol();
  }

  function handleRemoteClose(err) {
    if (!connected && !connecting) return;
    connected = false;
    connecting = false;
    setFormConnectedUI(false);
    els.btnConnect.disabled = false;
    closeAllPanels();
    if (manualClose) {
      setStatus('', '未连接');
      if (term) term.write('\r\n\x1b[90m[连接已断开]\x1b[0m\r\n');
    } else {
      setStatus('error', err ? ('连接已断开：' + err.message) : '连接已被服务器关闭');
      if (term) {
        term.write('\r\n\x1b[31m[连接已断开' + (err ? '：' + err.message : '') + ']\x1b[0m\r\n');
      }
    }
    channel = null;
    cleanupConnection();
  }

  function cleanupConnection() {
    if (client) {
      try { client.disconnect(); } catch (e) { }
    }
    if (ws) {
      try { ws.close(); } catch (e) { }
    }
    setTimeout(function () { client = null; ws = null; }, 0);
  }

  async function cancelAllRemoteForwards() {
    let keys = Object.keys(remoteFwdListeners);
    for (let k of keys) {
      let it = remoteFwdListeners[k];
      try {
        if (client && !client._closed) {
          await client.cancelTcpipForward(it.bindAddr, it.bindPort);
        }
      } catch (e) {
        console.warn('cancel remote forward failed', it, e);
      }
      delete remoteFwdListeners[k];
    }
  }

  async function doDisconnect() {
    manualClose = true;
    connected = false;
    connecting = false;
    setFormConnectedUI(false);
    setStatus('', '未连接');
    await cancelAllRemoteForwards();
    closeAllPanels();   
    if (channel) {
      let ch = channel;
      channel = null;
      try { ch.close(); } catch (e) { }
    }
    cleanupConnection();
  }

  /* ================= 绑定连接按钮 ================= */
  els.btnConnect.addEventListener('click', function () {
    if (connected || connecting) {
      if (connecting) {
        manualClose = true;
        connecting = false;
        els.btnConnect.disabled = false;
        setStatus('', '未连接');
        cleanupConnection();
      } else {
        doDisconnect();
      }
      return;
    }
    doConnect();
  });

  // 回车快捷连接（密码框内）
  [els.password, els.keypassphrase].forEach(function (inp) {
    inp.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' && !connected && !connecting) {
        ev.preventDefault();
        doConnect();
      }
    });
  });

  /* ================= 启动 ================= */
  (function init() {
    loadServerList();
    refreshSvrSelect(false);

    let savedUrl = storeGet('wssh.wsurl');
    let savedAddr = storeGet('wssh.svraddr');
    let savedUser = storeGet('wssh.user');
    let savedKey = storeGet('wssh.key');

    if (savedKey) selectedKeyFile = savedKey;

    if (savedUrl) els.wsurl.value = savedUrl;

    if (savedAddr) {
      let opts = els.svraddr.options;
      let found = false;
      for (let i = 0; i < opts.length; i++) {
        if (opts[i].value === savedAddr) {
          els.svraddr.value = savedAddr;
          found = true;
          break;
        }
      }
    }

    if (savedUser) els.username.value = savedUser;

    initTerminal();
    setStatus('', '未连接');
  })();

})();
