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
    sftpPanel: $('sftp-panel'),
    sftpFrame: $('sftp-frame'),
    sftpSplitter: $('sftp-splitter'),
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

  /* ================= SFTP 面板控制 ================= */
  function toggleSftp() {
    if (!connected) {
      setStatus('error', '请先建立 SSH 连接');
      return;
    }
    sftpEnabled = !sftpEnabled;
    if (sftpEnabled) {
      els.btnSftp.classList.add('active');
      // 恢复保存的宽度（默认 25%）
      let savedW = storeGet('wssh.sftpW');
      if (savedW && /^(\d+(px|%))$/.test(savedW)) {
        els.sftpPanel.style.flex = '0 0 ' + savedW;
      } else {
        els.sftpPanel.style.flex = '';
      }
      els.sftpPanel.style.display = 'flex';
      els.sftpSplitter.style.display = 'block';
      els.sftpFrame.src = 'sftp.html';
    } else {
      els.btnSftp.classList.remove('active');
      els.sftpPanel.style.display = 'none';
      els.sftpSplitter.style.display = 'none';
      els.sftpFrame.src = 'about:blank';
    }
    scheduleResize(true);
  }
  els.btnSftp.addEventListener('click', toggleSftp);

  /* ---- SFTP 分隔条拖拽（调整宽度） ---- */
  (function setupSplitter() {
    let dragging = false;
    let startX = 0;
    let startW = 0;

    els.sftpSplitter.addEventListener('mousedown', function (ev) {
      if (!sftpEnabled) return;
      ev.preventDefault();
      dragging = true;
      els.sftpSplitter.classList.add('dragging');
      startX = ev.clientX;
      // 用 px 计算更稳定
      startW = els.sftpPanel.getBoundingClientRect().width;
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    });
    document.addEventListener('mousemove', function (ev) {
      if (!dragging) return;
      // 拖拽分隔条：向右拖 = 增大 SFTP 面板
      let delta = ev.clientX - startX;
      let newW = startW + delta;
      let mainW = els.sftpPanel.parentElement.getBoundingClientRect().width;
      let minW = 240, maxW = Math.max(minW, mainW * 0.8);
      if (newW < minW) newW = minW;
      if (newW > maxW) newW = maxW;
      els.sftpPanel.style.flex = '0 0 ' + newW + 'px';
      scheduleResize(false);
    });
    document.addEventListener('mouseup', function () {
      if (!dragging) return;
      dragging = false;
      els.sftpSplitter.classList.remove('dragging');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      // 持久化宽度
      let w = els.sftpPanel.getBoundingClientRect().width;
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
    });      { 
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

  function handleRemoteClose(err) {
    if (!connected && !connecting) return;
    connected = false;
    connecting = false;
    setFormConnectedUI(false);
    els.btnConnect.disabled = false;
    // 关闭 SFTP
    if (sftpEnabled) {
      sftpEnabled = false;
      els.btnSftp.classList.remove('active');
      els.sftpPanel.style.display = 'none';
      els.sftpSplitter.style.display = 'none';
      els.sftpFrame.src = 'about:blank';
    }
    sftpClient = null;
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

  function doDisconnect() {
    manualClose = true;
    connected = false;
    connecting = false;
    setFormConnectedUI(false);
    setStatus('', '未连接');
    if (sftpEnabled) {
      sftpEnabled = false;
      els.btnSftp.classList.remove('active');
      els.sftpPanel.style.display = 'none';
      els.sftpSplitter.style.display = 'none';
      els.sftpFrame.src = 'about:blank';
    }
    sftpClient = null;
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
