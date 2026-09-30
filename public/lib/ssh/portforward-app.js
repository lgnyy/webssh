/*!
 * portforward-app.js - 端口转发测试面板逻辑
 *  支持本地转发 (direct-tcpip) 与远程转发 (forwarded-tcpip)
 *  通过 postMessage 与父窗口 app.js 交互：
 *    调用:  {type:'fwd-call', id, method, args} → {type:'fwd-result', id, ok, result|error}
 *    事件:  {type:'fwd-event', ...}
 */
(function () {
  'use strict';

  let $ = function (id) { return document.getElementById(id); };
  let els = {
    modeLocal: $('mode-local'),
    modeRemote: $('mode-remote'),
    destHost: $('dest-host'),
    destPort: $('dest-port'),
    lblHost: $('lbl-host'),
    lblPort: $('lbl-port'),
    btnOpen: $('btn-open'),
    btnStart: $('btn-start'),
    connStatus: $('conn-status'),
    connStatusText: $('conn-status-text'),
    connListWrap: $('conn-list-wrap'),
    connListBody: $('conn-list-body'),
    recvText: $('recv-text'),
    recvModeHex: $('recv-mode-hex'),
    recvModeText: $('recv-mode-text'),
    recvClear: $('recv-clear'),
    sendText: $('send-text'),
    sendModeHex: $('send-mode-hex'),
    sendModeText: $('send-mode-text'),
    btnSend: $('btn-send'),
    statusMsg: $('status-msg'),
    rxBytes: $('rx-bytes'),
    txBytes: $('tx-bytes')
  };

  let mode = 'local';
  let recvMode = 'hex';
  let sendMode = 'hex';

  // 本地转发状态
  let fwdId = null;
  let localOpen = false;
  let localRx = 0, localTx = 0;

  // 远程转发状态
  let listenerId = null;
  let listening = false;
  let remoteConnections = {}; // connId -> { info, rx, tx, recvHex, state }
  let selectedConnId = null;
  let remoteBusy = false;

  let callSeq = 0;
  let callWaiters = {};

  /* ---------- 工具 ---------- */
  function setMsg(text) { els.statusMsg.textContent = text; }

  function hexToBytes(hex) {
    hex = String(hex).replace(/[^0-9a-fA-F]/g, '');
    if (hex.length % 2) hex = hex.slice(0, -1);
    let arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
    return arr;
  }
  function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return s;
  }
  function prettyHex(hex) {
    hex = String(hex).replace(/[^0-9a-fA-F]/g, '');
    let out = '';
    for (let i = 0; i < hex.length; i += 2) { if (i > 0) out += ' '; out += hex.substr(i, 2); }
    return out;
  }
  function bytesToText(bytes) {
    try { return new TextDecoder('utf-8', { fatal: false }).decode(bytes); } catch (e) { return ''; }
  }
  function textToBytes(text) { return new TextEncoder().encode(text); }

  /* ---------- postMessage ---------- */
  function callParent(method, args) {
    return new Promise(function (resolve, reject) {
      let id = ++callSeq;
      callWaiters[id] = function (ok, payload) {
        delete callWaiters[id];
        if (ok) resolve(payload); else reject(new Error(payload));
      };
      parent.postMessage({ type: 'fwd-call', id: id, method: method, args: args }, '*');
    });
  }

  window.addEventListener('message', function (ev) {
    let data = ev.data;
    if (!data) return;
    if (data.type === 'fwd-result') {
      let w = callWaiters[data.id];
      if (w) w(data.ok, data.ok ? data.result : data.error);
      return;
    }
    if (data.type === 'fwd-event') {
      if (data.remote) handleRemoteEvent(data);
      else handleLocalEvent(data);
    }
  });

  /* ---------- 模式切换 ---------- */
  function setMode(m) {
    mode = m;
    els.modeLocal.classList.toggle('active', m === 'local');
    els.modeRemote.classList.toggle('active', m === 'remote');
    if (m === 'local') {
      els.lblHost.textContent = '目标主机';
      els.lblPort.textContent = '目标端口';
      els.btnOpen.style.display = '';
      els.btnStart.style.display = 'none';
      els.connListWrap.classList.add('hidden');
      updateLocalUI();
    } else {
      els.lblHost.textContent = '监听地址';
      els.lblPort.textContent = '监听端口';
      els.btnOpen.style.display = 'none';
      els.btnStart.style.display = '';
      els.connListWrap.classList.remove('hidden');
      updateRemoteUI();
    }
  }
  els.modeLocal.addEventListener('click', function () { setMode('local'); });
  els.modeRemote.addEventListener('click', function () { setMode('remote'); });

  /* ================= 本地转发 ================= */
  function handleLocalEvent(ev) {
    if (ev.id !== fwdId) return;
    if (ev.event === 'data') {
      let bytes = hexToBytes(ev.hex);
      localRx += bytes.length;
      els.rxBytes.textContent = localRx;
      let chunk = recvMode === 'hex' ? prettyHex(ev.hex) : bytesToText(bytes);
      if (els.recvText.value) els.recvText.value += (recvMode === 'hex' ? ' ' : '') + chunk;
      else els.recvText.value = chunk;
      els.recvText.scrollTop = els.recvText.scrollHeight;
    } else if (ev.event === 'close') {
      setLocalOpen(false);
      setMsg('远端关闭连接');
    }
  }

  function setLocalOpen(on) {
    localOpen = on;
    if (on) {
      els.btnOpen.textContent = '关 闭';
      els.btnOpen.classList.add('active');
      els.connStatus.className = 'open';
      els.connStatusText.textContent = '已连接 ' + els.destHost.value.trim() + ':' + els.destPort.value.trim();
      els.btnSend.disabled = false;
    } else {
      els.btnOpen.textContent = '打 开';
      els.btnOpen.classList.remove('active');
      els.connStatus.className = '';
      els.connStatusText.textContent = '未连接';
      els.btnSend.disabled = true;
      fwdId = null;
    }
  }

  function updateLocalUI() {
    setLocalOpen(localOpen);
    els.rxBytes.textContent = localRx;
    els.txBytes.textContent = localTx;
  }

  async function doOpenLocal() {
    if (localOpen) {
      try { if (fwdId != null) await callParent('close', [fwdId]); } catch (e) { }
      setLocalOpen(false);
      setMsg('已关闭');
      return;
    }
    let host = els.destHost.value.trim();
    let port = parseInt(els.destPort.value.trim(), 10);
    if (!host) { setMsg('请输入目标主机'); return; }
    if (!port || port < 1 || port > 65535) { setMsg('端口需为 1-65535'); return; }
    els.btnOpen.disabled = true;
    setMsg('正在建立转发通道…');
    els.connStatus.className = '';
    els.connStatusText.textContent = '连接中…';
    try {
      fwdId = await callParent('open', [host, port]);
      setLocalOpen(true);
      setMsg('转发通道已建立');
    } catch (e) {
      els.connStatus.className = 'error';
      els.connStatusText.textContent = '连接失败';
      setMsg('打开失败: ' + e.message);
    } finally {
      els.btnOpen.disabled = false;
    }
  }
  els.btnOpen.addEventListener('click', doOpenLocal);

  /* ================= 远程转发 ================= */
  function handleRemoteEvent(ev) {
    if (ev.event === 'reset') {
      listenerId = null;
      listening = false;
      setRemoteListening(false);
      // 保留历史连接记录，只把所有 open 标记为 closed
      Object.keys(remoteConnections).forEach(function (cid) {
        if (remoteConnections[cid].state === 'open') {
          remoteConnections[cid].state = 'closed';
        }
      });
      renderConnList();
      if (selectedConnId != null) {
        let c = remoteConnections[selectedConnId];
        els.btnSend.disabled = !c || c.state !== 'open';
      } else {
        els.btnSend.disabled = true;
      }
      setMsg('SSH 连接已断开，转发已停止（历史连接保留）');
      return;
    }

    // 关键：connId 统一转成字符串，避免 === 比较类型不一致
    let connId = String(ev.connId);

    if (ev.event === 'open') {
      remoteConnections[connId] = {
        info: ev.info, rx: 0, tx: 0, recvHex: '', state: 'open', eofReceived: false
      };
      renderConnList();
      // 没有选中任何连接时，自动选中新连接
      if (selectedConnId == null) {
        selectConn(connId);
      }
      // 即使已有选中连接，也更新列表让新连接可见
      setMsg('新连接 #' + connId + ' 来自 ' + ev.info.originAddr + ':' + ev.info.originPort);
    } else if (ev.event === 'data') {
      let c = remoteConnections[connId];
      if (!c) return;
      let bytes = hexToBytes(ev.hex);
      c.rx += bytes.length;
      c.recvHex += (c.recvHex ? ' ' : '') + ev.hex;
      if (connId === selectedConnId) {
        els.rxBytes.textContent = c.rx;
        let chunk = recvMode === 'hex' ? prettyHex(ev.hex) : bytesToText(bytes);
        if (els.recvText.value) {
          els.recvText.value += (recvMode === 'hex' ? ' ' : '') + chunk;
        } else {
          els.recvText.value = chunk;
        }
        els.recvText.scrollTop = els.recvText.scrollHeight;
      }
      renderConnList();
    } else if (ev.event === 'eof') {
      // 对端发送 EOF：不再接收数据，但仍可向对端发送（半关闭）
      let c = remoteConnections[connId];
      if (c) {
        c.eofReceived = true;
        renderConnList();
      }
      setMsg('连接 #' + connId + ' 对端已 EOF（仍可发送数据）');
    } else if (ev.event === 'close') {
      let c = remoteConnections[connId];
      if (c) { c.state = 'closed'; renderConnList(); }
      if (connId === selectedConnId) {
        els.btnSend.disabled = true;
      }
      setMsg('连接 #' + connId + ' 已关闭');
    }
  }

  function renderConnList() {
    els.connListBody.innerHTML = '';
    Object.keys(remoteConnections).forEach(function (cid) {   // cid 已是字符串
      let c = remoteConnections[cid];
      let tr = document.createElement('tr');
      if (cid === selectedConnId) tr.classList.add('selected');  // 严格相等，类型一致
      if (c.state === 'closed') tr.classList.add('closed');
      // 状态图标：●=打开 ◐=对端EOF(半关闭) ○=已关闭
      let stateIcon = '○';
      if (c.state === 'open') stateIcon = c.eofReceived ? '◐' : '●';
      tr.innerHTML =
        '<td class="cid">#' + cid + '</td>' +
        '<td class="origin">' + (c.info.originAddr || '') + ':' + c.info.originPort + '</td>' +
        '<td class="origin">' + (c.info.connectedAddr || '') + ':' + c.info.connectedPort + '</td>' +
        '<td class="state" title="' + (c.state === 'open' ? (c.eofReceived ? '对端已 EOF（半关闭）' : '连接中') : '已关闭') + '">' + stateIcon + '</td>' +
        '<td class="act"><button class="del-btn" type="button" title="关闭连接" ' +
        (c.state === 'open' ? '' : 'disabled') + '>✕</button></td>';
      tr.addEventListener('click', function (ev) {
        if (ev.target.classList.contains('del-btn')) return;
        selectConn(cid);
      });
      tr.querySelector('.del-btn').addEventListener('click', function (ev) {
        ev.stopPropagation();
        closeRemoteConn(cid);
      });
      els.connListBody.appendChild(tr);
    });
  }

  function selectConn(cid) {
    selectedConnId = cid;
    let c = remoteConnections[cid];
    renderConnList();
    if (c) {
      els.recvText.value = recvMode === 'hex' ? prettyHex(c.recvHex) : bytesToText(hexToBytes(c.recvHex));
      els.rxBytes.textContent = c.rx;
      els.txBytes.textContent = c.tx;
      els.btnSend.disabled = c.state !== 'open';
    } else {
      els.recvText.value = '';
      els.rxBytes.textContent = '0';
      els.txBytes.textContent = '0';
      els.btnSend.disabled = true;
    }
  }

  function setRemoteListening(on, port) {
    listening = on;
    if (on) {
      els.btnStart.textContent = '停止监听';
      els.btnStart.classList.add('active');
      els.connStatus.className = 'open';
      els.connStatusText.textContent = '监听中 ' + els.destHost.value.trim() + ':' + (port || els.destPort.value.trim());
    } else {
      els.btnStart.textContent = '开始监听';
      els.btnStart.classList.remove('active');
      els.connStatus.className = '';
      els.connStatusText.textContent = '未监听';
    }
  }

  function updateRemoteUI() {
    setRemoteListening(listening);
    if (selectedConnId != null) selectConn(selectedConnId);
    else { els.recvText.value = ''; els.rxBytes.textContent = '0'; els.txBytes.textContent = '0'; }
  }

  async function doStartRemote() {
    if (remoteBusy) return;
    if (listening) {
      remoteBusy = true;
      els.btnStart.disabled = true;
      try {
        if (listenerId != null) {
          await callParent('stopRemote', [listenerId]);
        }
        listenerId = null;
        setRemoteListening(false);
        // 保留历史连接记录，只把所有 open 标记为 closed
        Object.keys(remoteConnections).forEach(function (cid) {
          if (remoteConnections[cid].state === 'open') {
            remoteConnections[cid].state = 'closed';
          }
        });
        renderConnList();
        if (selectedConnId != null) {
          let c = remoteConnections[selectedConnId];
          els.btnSend.disabled = !c || c.state !== 'open';
        } else {
          els.btnSend.disabled = true;
        }
        setMsg('已停止监听（历史连接保留）');
      } catch (e) {
        listenerId = null;
        setRemoteListening(false);
        setMsg('停止失败: ' + e.message);
      } finally {
        remoteBusy = false;
        els.btnStart.disabled = false;
      }
      return;
    }
    let addr = els.destHost.value.trim();
    let port = parseInt(els.destPort.value.trim(), 10) || 0;
    els.btnStart.disabled = true;
    setMsg('正在请求服务器监听端口…');
    els.connStatusText.textContent = '请求中…';
    try {
      let res = await callParent('startRemote', [addr, port]);
      listenerId = res.listenerId;
      setRemoteListening(true, res.port);
      setMsg('服务器已在 ' + addr + ':' + res.port + ' 监听');
    } catch (e) {
      els.connStatus.className = 'error';
      els.connStatusText.textContent = '监听失败';
      setMsg('监听失败: ' + e.message);
    } finally {
      els.btnStart.disabled = false;
    }
  }
  els.btnStart.addEventListener('click', doStartRemote);

  /* ================= 发送数据 ================= */
  async function doSend() {
    let raw = els.sendText.value;
    let bytes = sendMode === 'hex' ? hexToBytes(raw) : textToBytes(raw);
    if (bytes.length === 0) { setMsg(sendMode === 'hex' ? 'HEX 内容为空或无效' : '发送内容为空'); return; }
    let hex = bytesToHex(bytes);

    els.btnSend.disabled = true;
    try {
      if (mode === 'local') {
        if (!localOpen || fwdId == null) return;
        await callParent('send', [fwdId, hex]);
        localTx += bytes.length;
        els.txBytes.textContent = localTx;
      } else {
        if (selectedConnId == null) return;
        await callParent('sendRemote', [selectedConnId, hex]);
        let c = remoteConnections[selectedConnId];
        if (c) { c.tx += bytes.length; els.txBytes.textContent = c.tx; }
      }
      setMsg('已发送 ' + bytes.length + ' 字节');
    } catch (e) {
      setMsg('发送失败: ' + e.message);
    } finally {
      if (mode === 'local') els.btnSend.disabled = !localOpen;
      else {
        let c = remoteConnections[selectedConnId];
        els.btnSend.disabled = !c || c.state !== 'open';
      }
    }
  }
  els.btnSend.addEventListener('click', doSend);

  // 关闭远程转发的单个连接（由列表中的删除按钮触发）
  async function closeRemoteConn(cid) {
    // 乐观更新：立即标记为关闭，避免等待往返
    let c = remoteConnections[cid];
    if (c) {
      c.state = 'closed';
      renderConnList();
      if (cid === selectedConnId) els.btnSend.disabled = true;
    }
    try {
      await callParent('closeRemote', [cid]);
      setMsg('已关闭连接 #' + cid);
    } catch (e) {
      setMsg('关闭失败: ' + e.message);
    }
  }

  els.sendText.addEventListener('keydown', function (ev) {
    if (ev.ctrlKey && ev.key === 'Enter') { ev.preventDefault(); doSend(); }
  });

  /* ================= 显示模式切换 ================= */
  els.recvModeHex.addEventListener('click', function () {
    recvMode = 'hex';
    els.recvModeHex.classList.add('active');
    els.recvModeText.classList.remove('active');
    refreshRecvDisplay();
  });
  els.recvModeText.addEventListener('click', function () {
    recvMode = 'text';
    els.recvModeText.classList.add('active');
    els.recvModeHex.classList.remove('active');
    refreshRecvDisplay();
  });
  els.sendModeHex.addEventListener('click', function () {
    sendMode = 'hex';
    els.sendModeHex.classList.add('active');
    els.sendModeText.classList.remove('active');
  });
  els.sendModeText.addEventListener('click', function () {
    sendMode = 'text';
    els.sendModeText.classList.add('active');
    els.sendModeHex.classList.remove('active');
  });
  els.recvClear.addEventListener('click', function () {
    els.recvText.value = '';
    if (mode === 'local') { localRx = 0; els.rxBytes.textContent = '0'; }
    else {
      let c = remoteConnections[selectedConnId];
      if (c) { c.rx = 0; c.recvHex = ''; els.rxBytes.textContent = '0'; }
    }
    setMsg('已清空接收区');
  });

  function refreshRecvDisplay() {
    if (mode === 'local') {
      // 本地模式未缓存原始 hex，仅提示
    } else {
      let c = remoteConnections[selectedConnId];
      if (c) {
        els.recvText.value = recvMode === 'hex' ? prettyHex(c.recvHex) : bytesToText(hexToBytes(c.recvHex));
      }
    }
    setMsg('已切换接收显示模式');
  }

  setMsg('就绪：选择本地或远程转发模式');
})();
