/*!
 * sftp-app.js - SFTP 文件管理器逻辑
 *  通过 parent.window._wssh_getSftpClient() 获取 SFTP 客户端实例
 *  实现：文件列表、导航、上传、下载、删除、新建目录、目录上传/下载
 */
(function () {
  'use strict';

  let $ = function (id) { return document.getElementById(id); };
  let els = {
    btnUp: $('btn-up'),
    btnRefresh: $('btn-refresh'),
    btnGo: $('btn-go'),
    pathInput: $('path-input'),
    btnMkdir: $('btn-mkdir'),
    btnDelete: $('btn-delete'),
    btnDownload: $('btn-download'),
    btnUpload: $('btn-upload'),
    fileUpload: $('file-upload'),
    btnUploadDir: $('btn-upload-dir'),
    dirUpload: $('dir-upload'),
    filelistWrap: $('filelist-wrap'),
    filelistBody: $('filelist-body'),
    emptyState: $('empty-state'),
    statusMsg: $('status-msg'),
    itemCount: $('item-count'),
    progressOverlay: $('progress-overlay')
  };

  let sftp = null;
  let cwd = '/';
  let selectedItems = []; // [{ filename, attrs, path }]
  let busy = false;

  /* ================= 工具 ================= */
  function setMsg(text) { els.statusMsg.textContent = text; }

  function fmtSize(bytes) {
    if (bytes == null) return '-';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' K';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' M';
    return (bytes / 1073741824).toFixed(1) + ' G';
  }

  function fmtDate(ts) {
    if (!ts) return '-';
    let d = new Date(ts * 1000);
    let pad = function (n) { return n < 10 ? '0' + n : n; };
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
      ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  function joinPath(base, name) {
    if (base.endsWith('/')) return base + name;
    return base + '/' + name;
  }

  function parentPath(p) {
    if (p === '/' || p === '') return '/';
    let parts = p.split('/').filter(Boolean);
    if (parts.length <= 1) return '/';
    parts.pop();
    return '/' + parts.join('/');
  }

  function normalizePath(p) {
    if (!p) return '/';
    let parts = p.split('/').filter(Boolean);
    let resolved = [];
    for (let part of parts) {
      if (part === '.') continue;
      if (part === '..') { if (resolved.length) resolved.pop(); continue; }
      resolved.push(part);
    }
    return '/' + resolved.join('/');
  }

  function isDir(entry) {
    if (entry.attrs && entry.attrs.type != null) {
      return entry.attrs.type === 2; // TYPE_DIRECTORY
    }
    // 从 longname 判断
    if (entry.longname && entry.longname[0] === 'd') return true;
    return false;
  }

  function isLink(entry) {
    if (entry.longname && entry.longname[0] === 'l') return true;
    if (entry.attrs && entry.attrs.type === 3) return true;
    return false;
  }

  function iconHTML(entry) {
    if (isDir(entry)) return '<span class="icon-dir">📁</span>';
    if (isLink(entry)) return '<span class="icon-link">🔗</span>';
    return '<span class="icon-file">📄</span>';
  }

  /* ================= SFTP 客户端获取 ================= */
  // 直连模式（同源 http(s)）下可直接访问 parent.window._wssh_getSftpClient()
  // 跨域模式（file://）下 parent.window 抛 SecurityError，回退到 postMessage RPC 代理
  let directBlocked = false;
  let proxy = null;

  function canAccessParent() {
    if (directBlocked) return false;
    try {
      // 试图访问 parent.window 的属性；跨域会抛 SecurityError
      let _ = window.parent.location && window.parent.location.href;
      return true;
    } catch (e) {
      directBlocked = true;
      return false;
    }
  }

  function createSftpProxy() {
    if (proxy) return proxy;
    let callId = 0;
    let pending = {};
    window.addEventListener('message', function (ev) {
      if (!ev.data || ev.data.type !== 'sftp-result') return;
      let p = pending[ev.data.id];
      if (!p) return;
      delete pending[ev.data.id];
      if (ev.data.ok) p.resolve(ev.data.result);
      else p.reject(new Error(ev.data.error || 'SFTP 调用失败'));
    });
    let methods = ['init', 'realpath', 'stat', 'opendir', 'readdir',
      'mkdir', 'rmdir', 'remove', 'rename', 'openFile', 'readFile',
      'writeFile', 'closeFile', 'close', 'readFileAll', 'writeFileAll',
      'readDirAll', 'removeDirAll'];
    proxy = {
      _ch: { closed: false },
      _isProxy: true
    };
    methods.forEach(function (m) {
      proxy[m] = function () {
        let args = Array.from(arguments);
        let id = ++callId;
        return new Promise(function (resolve, reject) {
          pending[id] = { resolve: resolve, reject: reject };
          window.parent.postMessage({ type: 'sftp-call', id: id, method: m, args: args }, '*');
        });
      };
    });
    return proxy;
  }

  async function ensureSftp() {
    if (sftp && !sftp._ch.closed) return sftp;
    if (!window.parent || window.parent === window) {
      throw new Error('未找到父窗口，SFTP 不可用');
    }
    // 优先直连（同源时性能更好）
    if (canAccessParent() && window.parent._wssh_getSftpClient) {
      try {
        sftp = await window.parent._wssh_getSftpClient();
        return sftp;
      } catch (e) {
        // 直连失败（如 SSH 未连接），抛出原错误
        throw e;
      }
    }
    // 回退到 postMessage RPC 代理
    sftp = createSftpProxy();
    // 触发一次 init 让父窗口初始化（如果未连接会返回错误）
    try { await sftp.init(); } catch (e) {
      sftp = null;
      throw e;
    }
    return sftp;
  }

  /* ================= 文件列表 ================= */
  async function loadDir(path) {
    if (busy) return;
    busy = true;
    selectedItems = [];
    updateButtonStates();
    setMsg('正在读取目录…');

    try {
      let client = await ensureSftp();
      let realPath = await client.realpath(path || cwd);
      cwd = realPath;
      els.pathInput.value = cwd;

      let entries = await client.readDirAll(cwd);

      // 排序：目录在前，名称字母序
      entries.sort(function (a, b) {
        let ad = isDir(a), bd = isDir(b);
        if (ad && !bd) return -1;
        if (!ad && bd) return 1;
        return a.filename.localeCompare(b.filename, undefined, { sensitivity: 'base' });
      });

      renderList(entries);
      setMsg('目录: ' + cwd + ' (' + entries.length + ' 项)');
      els.itemCount.textContent = entries.length + ' 项';
    } catch (e) {
      setMsg('错误: ' + e.message);
      renderList([]);
      els.itemCount.textContent = '0 项';
    } finally {
      busy = false;
    }
  }

  function renderList(entries) {
    els.filelistBody.innerHTML = '';
    if (entries.length === 0) {
      els.emptyState.style.display = 'flex';
      return;
    }
    els.emptyState.style.display = 'none';

    for (let entry of entries) {
      let tr = document.createElement('tr');
      tr.dataset.name = entry.filename;

      let tdIcon = document.createElement('td');
      tdIcon.className = 'icon';
      tdIcon.innerHTML = iconHTML(entry);

      let tdName = document.createElement('td');
      tdName.className = 'name';
      tdName.textContent = entry.filename;
      tdName.title = entry.longname || entry.filename;

      let tdSize = document.createElement('td');
      tdSize.className = 'size';
      tdSize.textContent = isDir(entry) ? '-' : fmtSize(entry.attrs && entry.attrs.size);

      let tdDate = document.createElement('td');
      tdDate.className = 'date';
      tdDate.textContent = fmtDate(entry.attrs && entry.attrs.mtime);

      tr.appendChild(tdIcon);
      tr.appendChild(tdName);
      tr.appendChild(tdSize);
      tr.appendChild(tdDate);

      // 单击选中/取消
      tr.addEventListener('click', function (ev) {
        ev.stopPropagation();
        if (ev.ctrlKey || ev.metaKey) {
          // 多选
          if (tr.classList.contains('selected')) {
            tr.classList.remove('selected');
            selectedItems = selectedItems.filter(function (it) { return it.filename !== entry.filename; });
          } else {
            tr.classList.add('selected');
            selectedItems.push({ filename: entry.filename, attrs: entry.attrs, path: joinPath(cwd, entry.filename), isDir: isDir(entry) });
          }
        } else {
          // 单选
          els.filelistBody.querySelectorAll('tr.selected').forEach(function (r) { r.classList.remove('selected'); });
          tr.classList.add('selected');
          selectedItems = [{ filename: entry.filename, attrs: entry.attrs, path: joinPath(cwd, entry.filename), isDir: isDir(entry) }];
        }
        updateButtonStates();
      });

      // 双击：目录=进入，文件=下载
      tr.addEventListener('dblclick', function (ev) {
        ev.preventDefault();
        if (isDir(entry)) {
          loadDir(joinPath(cwd, entry.filename));
        } else {
          downloadFile(joinPath(cwd, entry.filename), entry.filename);
        }
      });

      els.filelistBody.appendChild(tr);
    }
  }

  function updateButtonStates() {
    let hasSelection = selectedItems.length > 0;
    let singleSelected = selectedItems.length === 1;
    let canDownload = selectedItems.length > 0 && selectedItems.some(function (it) { return !it.isDir; });
    els.btnDelete.disabled = !hasSelection;
    els.btnDownload.disabled = !canDownload;
  }

  /* ================= 导航 ================= */
  els.btnUp.addEventListener('click', function () { loadDir(parentPath(cwd)); });
  els.btnRefresh.addEventListener('click', function () { loadDir(cwd); });
  els.btnGo.addEventListener('click', function () {
    let p = els.pathInput.value.trim();
    if (p) loadDir(normalizePath(p));
  });
  els.pathInput.addEventListener('keydown', function (ev) {
    if (ev.key === 'Enter') {
      let p = els.pathInput.value.trim();
      if (p) loadDir(normalizePath(p));
    }
  });

  /* ================= 新建目录 ================= */
  els.btnMkdir.addEventListener('click', async function () {
    let name = prompt('目录名称:', 'new_dir');
    if (!name) return;
    try {
      let client = await ensureSftp();
      await client.mkdir(joinPath(cwd, name));
      setMsg('已创建目录: ' + name);
      loadDir(cwd);
    } catch (e) {
      setMsg('创建失败: ' + e.message);
    }
  });

  /* ================= 删除 ================= */
  els.btnDelete.addEventListener('click', async function () {
    if (selectedItems.length === 0) return;
    let names = selectedItems.map(function (it) { return it.filename; }).join(', ');
    let dirCount = selectedItems.filter(function (it) { return it.isDir; }).length;
    let hint = '确定删除以下 ' + selectedItems.length + ' 项？\n' + names;
    if (dirCount > 0) {
      hint += '\n（其中 ' + dirCount + ' 个目录将递归删除所有内容）';
    }
    if (!confirm(hint)) return;
    let client = await ensureSftp();
    let ok = 0, fail = 0;
    for (let item of selectedItems) {
      try {
        if (item.isDir) {
          await client.removeDirAll(item.path);
        } else {
          await client.remove(item.path);
        }
        ok++;
      } catch (e) {
        fail++;
        setMsg('删除 ' + item.filename + ' 失败: ' + e.message);
      }
    }
    setMsg('删除完成: 成功 ' + ok + ', 失败 ' + fail);
    selectedItems = [];
    loadDir(cwd);
  });

  /* ================= 下载 ================= */
  async function downloadFile(remotePath, filename) {
    try {
      setMsg('正在下载: ' + filename + ' …');
      let client = await ensureSftp();
      let data = await client.readFileAll(remotePath);
      // 创建 Blob 并下载
      let blob = new Blob([data], { type: 'application/octet-stream' });
      let url = URL.createObjectURL(blob);
      let a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      setMsg('下载完成: ' + filename + ' (' + fmtSize(data.length) + ')');
    } catch (e) {
      setMsg('下载失败: ' + e.message);
    }
  }

  async function downloadDir(remotePath, dirname) {
    // 递归下载目录为 zip 不容易实现（需要 zip 库），改为逐个下载
    try {
      setMsg('正在下载目录: ' + dirname + ' …');
      let client = await ensureSftp();
      let entries = await client.readDirAll(remotePath);
      for (let entry of entries) {
        let fullPath = joinPath(remotePath, entry.filename);
        if (isDir(entry)) {
          await downloadDir(fullPath, dirname + '/' + entry.filename);
        } else {
          await downloadFile(fullPath, dirname + '/' + entry.filename);
        }
      }
      setMsg('目录下载完成: ' + dirname);
    } catch (e) {
      setMsg('目录下载失败: ' + e.message);
    }
  }

  els.btnDownload.addEventListener('click', function () {
    for (let item of selectedItems) {
      if (item.isDir) {
        downloadDir(item.path, item.filename);
      } else {
        downloadFile(item.path, item.filename);
      }
    }
  });

  /* ================= 上传 ================= */
  els.btnUpload.addEventListener('click', function () { els.fileUpload.click(); });
  els.fileUpload.addEventListener('change', async function () {
    let files = Array.from(els.fileUpload.files);
    if (files.length === 0) return;
    els.fileUpload.value = '';
    await uploadFiles(files, cwd);
  });

  async function uploadFiles(files, destDir) {
    let client = await ensureSftp();
    showProgress(true);
    for (let i = 0; i < files.length; i++) {
      let file = files[i];
      let destPath = joinPath(destDir, file.name);
      let item = addProgressItem(file.name, file.size);
      try {
        let offset = 0;
        let chunkSize = 32768;
        let totalRead = 0;
        // 先尝试打开已有文件，失败则创建
        let handle = await client.openFile(destPath, 0x02 | 0x08 | 0x10, 0o644); // WRITE|CREAT|TRUNC
        while (offset < file.size) {
          let end = Math.min(offset + chunkSize, file.size);
          let chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());
          await client.writeFile(handle, offset, chunk);
          offset = end;
          totalRead += chunk.length;
          updateProgressItem(item, totalRead, file.size);
        }
        await client.closeFile(handle);
        finishProgressItem(item, true);
      } catch (e) {
        finishProgressItem(item, false, e.message);
        setMsg('上传 ' + file.name + ' 失败: ' + e.message);
      }
    }
    setMsg('上传完成');
    loadDir(destDir);
    setTimeout(function () { showProgress(false); }, 2000);
  }

  /* ================= 目录上传 ================= */
  els.btnUploadDir.addEventListener('click', function () { els.dirUpload.click(); });
  els.dirUpload.addEventListener('change', async function () {
    let files = Array.from(els.dirUpload.files);
    if (files.length === 0) return;
    els.dirUpload.value = '';
    let client = await ensureSftp();
    // webkitdirectory 的 files 带相对路径 (dirName/sub/file.txt)
    // 按 relativePath 分组创建目录
    let dirs = new Set();
    let fileMap = []; // { file, relPath }
    for (let file of files) {
      let relPath = file.webkitRelativePath || file.name;
      let parts = relPath.split('/').filter(Boolean);
      // 第一段是顶层目录名
      for (let j = 1; j < parts.length; j++) {
        dirs.add(parts.slice(0, j).join('/'));
      }
      if (parts.length > 1) {
        fileMap.push({ file: file, relPath: relPath, dirParts: parts.slice(0, -1) });
      } else {
        fileMap.push({ file: file, relPath: relPath, dirParts: [] });
      }
    }
    // 在 cwd 下创建目录结构
    let dirList = Array.from(dirs).sort(function (a, b) { return a.split('/').length - b.split('/').length; });
    for (let dir of dirList) {
      let dirPath = joinPath(cwd, dir);
      try { await client.mkdir(dirPath); } catch (e) { /* 已存在则忽略 */ }
    }
    // 上传文件
    showProgress(true);
    for (let i = 0; i < fileMap.length; i++) {
      let item = fileMap[i];
      let destDir = cwd;
      if (item.dirParts.length > 0) {
        destDir = joinPath(cwd, item.dirParts.join('/'));
      }
      let destPath = joinPath(destDir, item.file.name);
      let progItem = addProgressItem(item.relPath, item.file.size);
      try {
        let offset = 0;
        let chunkSize = 32768;
        let totalRead = 0;
        let handle = await client.openFile(destPath, 0x02 | 0x08 | 0x10, 0o644);
        while (offset < item.file.size) {
          let end = Math.min(offset + chunkSize, item.file.size);
          let chunk = new Uint8Array(await item.file.slice(offset, end).arrayBuffer());
          await client.writeFile(handle, offset, chunk);
          offset = end;
          totalRead += chunk.length;
          updateProgressItem(progItem, totalRead, item.file.size);
        }
        await client.closeFile(handle);
        finishProgressItem(progItem, true);
      } catch (e) {
        finishProgressItem(progItem, false, e.message);
      }
    }
    setMsg('目录上传完成');
    loadDir(cwd);
    setTimeout(function () { showProgress(false); }, 2000);
  });

  /* ================= 拖放上传 ================= */
  let dragCounter = 0;
  els.filelistWrap.addEventListener('dragenter', function (ev) {
    ev.preventDefault();
    dragCounter++;
    els.filelistWrap.classList.add('dragover');
  });
  els.filelistWrap.addEventListener('dragleave', function (ev) {
    ev.preventDefault();
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      els.filelistWrap.classList.remove('dragover');
    }
  });
  els.filelistWrap.addEventListener('dragover', function (ev) { ev.preventDefault(); });
  els.filelistWrap.addEventListener('drop', async function (ev) {
    ev.preventDefault();
    dragCounter = 0;
    els.filelistWrap.classList.remove('dragover');
    let items = ev.dataTransfer.items;
    if (items) {
      // 递归读取拖放的目录
      let files = [];
      let entries = [];
      for (let i = 0; i < items.length; i++) {
        let entry;
        if (items[i].webkitGetAsEntry) entry = items[i].webkitGetAsEntry();
        if (entry) {
          entries.push(entry);
        } else {
          let file = items[i].getAsFile();
          if (file) files.push(file);
        }
      }
      // 先处理简单文件
      if (files.length > 0) await uploadFiles(files, cwd);
      // 再处理目录 entry
      for (let entry of entries) {
        await uploadEntry(entry, cwd);
      }
      if (entries.length > 0 || files.length > 0) loadDir(cwd);
    } else {
      let files = Array.from(ev.dataTransfer.files);
      if (files.length > 0) await uploadFiles(files, cwd);
    }
  });

  async function uploadEntry(entry, destDir) {
    if (entry.isFile) {
      return new Promise(function (resolve) {
        entry.file(function (file) {
          uploadFiles([file], destDir).then(resolve);
        });
      });
    } else if (entry.isDirectory) {
      let dirPath = joinPath(destDir, entry.name);
      let client = await ensureSftp();
      try { await client.mkdir(dirPath); } catch (e) { }
      let reader = entry.createReader();
      await new Promise(function (resolve) {
        reader.readEntries(async function (entries) {
          for (let sub of entries) {
            await uploadEntry(sub, dirPath);
          }
          resolve();
        });
      });
    }
  }

  /* ================= 进度条 ================= */
  function showProgress(show) {
    if (show) els.progressOverlay.classList.add('show');
    else els.progressOverlay.classList.remove('show');
  }

  function addProgressItem(name, total) {
    let div = document.createElement('div');
    div.className = 'prog-item';
    div.innerHTML = '<span class="name"></span><div class="bar"><div class="bar-fill" style="width:0%"></div></div><span class="pct">0%</span>';
    div.querySelector('.name').textContent = name;
    els.progressOverlay.appendChild(div);
    return { el: div, total: total, done: 0 };
  }

  function updateProgressItem(item, done, total) {
    item.done = done;
    if (total) item.total = total;
    let pct = item.total > 0 ? Math.round(done / item.total * 100) : 0;
    item.el.querySelector('.bar-fill').style.width = pct + '%';
    item.el.querySelector('.pct').textContent = pct + '%';
  }

  function finishProgressItem(item, success, errMsg) {
    if (success) {
      item.el.classList.add('done');
      item.el.querySelector('.bar-fill').style.width = '100%';
      item.el.querySelector('.pct').textContent = '✓';
    } else {
      item.el.classList.add('err');
      item.el.querySelector('.pct').textContent = '✗';
      item.el.title = errMsg || '失败';
    }
  }

  /* ================= 启动 ================= */
  (async function init() {
    setMsg('正在连接 SFTP…');
    try {
      await ensureSftp();
      // 获取用户家目录
      let client = sftp;
      let home = await client.realpath('.');
      loadDir(home);
    } catch (e) {
      setMsg('SFTP 初始化失败: ' + e.message);
    }
  })();

})();
