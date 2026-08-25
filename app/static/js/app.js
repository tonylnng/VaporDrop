// 擁有者介面：登入、開 session、加密上傳、產生取用連結、閒置登出。
import { api, putBytes } from './api.js';
import * as V from './vcrypto.js';
import * as WA from './webauthn.js';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

let CFG = { idle_timeout: 1800, content_ttl: 600, allow_plain: false, google: false };

// 伺服器只回短碼，訊息由前端翻譯（避免伺服器端回應洩漏細節）
const AUTH_ERRORS = {
  denied: '你在 Google 端取消了登入。',
  state: '登入流程已逾時，請再按一次。',
  token: '無法與 Google 完成驗證，請稍後再試。',
  email: '此 Google 帳號的 email 未經驗證。',
  nolist: '此帳號不在允許清單內。',
  rescue: '緊急登入連結無效、已使用或已過期。',
};
let refreshTimer = null;
let tickTimer = null;
let lastActivity = Date.now();
let idleWarned = false;

// ---------------------------------------------------------------- 工具
function show(el) { el.classList.remove('hidden'); }
function hide(el) { el.classList.add('hidden'); }

function msg(el, text, kind = 'info') {
  el.textContent = text || '';
  el.className = `msg ${kind}`;
}

function fmtDuration(sec) {
  sec = Math.max(0, Math.floor(sec));
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// ---------------------------------------------------------------- 啟動
async function boot() {
  try {
    CFG = await api('GET', '/auth/state');
  } catch (_) {
    msg($('#auth-msg'), '無法連線到伺服器', 'err');
    show($('#view-auth'));
    return;
  }

  if (CFG.allow_plain) show($('#plain-row'));
  $('#limits').textContent =
    `單項上限 ${fmtBytes(CFG.max_item_bytes)} · session 上限 ${fmtBytes(CFG.max_session_bytes)} · ` +
    `內容 ${Math.round(CFG.content_ttl / 60)} 分鐘後蒸發`;

  if (CFG.google) {
    show($('#btn-google'));
    show($('#google-hint'));
  } else {
    $('#pk-block').open = true;
  }

  const QS = new URLSearchParams(location.search);
  const err = QS.get('e');
  if (err) {
    msg($('#auth-msg'), AUTH_ERRORS[err] || '登入失敗，請重試。', 'err');
    history.replaceState(null, '', location.pathname);
  }

  if (CFG.bootstrap && !CFG.google) {
    $('#reg-block').open = true;
    hide($('#reg-invite-row'));
    msg($('#auth-msg'), '尚未有任何帳號，請先註冊第一個 Passkey。', 'info');
  }
  const invite = QS.get('invite');
  if (invite) {
    $('#reg-invite').value = invite;
    $('#reg-block').open = true;
    // 立刻把邀請碼從網址移除，避免留在瀏覽器歷史
    history.replaceState(null, '', location.pathname);
  }

  if (!WA.supported() && !CFG.google) {
    msg($('#auth-msg'), '此瀏覽器不支援 Passkey，請改用 Safari / Chrome / Edge 新版。', 'err');
  }

  CFG.authenticated ? enterApp() : show($('#view-auth'));
}

function enterApp() {
  hide($('#view-auth'));
  show($('#view-app'));
  show($('#btn-logout'));
  if (CFG.handle) {
    $('#who').textContent = CFG.handle;
    show($('#who'));
  }
  show($('#idle'));
  lastActivity = Date.now();
  idleWarned = false;
  refresh();
  refreshTimer = setInterval(refresh, 15000);
  tickTimer = setInterval(tick, 1000);
  loadCredentials();
}

// ---------------------------------------------------------------- 認證
$('#btn-login').addEventListener('click', async () => {
  msg($('#auth-msg'), '請完成生物認證…');
  try {
    const begin = await api('POST', '/auth/login/begin');
    const credential = await WA.getAssertion(begin.options);
    const done = await api('POST', '/auth/login/finish', { flow: begin.flow, credential });
    CFG.authenticated = true;
    CFG.handle = done.handle || '';
    msg($('#auth-msg'), '');
    enterApp();
  } catch (err) {
    msg($('#auth-msg'), err.message || '登入失敗', 'err');
  }
});

$('#btn-register').addEventListener('click', async () => {
  const handle = $('#reg-handle').value.trim();
  if (!handle) return msg($('#auth-msg'), '請輸入 handle', 'err');
  msg($('#auth-msg'), '請完成生物認證…');
  try {
    const begin = await api('POST', '/auth/register/begin', {
      handle,
      invite: $('#reg-invite').value.trim(),
      label: $('#reg-label').value.trim(),
    });
    const credential = await WA.createCredential(begin.options);
    await api('POST', '/auth/register/finish', { flow: begin.flow, credential });
    CFG.authenticated = true;
    CFG.handle = handle;
    msg($('#auth-msg'), '');
    enterApp();
  } catch (err) {
    msg($('#auth-msg'), err.message || '註冊失敗', 'err');
  }
});

$('#btn-logout').addEventListener('click', () => logout('已登出，所有暫存內容已銷毀。'));

async function logout(reason) {
  clearInterval(refreshTimer);
  clearInterval(tickTimer);
  V.forgetAllKeys();
  try {
    await api('POST', '/auth/logout');
  } catch (_) {}
  location.replace('/');
}

$('#btn-add-cred').addEventListener('click', async () => {
  try {
    const begin = await api('POST', '/auth/credentials/add/begin');
    const credential = await WA.createCredential(begin.options);
    await api('POST', '/auth/register/finish', { flow: begin.flow, credential });
    msg($('#app-msg'), '已新增這台裝置的 Passkey。', 'ok');
    loadCredentials();
  } catch (err) {
    msg($('#app-msg'), err.message || '新增失敗', 'err');
  }
});

async function loadCredentials() {
  try {
    const { credentials } = await api('GET', '/auth/credentials');
    $('#creds').innerHTML = credentials
      .map(
        (c) =>
          `<div class="row between cred"><span class="mono small">${c.credential_id.slice(0, 20)}…` +
          `${c.label ? ' · ' + escapeHtml(c.label) : ''}</span>` +
          `<span class="muted small">${c.transports || '-'}</span></div>`,
      )
      .join('');
  } catch (_) {}
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------------------------------------------------------------- Session
$('#btn-new').addEventListener('click', async () => {
  const plain = CFG.allow_plain && $('#new-plain').checked;
  try {
    const res = await api('POST', '/api/sessions', {
      label: $('#new-label').value.trim(),
      burn_after_read: $('#new-burn').checked,
      plain,
    });
    if (!plain) {
      // 金鑰在此刻誕生，只存在這個分頁
      V.stashKey(res.cid, V.b64uEncode(V.newKeyBytes()));
    }
    $('#new-label').value = '';
    msg($('#app-msg'), `已開啟 session，${Math.round(CFG.content_ttl / 60)} 分鐘後自動蒸發。`, 'ok');
    refresh();
  } catch (err) {
    msg($('#app-msg'), err.message || '無法建立 session', 'err');
  }
});

async function refresh() {
  let data;
  try {
    data = await api('GET', '/api/sessions');
  } catch (err) {
    if (err.status === 401) return logout();
    return;
  }
  const host = $('#sessions');
  const openState = new Map($$('.session', host).map((el) => [el.dataset.cid, el]));
  host.innerHTML = '';
  data.sessions.forEach((s) => host.appendChild(renderSession(s, openState.get(s.cid))));
  data.sessions.length ? hide($('#empty')) : show($('#empty'));
}

function renderSession(s, prev) {
  const node = $('#tpl-session').content.cloneNode(true).firstElementChild;
  node.dataset.cid = s.cid;
  node.dataset.ttl = s.ttl;
  node.dataset.plain = s.plain ? '1' : '0';
  $('.cid', node).textContent = s.cid;
  if (s.label) $('.label', node).textContent = s.label;
  if (s.burn) show($('.tag.burn', node));
  if (s.plain) show($('.tag.plain', node));
  $('.ttl', node).textContent = fmtDuration(s.ttl);

  const keyB64 = V.recallKey(s.cid);
  const list = $('.items', node);
  if (!s.items.length) {
    list.innerHTML = '<li class="muted small">尚無內容</li>';
  } else {
    s.items.forEach(async (it) => {
      const li = document.createElement('li');
      li.className = 'item';
      let name = '(加密名稱)';
      if (s.plain) {
        name = it.name ? atobSafe(it.name) : it.kind;
      } else if (keyB64) {
        try {
          const key = await V.importKey(V.b64uDecode(keyB64));
          name = await V.decryptString(key, V.b64uDecode(it.name));
        } catch (_) {
          name = '(無法解密名稱)';
        }
      } else {
        name = '(金鑰不在本分頁)';
      }
      li.innerHTML = `<span class="mono small">${escapeHtml(name)}</span>
        <span class="muted small">${it.kind} · ${fmtBytes(it.size)}</span>`;
      list.appendChild(li);
    });
  }

  if (!keyB64 && !s.plain) {
    const warn = document.createElement('p');
    warn.className = 'msg warn';
    warn.textContent = '此 session 的解密金鑰不在這個分頁（可能是重新載入或換了瀏覽器），無法再解密其內容。';
    node.appendChild(warn);
  }

  wireSession(node, s);
  if (prev) {
    const out = $('.out', prev);
    if (!out.classList.contains('hidden')) {
      $('.out-link', node).value = $('.out-link', prev).value;
      $('.out-curl', node).value = $('.out-curl', prev).value;
      show($('.out', node));
    }
    $('.in-text', node).value = $('.in-text', prev).value;
  }
  return node;
}

function atobSafe(b64u) {
  try {
    return new TextDecoder().decode(V.b64uDecode(b64u));
  } catch (_) {
    return '(名稱)';
  }
}

function wireSession(node, s) {
  const cid = s.cid;

  $('.act-destroy', node).addEventListener('click', async () => {
    await api('DELETE', `/api/sessions/${cid}`);
    V.forgetKey(cid);
    refresh();
  });

  $('.act-add-text', node).addEventListener('click', async () => {
    const text = $('.in-text', node).value;
    if (!text.trim()) return;
    await upload(cid, s.plain, 'text', `text-${Date.now()}.txt`, new TextEncoder().encode(text));
    $('.in-text', node).value = '';
    refresh();
  });

  $('.in-file', node).addEventListener('change', async (ev) => {
    for (const file of ev.target.files) {
      if (file.size > CFG.max_item_bytes) {
        msg($('#app-msg'), `${file.name} 超過單項上限`, 'err');
        continue;
      }
      await upload(cid, s.plain, 'file', file.name, new Uint8Array(await file.arrayBuffer()));
    }
    ev.target.value = '';
    refresh();
  });

  $('.act-token', node).addEventListener('click', async () => {
    const uses = Math.max(1, parseInt($('.in-uses', node).value, 10) || 1);
    try {
      const { token } = await api('POST', `/api/sessions/${cid}/tokens`, { uses });
      const keyB64 = V.recallKey(cid);
      // 金鑰與 token 都放在 fragment：兩者都不會出現在任何伺服器端 URL
      const frag = s.plain ? `#t=${token}` : `#k=${keyB64}&t=${token}`;
      const link = `${location.origin}/s/${cid}${frag}`;
      $('.out-link', node).value = link;
      $('.out-curl', node).value = buildCurl(cid, token, keyB64, s.plain);
      show($('.out', node));
    } catch (err) {
      msg($('#app-msg'), err.message || '無法產生 token', 'err');
    }
  });

  $('.act-copy-link', node).addEventListener('click', () => copy($('.out-link', node).value));
  $('.act-copy-curl', node).addEventListener('click', () => copy($('.out-curl', node).value));
}

async function upload(cid, plain, kind, name, bytes) {
  let payload = bytes;
  let encName = V.b64uEncode(new TextEncoder().encode(name));
  if (!plain) {
    const keyB64 = V.recallKey(cid);
    if (!keyB64) {
      msg($('#app-msg'), '本分頁沒有此 session 的金鑰，無法上傳。', 'err');
      return;
    }
    const key = await V.importKey(V.b64uDecode(keyB64));
    payload = await V.encrypt(key, bytes);
    encName = V.b64uEncode(await V.encryptString(key, name));
  }
  try {
    await putBytes(`/api/sessions/${cid}/items`, payload, {
      'X-Vapor-Kind': kind,
      'X-Vapor-Name': encName,
    });
    msg($('#app-msg'), `已加入 ${name}`, 'ok');
  } catch (err) {
    msg($('#app-msg'), err.message || '上傳失敗', 'err');
  }
}

function buildCurl(cid, token, keyB64, plain) {
  const base = `${location.origin}/s/${cid}`;
  if (plain) {
    return [
      '# 明文模式：直接取用',
      `curl -fsSL -H "Authorization: Bearer ${token}" "${base}/raw"`,
    ].join('\n');
  }
  return [
    '# 零知識模式：伺服器只有密文，需用金鑰在本地解密',
    '# scripts/vapor_fetch.py 在 repo 內，只需 python3 + cryptography',
    `export VAPOR_URL="${base}"`,
    `export VAPOR_TOKEN="${token}"`,
    `export VAPOR_KEY="${keyB64}"`,
    'python3 vapor_fetch.py --all -o ./inbox',
  ].join('\n');
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    msg($('#app-msg'), '已複製到剪貼板', 'ok');
  } catch (_) {
    msg($('#app-msg'), '瀏覽器拒絕存取剪貼板，請手動複製', 'warn');
  }
}

// ---------------------------------------------------------------- 計時
function tick() {
  $$('.session').forEach((node) => {
    const ttl = Math.max(0, parseInt(node.dataset.ttl, 10) - 1);
    node.dataset.ttl = ttl;
    $('.ttl', node).textContent = fmtDuration(ttl);
    const pct = Math.max(0, Math.min(100, (ttl / CFG.content_ttl) * 100));
    $('.bar-fill', node).style.width = `${pct}%`;
    $('.ttl', node).classList.toggle('hot', ttl <= 60);
    if (ttl === 0) {
      V.forgetKey(node.dataset.cid);
      refresh();
    }
  });

  const idleLeft = CFG.idle_timeout - (Date.now() - lastActivity) / 1000;
  $('#idle').textContent = `閒置 ${fmtDuration(idleLeft)}`;
  $('#idle').classList.toggle('hot', idleLeft <= 300);
  if (idleLeft <= 300 && !idleWarned) {
    idleWarned = true;
    msg($('#app-msg'), '即將因閒置自動登出，任何操作即可延長。', 'warn');
  }
  if (idleLeft <= 0) logout();
}

['click', 'keydown', 'pointermove', 'touchstart'].forEach((evt) =>
  window.addEventListener(evt, () => {
    lastActivity = Date.now();
    idleWarned = false;
  }, { passive: true }),
);

// 關閉分頁即抹除記憶體中的金鑰
window.addEventListener('pagehide', () => V.forgetAllKeys());

boot();
