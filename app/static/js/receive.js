// 接收方介面。金鑰與 token 都從 URL fragment 讀取，兩者都不會送到伺服器。
import { getBytes } from './api.js';
import * as V from './vcrypto.js';

const $ = (s) => document.querySelector(s);
const cid = location.pathname.split('/').filter(Boolean)[1] || '';
const frag = new URLSearchParams(location.hash.replace(/^#/, ''));
const keyB64 = frag.get('k') || '';
const token = frag.get('t') || '';

let ttl = 0;
let key = null;

function msg(text, kind = 'info') {
  $('#msg').textContent = text || '';
  $('#msg').className = `msg ${kind}`;
}

function fmt(sec) {
  sec = Math.max(0, Math.floor(sec));
  return `${Math.floor(sec / 60)}:${String(sec % 60).padStart(2, '0')}`;
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

async function authHeaders() {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function boot() {
  $('#cid').textContent = cid;
  if (!cid) return msg('連結不完整', 'err');

  let meta;
  try {
    const res = await fetch(`/api/receive/${cid}`, {
      headers: await authHeaders(),
      credentials: token ? 'omit' : 'same-origin',
      cache: 'no-store',
    });
    if (!res.ok) throw new Error(res.status === 404 ? '內容不存在或已蒸發' : `HTTP ${res.status}`);
    meta = await res.json();
  } catch (err) {
    return msg(err.message, 'err');
  }

  ttl = meta.ttl;
  if (meta.burn) $('#burn-note').classList.remove('hidden');

  if (!meta.plain) {
    if (!keyB64) {
      return msg('網址缺少解密金鑰（# 後的 k= 部分）。沒有金鑰時伺服器與本頁都無法還原內容。', 'err');
    }
    try {
      key = await V.importKey(V.b64uDecode(keyB64));
    } catch (_) {
      return msg('金鑰格式不正確', 'err');
    }
  }

  $('#cli').value = buildCli(meta.plain);
  await renderItems(meta);
  tickTtl();
  setInterval(tickTtl, 1000);
}

async function renderItems(meta) {
  const list = $('#items');
  list.innerHTML = '';
  if (!meta.items.length) {
    list.innerHTML = '<li class="muted small">這個 session 目前沒有內容</li>';
    return;
  }
  for (const it of meta.items) {
    const li = document.createElement('li');
    li.className = 'item col';
    let name = it.kind === 'text' ? '文字' : '檔案';
    if (meta.plain) {
      name = it.name ? new TextDecoder().decode(V.b64uDecode(it.name)) : name;
    } else if (key) {
      try {
        name = await V.decryptString(key, V.b64uDecode(it.name));
      } catch (_) {
        name = '(名稱無法解密，金鑰可能不符)';
      }
    }
    const row = document.createElement('div');
    row.className = 'row between';
    const label = document.createElement('span');
    label.className = 'mono small';
    label.textContent = name;
    const info = document.createElement('span');
    info.className = 'muted small';
    info.textContent = `${it.kind} · ${fmtBytes(it.size)}`;
    const btn = document.createElement('button');
    btn.className = 'btn small';
    btn.textContent = it.kind === 'text' ? '顯示' : '下載';
    btn.addEventListener('click', () => fetchItem(it, name, meta, li, btn));
    row.append(label, info, btn);
    li.appendChild(row);
    list.appendChild(li);
  }
}

async function fetchItem(it, name, meta, container, btn) {
  btn.disabled = true;
  btn.textContent = '取用中…';
  try {
    const res = await getBytes(`/s/${cid}/raw?item=${encodeURIComponent(it.item_id)}`, token);
    const plainBytes = meta.plain ? res.bytes : await V.decrypt(key, res.bytes);
    if (it.kind === 'text') {
      const ta = document.createElement('textarea');
      ta.className = 'mono';
      ta.rows = 10;
      ta.readOnly = true;
      ta.value = new TextDecoder().decode(plainBytes);
      container.appendChild(ta);
      const copyBtn = document.createElement('button');
      copyBtn.className = 'btn ghost small';
      copyBtn.textContent = '複製全文';
      copyBtn.addEventListener('click', () => navigator.clipboard.writeText(ta.value));
      container.appendChild(copyBtn);
      btn.remove();
    } else {
      const url = URL.createObjectURL(new Blob([plainBytes], { type: 'application/octet-stream' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = name || `${it.item_id}.bin`;
      a.click();
      URL.revokeObjectURL(url);
      btn.textContent = '已下載';
    }
    if (meta.burn) msg('已取用，此項目已在伺服器端銷毀。', 'warn');
  } catch (err) {
    msg(err.message === 'HTTP 404' ? '內容已蒸發或 token 已用盡' : `解密失敗：${err.message}`, 'err');
    btn.disabled = false;
    btn.textContent = '重試';
  }
}

function buildCli(plain) {
  const base = `${location.origin}/s/${cid}`;
  if (plain) {
    return `curl -fsSL -H "Authorization: Bearer ${token}" "${base}/raw"`;
  }
  return [
    'export VAPOR_URL="' + base + '"',
    'export VAPOR_TOKEN="' + token + '"',
    'export VAPOR_KEY="' + keyB64 + '"',
    'python3 vapor_fetch.py --all -o ./inbox',
  ].join('\n');
}

function tickTtl() {
  ttl = Math.max(0, ttl - 1);
  $('#ttl').textContent = `剩餘 ${fmt(ttl)}`;
  $('#ttl').classList.toggle('hot', ttl <= 60);
  if (ttl === 0) msg('內容已到期蒸發。', 'warn');
}

boot();
