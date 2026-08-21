// 端到端加密工具。金鑰只在此檔案產生，只存於 sessionStorage 與 URL fragment。
// 伺服器永遠拿不到金鑰，也拿不到明文。

export function b64uEncode(bytes) {
  let s = '';
  const arr = new Uint8Array(bytes);
  const chunk = 0x8000;
  for (let i = 0; i < arr.length; i += chunk) {
    s += String.fromCharCode.apply(null, arr.subarray(i, i + chunk));
  }
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDecode(str) {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// 256-bit 金鑰，CSPRNG
export function newKeyBytes() {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function importKey(rawBytes) {
  return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

// 輸出格式：iv(12 bytes) || ciphertext+tag
export async function encrypt(key, plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBytes);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return out;
}

export async function decrypt(key, blobBytes) {
  const buf = new Uint8Array(blobBytes);
  if (buf.length <= 12) throw new Error('資料長度不合法');
  const iv = buf.subarray(0, 12);
  const ct = buf.subarray(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(pt);
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export async function encryptString(key, str) {
  return encrypt(key, enc.encode(str));
}

export async function decryptString(key, bytes) {
  return dec.decode(await decrypt(key, bytes));
}

// --- 金鑰在瀏覽器內的保管 ---------------------------------------------
// sessionStorage：關閉分頁即消失，且不跨分頁洩漏。
const KEY_PREFIX = 'vk:';

export function stashKey(cid, keyB64u) {
  sessionStorage.setItem(KEY_PREFIX + cid, keyB64u);
}

export function recallKey(cid) {
  return sessionStorage.getItem(KEY_PREFIX + cid);
}

export function forgetKey(cid) {
  sessionStorage.removeItem(KEY_PREFIX + cid);
}

export function forgetAllKeys() {
  for (const k of Object.keys(sessionStorage)) {
    if (k.startsWith(KEY_PREFIX)) sessionStorage.removeItem(k);
  }
}
