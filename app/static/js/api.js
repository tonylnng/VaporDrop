// 極薄的 fetch 封裝。全部相對路徑，同源，帶 cookie。
export async function api(method, path, body, extraHeaders) {
  const headers = Object.assign({}, extraHeaders || {});
  let payload;
  if (body !== undefined && body !== null) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const res = await fetch(path, {
    method,
    headers,
    body: payload,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (_) {
    data = null;
  }
  if (!res.ok) {
    const err = new Error((data && data.detail) || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

export async function putBytes(path, bytes, headers) {
  const res = await fetch(path, {
    method: 'PUT',
    headers: Object.assign({ 'Content-Type': 'application/octet-stream' }, headers || {}),
    body: bytes,
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      detail = (await res.json()).detail || detail;
    } catch (_) {}
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export async function getBytes(path, token) {
  const headers = { Accept: 'application/octet-stream' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, {
    headers,
    credentials: token ? 'omit' : 'same-origin',
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return {
    bytes: new Uint8Array(await res.arrayBuffer()),
    kind: res.headers.get('X-Vapor-Kind') || 'file',
    name: res.headers.get('X-Vapor-Name') || '',
    plain: res.headers.get('X-Vapor-Plain') === '1',
  };
}
