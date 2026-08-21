// WebAuthn 前端封裝。伺服器以 base64url 傳遞二進位欄位，這裡負責來回轉換。
import { b64uDecode, b64uEncode } from './vcrypto.js';

function toBuf(v) {
  return b64uDecode(v);
}

export function supported() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}

export async function createCredential(optionsJson) {
  const pub = { ...optionsJson };
  pub.challenge = toBuf(pub.challenge);
  pub.user = { ...pub.user, id: toBuf(pub.user.id) };
  if (Array.isArray(pub.excludeCredentials)) {
    pub.excludeCredentials = pub.excludeCredentials.map((c) => ({ ...c, id: toBuf(c.id) }));
  }
  const cred = await navigator.credentials.create({ publicKey: pub });
  if (!cred) throw new Error('未取得憑證');
  const r = cred.response;
  return {
    id: cred.id,
    rawId: b64uEncode(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64uEncode(r.clientDataJSON),
      attestationObject: b64uEncode(r.attestationObject),
      transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

export async function getAssertion(optionsJson) {
  const pub = { ...optionsJson };
  pub.challenge = toBuf(pub.challenge);
  if (Array.isArray(pub.allowCredentials) && pub.allowCredentials.length) {
    pub.allowCredentials = pub.allowCredentials.map((c) => ({ ...c, id: toBuf(c.id) }));
  } else {
    delete pub.allowCredentials; // discoverable credential：不需輸入帳號
  }
  const cred = await navigator.credentials.get({ publicKey: pub });
  if (!cred) throw new Error('未取得憑證');
  const r = cred.response;
  return {
    id: cred.id,
    rawId: b64uEncode(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64uEncode(r.clientDataJSON),
      authenticatorData: b64uEncode(r.authenticatorData),
      signature: b64uEncode(r.signature),
      userHandle: r.userHandle ? b64uEncode(r.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}
