import {
  createHmac,
  createPrivateKey,
  randomBytes,
  sign as signBytes,
} from 'node:crypto';

export type ApprovalCredential =
  | { keyId: string; secret: string; privateKey?: never }
  | { keyId: string; privateKey: string; secret?: never };

export interface ApprovalSignatureVector {
  method?: string;
  alg?: string;
  keyId: string;
  canonical: string;
  sig: string;
}

function encodeString(value: string): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function encodeCanonical(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return encodeString(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('승인 params의 숫자는 유한한 값이어야 합니다.');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(encodeCanonical).join(',') + ']';
  }
  if (typeof value === 'object') {
    const object = value as Record<string, unknown>;
    const keys = Object.keys(object).sort();
    return (
      '{' +
      keys
        .map((key) => encodeString(key) + ':' + encodeCanonical(object[key]))
        .join(',') +
      '}'
    );
  }
  throw new Error('승인 params에 지원하지 않는 값이 있습니다.');
}

export function stableJson(value: unknown): string {
  return encodeCanonical(value);
}

function normalizeApprovalValue(value: unknown): unknown {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new Error('승인 params의 숫자는 안전한 정수여야 합니다.');
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) return value.map(normalizeApprovalValue);
  if (value && typeof value === 'object') {
    const normalized: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(value as Record<string, unknown>)) {
      if (!/^[\x00-\x7f]*$/.test(key)) {
        throw new Error('승인 params의 객체 키는 ASCII 문자만 사용할 수 있습니다.');
      }
      normalized[key] = normalizeApprovalValue((value as Record<string, unknown>)[key]);
    }
    return normalized;
  }
  return value;
}

export function normalizeApprovalParams(
  params: Record<string, unknown>,
): Record<string, unknown> {
  const filtered: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of Object.entries(params)) {
    if (key.startsWith('DEPLITE_') || key === 'registry_token') continue;
    filtered[key] = value;
  }
  const normalized = normalizeApprovalValue(filtered);
  if (!normalized || typeof normalized !== 'object' || Array.isArray(normalized)) {
    throw new Error('승인 params는 JSON 객체여야 합니다.');
  }
  return normalized as Record<string, unknown>;
}

export function canonicalApprovalRequest(
  agentId: string,
  workflow: string,
  params: Record<string, unknown>,
  ref: string | undefined,
  nonce: string,
  ts: number,
): string {
  if (!Number.isSafeInteger(ts)) throw new Error('승인 timestamp가 올바르지 않습니다.');
  return stableJson({
    agentId,
    nonce,
    params: normalizeApprovalParams(params),
    ref: ref || null,
    ts,
    v: 1,
    workflow,
  });
}

function decodeHmacSecret(secret: string): Buffer {
  const encoded = secret;
  const standardBase64 =
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  if (!standardBase64.test(encoded) || encoded.length % 4 !== 0) {
    throw new Error('approval-secret은 32바이트 이상 키의 표준 Base64 문자열이어야 합니다.');
  }
  const decoded = Buffer.from(encoded, 'base64');
  if (decoded.toString('base64') !== encoded || decoded.length < 32) {
    throw new Error('approval-secret은 32바이트 이상 키의 표준 Base64 문자열이어야 합니다.');
  }
  return decoded;
}

export function validateHmacSecret(secret: string): void {
  decodeHmacSecret(secret);
}

function encodeBase64Url(value: Buffer): string {
  return value.toString('base64url');
}

export function buildApproval(
  credential: ApprovalCredential,
  agentId: string,
  workflow: string,
  params: Record<string, unknown>,
  ref?: string,
  nonce = encodeBase64Url(randomBytes(32)),
  ts = Math.floor(Date.now() / 1000),
): Record<string, unknown> {
  const canonical = Buffer.from(
    canonicalApprovalRequest(agentId, workflow, params, ref, nonce, ts),
    'utf8',
  );
  if ('secret' in credential && credential.secret !== undefined) {
    const sig = createHmac('sha256', decodeHmacSecret(credential.secret))
      .update(canonical)
      .digest();
    return {
      method: 'hmac',
      keyId: credential.keyId,
      nonce,
      ts,
      sig: encodeBase64Url(sig),
    };
  }

  const pem = credential.privateKey;
  if (!pem) throw new Error('approval-private-key 입력이 필요합니다.');
  let key;
  try {
    key = createPrivateKey(pem);
  } catch {
    throw new Error('approval-private-key가 올바른 PEM 개인 키가 아닙니다.');
  }
  const keyType = key.asymmetricKeyType;
  let alg: 'ed25519' | 'ecdsa-p256-sha256';
  let sig: Buffer;
  if (keyType === 'ed25519') {
    alg = 'ed25519';
    sig = signBytes(null, canonical, key);
  } else if (
    keyType === 'ec' &&
    key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
  ) {
    alg = 'ecdsa-p256-sha256';
    sig = signBytes('sha256', canonical, { key, dsaEncoding: 'ieee-p1363' });
  } else {
    throw new Error('approval-private-key는 Ed25519 또는 ECDSA P-256 키여야 합니다.');
  }
  return {
    method: 'signature',
    alg,
    keyId: credential.keyId,
    nonce,
    ts,
    sig: encodeBase64Url(sig),
  };
}
