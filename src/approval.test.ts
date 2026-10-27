import assert from 'node:assert/strict';
import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  verify,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  buildApproval,
  canonicalApprovalRequest,
  type ApprovalSignatureVector,
} from './approval.ts';

interface KeyPairVector {
  privateKeyPEM: string;
  publicKeyPEM: string;
}

interface ApprovalVectors {
  now: number;
  agentId: string;
  canonical: Array<{
    name: string;
    input: {
      agentId: string;
      workflow: string;
      params: Record<string, unknown>;
      ref: string | null;
      nonce: string;
      ts: number;
    };
    canonical?: string;
    error?: boolean;
  }>;
  keys: {
    hmac: Record<string, string>;
    ed25519: Record<string, KeyPairVector>;
    ecdsaP256: Record<string, KeyPairVector>;
  };
  signatures: ApprovalSignatureVector[];
  decisions: Array<{
    name: string;
    job: {
      agentId: string;
      workflow: string;
      params: Record<string, unknown>;
      ref: string;
    };
    sequence: Array<{
      approval: {
        method?: string;
        alg?: string;
        keyId?: string;
        nonce?: string;
        ts?: number;
        sig?: string;
      } | null;
      expect: string;
    }>;
  }>;
}

const vectors = JSON.parse(
  readFileSync('test/fixtures/approval-vectors.json', 'utf8'),
) as ApprovalVectors;

function verifyVectorSignature(
  method: string | undefined,
  alg: string | undefined,
  keyId: string,
  canonical: string,
  signature: string,
): boolean {
  const bytes = Buffer.from(signature, 'base64url');
  if (method === 'hmac') {
    const encodedKey = vectors.keys.hmac[keyId];
    if (!encodedKey) return false;
    const expected = createHmac('sha256', Buffer.from(encodedKey, 'base64'))
      .update(canonical)
      .digest();
    return expected.equals(bytes);
  }
  if (alg === 'ed25519') {
    const pair = vectors.keys.ed25519[keyId];
    if (!pair) return false;
    return verify(null, Buffer.from(canonical), createPublicKey(pair.publicKeyPEM), bytes);
  }
  if (alg === 'ecdsa-p256-sha256') {
    const pair = vectors.keys.ecdsaP256[keyId];
    if (!pair) return false;
    return verify(
      'sha256',
      Buffer.from(canonical),
      { key: createPublicKey(pair.publicKeyPEM), dsaEncoding: 'ieee-p1363' },
      bytes,
    );
  }
  return false;
}

test('canonical request output matches every approval canonicalization vector', () => {
  for (const vector of vectors.canonical) {
    const input = vector.input;
    const build = () =>
      canonicalApprovalRequest(
        input.agentId,
        input.workflow,
        input.params,
        input.ref ?? undefined,
        input.nonce,
        input.ts,
      );
    if (vector.error) {
      assert.throws(build, vector.name);
    } else {
      assert.equal(build(), vector.canonical, vector.name);
    }
  }
});

test('approval canonicalization preserves a JSON __proto__ parameter key', () => {
  const params = JSON.parse('{"__proto__":{"key":1},"ok":2}') as Record<string, unknown>;
  assert.equal(
    canonicalApprovalRequest('agent', 'deploy', params, undefined, 'nonce', 1),
    '{"agentId":"agent","nonce":"nonce","params":{"__proto__":{"key":1},"ok":2},"ref":null,"ts":1,"v":1,"workflow":"deploy"}',
  );
});

test('all HMAC, Ed25519, and P-256 signature vectors verify', () => {
  assert.equal(vectors.signatures.length, 3);
  for (const vector of vectors.signatures) {
    assert.equal(
      verifyVectorSignature(
        vector.method,
        vector.alg,
        vector.keyId,
        vector.canonical,
        vector.sig,
      ),
      true,
      vector.keyId + ' vector',
    );
  }
});

test('approval generation matches the fixture canonical message and signatures', () => {
  const nonce = Buffer.alloc(16, 0x11).toString('base64url');
  const params = { a: 1, message: 'approval vectors' };
  const hmacVector = vectors.signatures.find((item) => item.method === 'hmac');
  const edVector = vectors.signatures.find((item) => item.alg === 'ed25519');
  const ecVector = vectors.signatures.find((item) => item.alg === 'ecdsa-p256-sha256');
  assert.ok(hmacVector && edVector && ecVector);

  const canonical = canonicalApprovalRequest(
    vectors.agentId,
    'deploy',
    params,
    'refs/main',
    nonce,
    vectors.now,
  );
  assert.equal(canonical, hmacVector.canonical);

  const hmacApproval = buildApproval(
    { keyId: hmacVector.keyId, secret: vectors.keys.hmac[hmacVector.keyId] },
    vectors.agentId,
    'deploy',
    params,
    'refs/main',
    nonce,
    vectors.now,
  );
  assert.equal(hmacApproval.sig, hmacVector.sig);

  const edKey = vectors.keys.ed25519[edVector.keyId];
  const edApproval = buildApproval(
    { keyId: edVector.keyId, privateKey: edKey.privateKeyPEM },
    vectors.agentId,
    'deploy',
    params,
    'refs/main',
    nonce,
    vectors.now,
  );
  assert.equal(edApproval.alg, 'ed25519');
  assert.equal(edApproval.sig, edVector.sig);

  const ecKey = vectors.keys.ecdsaP256[ecVector.keyId];
  const ecApproval = buildApproval(
    { keyId: ecVector.keyId, privateKey: ecKey.privateKeyPEM },
    vectors.agentId,
    'deploy',
    params,
    'refs/main',
    nonce,
    vectors.now,
  );
  assert.equal(ecApproval.alg, 'ecdsa-p256-sha256');
  assert.equal(
    verifyVectorSignature(
      'signature',
      'ecdsa-p256-sha256',
      ecVector.keyId,
      canonical,
      String(ecApproval.sig),
    ),
    true,
  );
  assert.equal(createPrivateKey(ecKey.privateKeyPEM).asymmetricKeyType, 'ec');
});

test('HMAC approval requires a strict standard Base64 key of at least 32 bytes', () => {
  assert.throws(
    () =>
      buildApproval(
        { keyId: 'raw-key', secret: 'r'.repeat(32) },
        vectors.agentId,
        'deploy',
        {},
        'main',
      ),
    /표준 Base64/,
  );
  assert.throws(
    () =>
      buildApproval(
        {
          keyId: 'whitespace-key',
          secret: ' ' + vectors.keys.hmac['test-hmac'] + ' ',
        },
        vectors.agentId,
        'deploy',
        {},
        'main',
      ),
    /표준 Base64/,
  );
  assert.throws(
    () =>
      buildApproval(
        { keyId: 'short-key', secret: Buffer.from('short').toString('base64') },
        vectors.agentId,
        'deploy',
        {},
        'main',
      ),
    /32바이트/,
  );
});

test('successful HMAC and key-ID signature decision vectors verify against fixture data', () => {
  for (const decision of vectors.decisions) {
    for (const step of decision.sequence) {
      const approval = step.approval;
      if (
        !approval ||
        !approval.keyId ||
        !['ok', 'approval_replayed', 'approval_expired'].includes(step.expect)
      ) {
        continue;
      }
      const canonical = canonicalApprovalRequest(
        decision.job.agentId,
        decision.job.workflow,
        decision.job.params,
        decision.job.ref || undefined,
        approval.nonce ?? '',
        approval.ts ?? 0,
      );
      assert.equal(
        verifyVectorSignature(
          approval.method,
          approval.alg,
          approval.keyId,
          canonical,
          approval.sig ?? '',
        ),
        true,
        decision.name + ' expects a valid signature',
      );
    }
  }
});
