import { describe, test, jest, expect } from '@jest/globals';
import * as jwksRsaModule from 'jwks-rsa';
import { TextEncoder } from 'util';
import {
  createValidTestToken,
  mockPublicKeyRsa4096,
  throwAsObject,
} from './helpers.js';

jest.unstable_mockModule('jwks-rsa', async () => {
  return {
    ...jwksRsaModule,
    JwksClient: function MockJwksClient() {
      return {
        async getSigningKey(kid: string): Promise<jwksRsaModule.SigningKey> {
          return {
            kid,
            alg: 'RS256',
            rsaPublicKey: mockPublicKeyRsa4096[kid],
            publicKey: mockPublicKeyRsa4096[kid],
            getPublicKey: () => mockPublicKeyRsa4096[kid],
          };
        },
      };
    },
  };
});

describe('TVF', () => {
  jest.useFakeTimers('modern');
  jest.setSystemTime(new Date('2022-02-22T22:22:22Z'));

  test('Vanilla no UIG', async () => {
    const { tokenVerifierFactory } = await import('../lib/index.js');

    const tvf = tokenVerifierFactory({
      jwksUri: 'https://example.com/.well-known/jwks.json',
    });

    await expect(
      tvf('invalid').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot(`[Error: Unparseable token]`);

    await expect(
      tvf('in.vali.d').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot(`[Error: Unparseable token]`);

    await expect(
      tvf('e30.InN0cmluZyBwYXlsb2FkIg').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot(`[Error: Unparseable token]`);

    await expect(
      tvf('e31wYXJzZWVycm9y.InN0cmluZyBwYXlsb2FkIg').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot(`[Error: Unparseable token]`);

    await expect(
      tvf('e30.e30').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot(`[Error: Unparseable token]`);

    await expect(
      tvf('e30.e30.hash').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot(`[Error: Missing key id]`);

    await expect(
      tvf(
        'ewpwYXJzZSBlcnJvcgp9.ewogICJleHAiOiAxNjQzNzg3Mzk4LAogICJpYXQiOiAxNjQzNzg3Mzk4Cn0.Hx_1eFsGKpnHhO5io6X5y12MmgAfgDwyE_V-iyvT7yo',
      ).catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot(`[Error: Unparseable token]`);
    await expect(
      tvf('e30.InN0cmluZyBwYXlsb2FkIg').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot(`[Error: Unparseable token]`);

    await expect(tvf(createValidTestToken('test1'))).resolves
      .toMatchInlineSnapshot(`
            Object {
              "claims": Object {
                "client_id": "888888800000008888111333335555",
                "exp": 1645572142,
                "iat": 1645568542,
                "jti": "beef-f00d-cafe",
                "scope": "test-scope",
                "sub": "test-subject",
                "token_use": "access",
              },
              "clientId": "888888800000008888111333335555",
              "expiresAt": 2022-02-22T23:22:22.000Z,
              "id": "beef-f00d-cafe",
              "ips": Array [],
              "isValid": [Function],
              "issuedAt": 2022-02-22T22:22:22.000Z,
              "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QxIn0.eyJjbGllbnRfaWQiOiI4ODg4ODg4MDAwMDAwMDg4ODgxMTEzMzMzMzU1NTUiLCJzY29wZSI6InRlc3Qtc2NvcGUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpYXQiOjE2NDU1Njg1NDIsImV4cCI6MTY0NTU3MjE0Miwic3ViIjoidGVzdC1zdWJqZWN0IiwianRpIjoiYmVlZi1mMDBkLWNhZmUifQ.SeM6jN2Xfdo86zC6vZX2MVu5z4mWjCqyZ8TciXsNtXdbAGgDRp__M9v8XqLIv9ZtS_WWbNFts--W8KvyACTtcI_7_YGhBJu79i574iftpPUDImQ_0xQojy6jymgSzk_o48qZkjvVGkAEzwOyg8lg32vQsWZFc3DawYJyjrlF7g0",
              "scope": Array [
                "test-scope",
              ],
              "ttl": 3600,
              "userId": undefined,
            }
          `);
  });

  test('Vanilla with UIG', async () => {
    const { tokenVerifierFactory } = await import('../lib/index.js');

    const tvf = tokenVerifierFactory({
      jwksUri: 'https://example.com/.well-known/jwks.json',
      userIdGenerator(claims) {
        const subject = claims.sub?.toString();
        if (!subject) {
          throw new Error('Missing subject');
        }
        return Buffer.from(new TextEncoder().encode(subject)).toString('hex');
      },
    });

    await expect(tvf(createValidTestToken('test1'))).resolves
      .toMatchInlineSnapshot(`
            Object {
              "claims": Object {
                "client_id": "888888800000008888111333335555",
                "exp": 1645572142,
                "iat": 1645568542,
                "jti": "beef-f00d-cafe",
                "scope": "test-scope",
                "sub": "test-subject",
                "token_use": "access",
              },
              "clientId": "888888800000008888111333335555",
              "expiresAt": 2022-02-22T23:22:22.000Z,
              "id": "beef-f00d-cafe",
              "ips": Array [],
              "isValid": [Function],
              "issuedAt": 2022-02-22T22:22:22.000Z,
              "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QxIn0.eyJjbGllbnRfaWQiOiI4ODg4ODg4MDAwMDAwMDg4ODgxMTEzMzMzMzU1NTUiLCJzY29wZSI6InRlc3Qtc2NvcGUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpYXQiOjE2NDU1Njg1NDIsImV4cCI6MTY0NTU3MjE0Miwic3ViIjoidGVzdC1zdWJqZWN0IiwianRpIjoiYmVlZi1mMDBkLWNhZmUifQ.SeM6jN2Xfdo86zC6vZX2MVu5z4mWjCqyZ8TciXsNtXdbAGgDRp__M9v8XqLIv9ZtS_WWbNFts--W8KvyACTtcI_7_YGhBJu79i574iftpPUDImQ_0xQojy6jymgSzk_o48qZkjvVGkAEzwOyg8lg32vQsWZFc3DawYJyjrlF7g0",
              "scope": Array [
                "test-scope",
              ],
              "ttl": 3600,
              "userId": "746573742d7375626a656374",
            }
          `);
  });

  test('Cognito', async () => {
    const { awsCognitoTokenVerifierFactory } = await import('../lib/index.js');

    const verifyCognitoToken = awsCognitoTokenVerifierFactory({
      region: 'local',
      userPoolId: 'issuer',
      async userIdGenerator() {
        return 'fakeUserId';
      },
    });

    const token = createValidTestToken('test1');
    const auth = await verifyCognitoToken(token);

    await expect(verifyCognitoToken(`${token}x`)).rejects.toBeInstanceOf(Error);

    expect(auth).toMatchInlineSnapshot(`
      Object {
        "claims": Object {
          "client_id": "888888800000008888111333335555",
          "exp": 1645572142,
          "iat": 1645568542,
          "jti": "beef-f00d-cafe",
          "scope": "test-scope",
          "sub": "test-subject",
          "token_use": "access",
        },
        "clientId": "888888800000008888111333335555",
        "expiresAt": 2022-02-22T23:22:22.000Z,
        "id": "beef-f00d-cafe",
        "ips": Array [],
        "isValid": [Function],
        "issuedAt": 2022-02-22T22:22:22.000Z,
        "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QxIn0.eyJjbGllbnRfaWQiOiI4ODg4ODg4MDAwMDAwMDg4ODgxMTEzMzMzMzU1NTUiLCJzY29wZSI6InRlc3Qtc2NvcGUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpYXQiOjE2NDU1Njg1NDIsImV4cCI6MTY0NTU3MjE0Miwic3ViIjoidGVzdC1zdWJqZWN0IiwianRpIjoiYmVlZi1mMDBkLWNhZmUifQ.SeM6jN2Xfdo86zC6vZX2MVu5z4mWjCqyZ8TciXsNtXdbAGgDRp__M9v8XqLIv9ZtS_WWbNFts--W8KvyACTtcI_7_YGhBJu79i574iftpPUDImQ_0xQojy6jymgSzk_o48qZkjvVGkAEzwOyg8lg32vQsWZFc3DawYJyjrlF7g0",
        "scope": Array [
          "test-scope",
        ],
        "ttl": 3600,
        "userId": "fakeUserId",
      }
    `);
    expect(auth.userId).toEqual('fakeUserId');
  });
});
