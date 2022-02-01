import { CustomError } from '@block65/custom-error';
import { describe, test, jest, expect } from '@jest/globals';
import jsonwebtoken from 'jsonwebtoken';
import * as jwksRsaModule from 'jwks-rsa';

const mockPrivateKeyRsa4096: Record<string, string> = {
  test1: `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgF47W5K5MPXWHk08DpsiNBjpcTr2gsiylv5eNixT7e95QzgeenTq
CaQ0k+3RsVN+5kuTcfvTLqEoXrSbj9uBsZ2G1qtopjgrQo9cYPNncgmI/rZzR8nt
osZmwjTUudOTgna55Jw533fXcmF0VeD9Ml21cPgXhGheO2u3oYQl2mjnAgMBAAEC
gYAFtyXzvUXJ82W9G4JrSGTOigIzKFaAY8yiuwYgJCsPVlSMZ9TXmIZjLkk2qHxP
6yd+t/+23XU7kx5DaBgOoUwrhdI3fmRyF0d23F3UWc5FAUy6yUTPZNvkQmA0MsW1
e8b6hUxhd7ThoQVRtbPJ/JDcAWmdF/S4RHAf1wNK8b4hEQJBAK9gVg6BuGcdYxtp
Qjw67zD5EEd4M4q4PQWmsAUYbeC0JDGWNHJxOWjuTEuDFVRCuPBguvQnSupoi8ge
zxjezokCQQCJjU4JEE9abMeKBRsiaqMZHi5Rcq0kTGu8qHV8Gzr34U1MShsBb1Et
2/HuDmNOEva8ljpVB7PzcbzkS8ZO7R/vAkAVCITJsJ0hINEmFHWxK5BMW1Ksf6oO
1RHcf6VUtx1WecRtfgpEP3gXMZ1M4SfJt0be7Xr+lUfS3T8GfUtxPCehAkEAh7ag
WLb75DbRhS7Wf9WAyCaMApZHmDnCTqhTCjj/rFRh5LR1AqxnBv0sLPmLJxv0z0rV
kNGBzd7ZRNIyferdhwJAUh0aNh/cjXSvxAE/gXl5FPzcaX2pJrIdo4+s6NFr5fBB
HS/UOnpzGCe0Nm+0yRK6Y6koi//UOheAk2S8b8AQNA==
-----END RSA PRIVATE KEY-----`,
};

const mockPublicKeyRsa4096: Record<keyof typeof mockPrivateKeyRsa4096, string> =
  {
    test1: `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgF47W5K5MPXWHk08DpsiNBjpcTr2
gsiylv5eNixT7e95QzgeenTqCaQ0k+3RsVN+5kuTcfvTLqEoXrSbj9uBsZ2G1qto
pjgrQo9cYPNncgmI/rZzR8ntosZmwjTUudOTgna55Jw533fXcmF0VeD9Ml21cPgX
hGheO2u3oYQl2mjnAgMBAAE=
-----END PUBLIC KEY-----`,
  };

// const mockPublicKeyRsa4096Modulus: Record<keyof typeof mockPublicKeyRsa4096,
//   Buffer> = {
//   test1: Buffer.from(
//     '5e3b5b92b930f5d61e4d3c0e9b223418e9713af682c8b296fe5e362c53edef7943381e7a74ea09a43493edd1b1537ee64b9371fbd32ea1285eb49b8fdb81b19d86d6ab68a6382b428f5c60f367720988feb67347c9eda2c666c234d4b9d3938276b9e49c39df77d772617455e0fd325db570f81784685e3b6bb7a18425da68e7',
//     'hex',
//   ),
// };

function createTestToken(kid: string): string {
  return jsonwebtoken.sign(
    {
      client_id: '888888800000008888111333335555',
      scope: 'test-scope',
      token_use: 'access',
    },
    mockPrivateKeyRsa4096[kid],
    {
      keyid: kid,
      algorithm: 'RS256',
      subject: 'test-subject',
      expiresIn: '1h',
      jwtid: `beef-f00d-cafe`,
    },
  );
}

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
  jest.setSystemTime(0);

  test('Cognito', async () => {
    const { awsCognitoTokenVerifierFactory } = await import('../lib/index.js');

    const verifyCognitoToken = awsCognitoTokenVerifierFactory({
      region: 'local',
      userPoolId: 'issuer',
      async userIdGenerator() {
        return 'fakeUserId';
      },
    });

    const token = createTestToken('test1');
    const auth = await verifyCognitoToken(token);

    await expect(verifyCognitoToken(`${token}x`)).rejects.toBeInstanceOf(Error);

    expect(auth).toMatchInlineSnapshot(`
      Object {
        "claims": Object {
          "client_id": "888888800000008888111333335555",
          "exp": 3600,
          "iat": 0,
          "jti": "beef-f00d-cafe",
          "scope": "test-scope",
          "sub": "test-subject",
          "token_use": "access",
        },
        "clientId": "888888800000008888111333335555",
        "expiresAt": 1970-01-01T01:00:00.000Z,
        "id": "beef-f00d-cafe",
        "ips": Array [],
        "isValid": [Function],
        "issuedAt": 1970-01-01T00:00:00.000Z,
        "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QxIn0.eyJjbGllbnRfaWQiOiI4ODg4ODg4MDAwMDAwMDg4ODgxMTEzMzMzMzU1NTUiLCJzY29wZSI6InRlc3Qtc2NvcGUiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJpYXQiOjAsImV4cCI6MzYwMCwic3ViIjoidGVzdC1zdWJqZWN0IiwianRpIjoiYmVlZi1mMDBkLWNhZmUifQ.O1z8H9o3e0-C2pcPehfcofOXR7kSMzdLxEsRqxmAAm-pLaOEkrjxj9Ui98LBnni0WqmW8B6YyQR0J9owxXdrGsO1a7J15iC5bFdLSmZVVN8BEEf3Vfg_OsDlLWWh0s3XE9ilx2IFKqwAh8Q-4SGep1XDY0RekIH4FquxtHI13ok",
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
