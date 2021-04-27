import { SigningKey } from 'jwks-rsa';
import * as jsonwebtoken from 'jsonwebtoken';
import * as crypto from 'crypto';
import { awsCognitoTokenVerifierFactory } from '../lib';

const mockPrivateKeyRsa4096: Record<string, string> = {
  welp: `-----BEGIN RSA PRIVATE KEY-----
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

const mockPublicKeyRsa4096: Record<string, string> = {
  welp: `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgF47W5K5MPXWHk08DpsiNBjpcTr2
gsiylv5eNixT7e95QzgeenTqCaQ0k+3RsVN+5kuTcfvTLqEoXrSbj9uBsZ2G1qto
pjgrQo9cYPNncgmI/rZzR8ntosZmwjTUudOTgna55Jw533fXcmF0VeD9Ml21cPgX
hGheO2u3oYQl2mjnAgMBAAE=
-----END PUBLIC KEY-----`,
};

jest.mock('jwks-rsa', () => {
  return function jwksRsa() {
    return {
      async getSigningKey(kid: string): Promise<SigningKey> {
        return {
          kid,
          alg: 'RS256',
          rsaPublicKey: mockPublicKeyRsa4096[kid],
          publicKey: mockPublicKeyRsa4096[kid],
          getPublicKey: () => {
            return mockPublicKeyRsa4096[kid];
          },
        };
      },
    };
  };
});

function createTestToken(kid: string): string {
  return jsonwebtoken.sign(
    {
      client_id: crypto.randomBytes(12).toString('hex'),
      scope: 'test',
      token_use: 'access',
    },
    mockPrivateKeyRsa4096[kid],
    {
      keyid: kid,
      algorithm: 'RS256',
      subject: 'test',
      expiresIn: '1h',
      jwtid: crypto.randomBytes(12).toString('hex'),
    },
  );
}

describe('token verifier', () => {
  test('basic', async () => {
    const verifyCognitoToken = awsCognitoTokenVerifierFactory({
      region: 'local',
      userPoolId: 'issuer',
      async userIdGenerator() {
        return 'fakeUserId';
      },
    });

    const token = createTestToken('welp');

    const auth = await verifyCognitoToken(token);

    expect(auth).toHaveProperty('userId', 'fakeUserId');
  });
});
