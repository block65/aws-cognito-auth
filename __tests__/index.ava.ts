import test from 'ava';
import { randomBytes } from 'crypto';
import jsonwebtoken from 'jsonwebtoken';
import type { SigningKey } from 'jwks-rsa';
import { mockCommonJs } from '@block65/typesmock';

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

const mockPublicKeyRsa4096Modulus: Record<
  keyof typeof mockPublicKeyRsa4096,
  Buffer
> = {
  test1: Buffer.from(
    '5e3b5b92b930f5d61e4d3c0e9b223418e9713af682c8b296fe5e362c53edef7943381e7a74ea09a43493edd1b1537ee64b9371fbd32ea1285eb49b8fdb81b19d86d6ab68a6382b428f5c60f367720988feb67347c9eda2c666c234d4b9d3938276b9e49c39df77d772617455e0fd325db570f81784685e3b6bb7a18425da68e7',
    'hex',
  ),
};

function createTestToken(kid: string): string {
  return jsonwebtoken.sign(
    {
      client_id: randomBytes(12).toString('hex'),
      scope: 'test',
      token_use: 'access',
    },
    mockPrivateKeyRsa4096[kid],
    {
      keyid: kid,
      algorithm: 'RS256',
      subject: 'test',
      expiresIn: '1h',
      jwtid: randomBytes(12).toString('hex'),
    },
  );
}

test.before(async () => {
  await mockCommonJs('jwks-rsa', {
    namedExports: {
      JwksClient: function MockJwksClient() {
        return {
          async getSigningKey(kid: string): Promise<SigningKey> {
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
    },
  });
});

test('Cognito TVF', async (t) => {
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

  t.is(auth.userId, 'fakeUserId');
});
