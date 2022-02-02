import { CustomError } from '@block65/custom-error';
import jsonwebtoken from 'jsonwebtoken';

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

export const mockPublicKeyRsa4096: Record<
  keyof typeof mockPrivateKeyRsa4096,
  string
> = {
  test1: `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgF47W5K5MPXWHk08DpsiNBjpcTr2
gsiylv5eNixT7e95QzgeenTqCaQ0k+3RsVN+5kuTcfvTLqEoXrSbj9uBsZ2G1qto
pjgrQo9cYPNncgmI/rZzR8ntosZmwjTUudOTgna55Jw533fXcmF0VeD9Ml21cPgX
hGheO2u3oYQl2mjnAgMBAAE=
-----END PUBLIC KEY-----`,
};

export function createValidTestToken(
  kid: keyof typeof mockPrivateKeyRsa4096,
): string {
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

export function throwAsObject(err: CustomError | any): never {
  if (err instanceof CustomError) {
    throw Object.assign(new Error(), err.serialize());
  }
  throw err;
}
