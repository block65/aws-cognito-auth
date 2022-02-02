import { describe, expect, jest, test } from '@jest/globals';
import * as jwksRsaModule from 'jwks-rsa';
import jsonwebtoken from 'jsonwebtoken';
import { mockPublicKeyRsa4096, throwAsObject } from './helpers.js';

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

describe('JWT Verify', () => {
  // jest.useFakeTimers('modern');
  // jest.setSystemTime(new Date('2022-02-22T22:22:22Z'));

  test('Basic', async () => {
    const { jsonWebTokenVerify } = await import('../lib/index.js');

    const completeltInvalidJwt = 'null';
    await expect(
      jsonWebTokenVerify(completeltInvalidJwt, '').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "jwt malformed",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const completeltInvalidButFormattedJwt = 'undefined.null.0';
    await expect(
      jsonWebTokenVerify(completeltInvalidButFormattedJwt, '').catch(
        throwAsObject,
      ),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "invalid token",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const stringPayloadJwt = 'e30.InN0cmluZyBwYXlsb2FkIg';
    await expect(
      jsonWebTokenVerify(stringPayloadJwt, '').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "jwt malformed",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const malformedHeaderJwt = 'e31wYXJzZSBlcnJvcg.InN0cmluZyBwYXlsb2FkIg';
    await expect(
      jsonWebTokenVerify(malformedHeaderJwt, '').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "jwt malformed",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const malformedPayloadJwt = 'e30.e31wYXJzZSBlcnJvcg';
    await expect(
      jsonWebTokenVerify(malformedPayloadJwt, '').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "jwt malformed",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const emptyButValidJwt = 'e30.e30.hash';
    await expect(
      jsonWebTokenVerify(emptyButValidJwt, 'secret').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "message": "invalid algorithm",
              "name": "JsonWebTokenError",
              "stack": Any<String>,
            }
          `,
    );

    const expiredJwt = jsonwebtoken.sign(
      {
        exp: Math.floor(Date.now() / 1000),
      },
      'correct-secret',
    );
    await expect(
      jsonWebTokenVerify(expiredJwt, 'correct-secret').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 16,
              "details": Array [
                Object {
                  "violations": Array [
                    Object {
                      "description": "Authorisation has expired",
                      "field": "exp",
                    },
                  ],
                },
              ],
              "message": "jwt expired",
              "stack": Any<String>,
              "status": "UNAUTHENTICATED",
            }
          `,
    );

    const badSecretStringJwt = jsonwebtoken.sign(
      {
        exp: 0,
      },
      'correct-secret',
    );
    await expect(
      jsonWebTokenVerify(badSecretStringJwt, 'incorrect-secret').catch(
        throwAsObject,
      ),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "invalid signature",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const missingKid = jsonwebtoken.sign(
      {
        kid: 'non-existent-kid',
      },
      'some-key',
    );
    await expect(
      jsonWebTokenVerify(missingKid, 'incorrect-secret').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "invalid signature",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const badAudience = jsonwebtoken.sign(
      {
        aud: 'some-audience',
      },
      'correct-secret',
    );
    await expect(
      jsonWebTokenVerify(badAudience, 'correct-secret', {
        audience: 'another-audience',
      }).catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "jwt audience invalid. expected: another-audience",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const badIssuer = jsonwebtoken.sign(
      {
        iss: 'some-issuer',
      },
      'correct-secret',
    );
    await expect(
      jsonWebTokenVerify(badIssuer, 'correct-secret', {
        issuer: 'another-issuer',
      }).catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "jwt issuer invalid. expected: another-issuer",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const badId = jsonwebtoken.sign(
      {
        id: 'some-id',
      },
      'correct-secret',
    );
    await expect(
      jsonWebTokenVerify(badId, 'correct-secret', {
        jwtid: 'another-id',
      }).catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "message": "jwt jwtid invalid. expected: another-id",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );

    const badSubject = jsonwebtoken.sign(
      {
        sub: 'some-subject',
      },
      'correct-secret',
    );
    await expect(
      jsonWebTokenVerify(badSubject, 'correct-secret', {
        subject: 'another-subject',
      }).catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "message": "jwt subject invalid. expected: another-subject",
              "name": "JsonWebTokenError",
              "stack": Any<String>,
            }
          `,
    );

    const badNotBefore = jsonwebtoken.sign(
      {
        nbf: Math.floor(Date.now() / 1000) + 10,
      },
      'correct-secret',
    );
    await expect(
      jsonWebTokenVerify(badNotBefore, 'correct-secret').catch(throwAsObject),
    ).rejects.toMatchInlineSnapshot<any>(
      {
        stack: expect.any(String),
      },
      `
            Object {
              "code": 3,
              "details": Array [
                Object {
                  "violations": Array [
                    Object {
                      "description": "Authorisation is not valid yet",
                      "field": "exp",
                    },
                  ],
                },
              ],
              "message": "jwt not active",
              "stack": Any<String>,
              "status": "INVALID_ARGUMENT",
            }
          `,
    );
  });
});
