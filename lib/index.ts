import { AuthToken, createAuthToken } from '@block65/auth-token';
import jsonwebtoken from 'jsonwebtoken';
import { JwksClient, SigningKeyNotFoundError } from 'jwks-rsa';
import type { JsonObject } from 'type-fest';
import { TokenExpiredError } from './errors/token-expired-error.js';
import { TokenInvalidError } from './errors/token-invalid-error.js';
import { TokenUnsuitableError } from './errors/token-unsuitable-error.js';

export { TokenInvalidError, TokenUnsuitableError, TokenExpiredError };

export interface AwsCognitoAuthOptions {
  region: string;
  userPoolId: string;
  userIdGenerator?: (claims: JsonObject) => Promise<string | void>;
}

interface TokenVerifierOptions {
  jwksUri: string;
  userIdGenerator?: (claims: JsonObject) => Promise<string | void>;
}

function jsonWebTokenVerifyAsync(
  jwt: string,
  key: jsonwebtoken.Secret | jsonwebtoken.GetPublicKeyOrSecret,
  options?: jsonwebtoken.VerifyOptions,
): Promise<jsonwebtoken.JwtPayload | undefined> {
  return new Promise<jsonwebtoken.JwtPayload>((resolve, reject) => {
    jsonwebtoken.verify(jwt, key, options, (err, result) => {
      if (!result || typeof result === 'string') {
        throw new Error('Bad token verify result');
      }

      return err ? reject(err) : resolve(result);
    });
  });
}

export function tokenVerifierFactory({
  jwksUri,
  userIdGenerator,
}: TokenVerifierOptions): (token: string) => Promise<AuthToken> {
  const client = new JwksClient({
    jwksUri,
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
  });

  const options = {};

  return async (jwt: string): Promise<AuthToken> => {
    const decoded = jsonwebtoken.decode(jwt, {
      complete: true,
    });

    if (!decoded || typeof decoded === 'string') {
      throw new TokenInvalidError('Unparseable token').debug({ decoded });
    }

    if (!decoded.header?.kid) {
      throw new TokenUnsuitableError('Missing key id').debug({
        decoded,
      });
    }

    if (typeof decoded.payload === 'string') {
      throw new TokenUnsuitableError('Bad string payload').debug({
        decoded,
      });
    }

    const key = await client.getSigningKey(decoded.header.kid).catch((err) => {
      if (err instanceof SigningKeyNotFoundError) {
        throw new TokenInvalidError(err.message, err);
      }
      throw err;
    });

    const verified = await jsonWebTokenVerifyAsync(jwt, key.getPublicKey(), {
      ...options,
      algorithms: ['RS256'],
    }).catch((err) => {
      if (err instanceof jsonwebtoken.TokenExpiredError) {
        throw new TokenExpiredError(err.message, err).addDetail({
          violations: [
            {
              field: 'exp',
              description: 'Authorisation has expired',
            },
          ],
        });
      }

      if (err instanceof jsonwebtoken.NotBeforeError) {
        throw new TokenUnsuitableError(err.message, err).addDetail({
          violations: [
            {
              field: 'exp',
              description: 'Authorisation is not valid yet',
            },
          ],
        });
      }

      if (err instanceof jsonwebtoken.JsonWebTokenError) {
        throw new TokenInvalidError(err.message, err);
      }
      throw err;
    });

    if (!verified) {
      throw new TokenInvalidError('not verified').addDetail({
        violations: [
          {
            field: 'jwt',
            description: 'Verification failed',
          },
        ],
      });
    }

    if (!decoded.payload?.sub) {
      throw new TokenUnsuitableError('Missing subject')
        .addDetail({
          violations: [
            {
              field: 'sub',
              description: 'Missing subject',
            },
          ],
        })
        .debug({ decoded });
    }

    if (decoded.payload.token_use && decoded.payload.token_use !== 'access') {
      throw new TokenUnsuitableError(`Unsuitable Token Use`)
        .addDetail({
          violations: [
            {
              field: 'token_use',
              description: 'Not an access token',
            },
          ],
        })
        .debug({
          payload: decoded.payload,
        });
    }

    const userId = userIdGenerator
      ? await userIdGenerator(decoded.payload)
      : undefined;

    return createAuthToken({
      jwt,
      ips: Array.from(
        new Set([
          /* req.ip, ...req.ips */
        ]),
      ),
      claims: decoded.payload,
      ...(userId && { userId }),
    });
  };
}

export function awsCognitoTokenVerifierFactory({
  region,
  userPoolId,
  userIdGenerator,
}: AwsCognitoAuthOptions): (token: string) => Promise<AuthToken> {
  if (!region || typeof region !== 'string') {
    throw new TypeError('Invalid region argument');
  }

  const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  const jwksUri = `${issuer}/.well-known/jwks.json`;

  return tokenVerifierFactory({ jwksUri, userIdGenerator });
}
