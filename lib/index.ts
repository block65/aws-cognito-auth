import type { JsonObject } from 'type-fest';
import { JwksClient, SigningKeyNotFoundError } from 'jwks-rsa';
import { AuthToken, createAuthToken } from '@block65/auth-token';
import jsonwebtoken from 'jsonwebtoken';
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

function verifyJwt(
  jwt: string,
  key: jsonwebtoken.Secret | jsonwebtoken.GetPublicKeyOrSecret,
  options?: jsonwebtoken.VerifyOptions,
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    jsonwebtoken.verify(jwt, key, options, (err, result) => {
      return err ? reject(err) : resolve(!!result);
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
    const decoded:
      | {
          header?: { kid?: string };
          payload?: JsonObject;
          signature?: string;
        }
      | null
      | string = jsonwebtoken.decode(jwt, {
      complete: true,
    });

    if (!decoded || typeof decoded === 'string') {
      throw new TokenInvalidError('Unparseable token').debug({ decoded });
    }

    if (!decoded.header?.kid) {
      throw new TokenUnsuitableError('Missing key id').debug({
        header: decoded.header,
      });
    }

    const key = await client.getSigningKey(decoded.header.kid).catch((err) => {
      if (err instanceof SigningKeyNotFoundError) {
        throw new TokenInvalidError(err.message, err);
      }
      throw err;
    });

    const verified = await verifyJwt(jwt, key.getPublicKey(), {
      ...options,
      algorithms: ['RS256'],
    }).catch((err) => {
      if (err instanceof jsonwebtoken.TokenExpiredError) {
        throw new TokenExpiredError(err.message, err);
      }

      if (err instanceof jsonwebtoken.NotBeforeError) {
        throw new TokenUnsuitableError(err.message, err);
      }

      if (err instanceof jsonwebtoken.JsonWebTokenError) {
        throw new TokenInvalidError(err.message, err);
      }
      throw err;
    });

    if (!verified) {
      throw new TokenInvalidError('not verified');
    }

    if (!decoded?.payload?.sub) {
      throw new TokenUnsuitableError('Missing subject');
    }

    if (decoded.payload.token_use !== 'access') {
      throw new TokenUnsuitableError(`Unsuitable Token Use`).debug({
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
  if (!region) {
    throw new Error('Missing/undefined issuer argument');
  }

  const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  const jwksUri = `${issuer}/.well-known/jwks.json`;

  return tokenVerifierFactory({ jwksUri, userIdGenerator });
}
