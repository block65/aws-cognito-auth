import type { JsonObject } from 'type-fest';
import jwks from 'jwks-rsa';
import { AuthToken, createAuthToken } from '@block65/auth-token';
import * as jsonwebtoken from 'jsonwebtoken';
import { JsonWebTokenError } from 'jsonwebtoken';
import { TokenUnsuitableError } from './errors/token-unsuitable-error';
import { MissingAuthorizationError } from './errors/missing-authorization-error';
import { TokenExpiredError } from './errors/token-expired-error';
import { TokenInvalidError } from './errors/token-invalid-error';

export interface CognitoOptions {
  region: string;
  userPoolId: string;
  userIdGenerator?: (claims: JsonObject) => Promise<string | void>;
}

export interface Options {
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
}: Options): (token: string) => Promise<AuthToken> {
  const client = jwks({
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

    const key = await client
      .getSigningKeyAsync(decoded.header.kid)
      .catch((err) => {
        if (err instanceof jwks.SigningKeyNotFoundError) {
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
}: CognitoOptions): (token: string) => Promise<AuthToken> {
  if (!region) {
    throw new Error('Missing/undefined issuer argument');
  }

  const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  const jwksUri = `${issuer}/.well-known/jwks.json`;

  return tokenVerifierFactory({ jwksUri, userIdGenerator });
}
