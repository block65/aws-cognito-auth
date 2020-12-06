import type { JsonObject } from 'type-fest';
import jwks from 'jwks-rsa';
import { AuthToken, createAuthToken } from '@block65/auth-token';
import expressJwt from 'express-jwt';
import * as jsonwebtoken from 'jsonwebtoken';
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

function errorHandler(err: Error): never {
  if (err instanceof expressJwt.UnauthorizedError) {
    switch (err.code) {
      case 'credentials_bad_scheme':
      case 'credentials_bad_format': {
        throw new MissingAuthorizationError(
          `Invalid credential scheme or format`,
          err,
        );
      }
      case 'invalid_token': {
        throw new TokenInvalidError(`Invalid token`, err).debug({
          code: err.code,
          inner: err.inner,
        });
      }
      default: {
        if ('inner' in err) {
          switch ((err.inner as Error).name) {
            case 'TokenExpiredError': {
              throw new TokenExpiredError(`Token Expired: ${err.code}`, err);
            }
            default: {
              throw new TokenInvalidError(`Token Error: ${err.code}`, err);
            }
          }
        } else {
          throw new TokenInvalidError(
            'Not Authorized due to unknown error',
            err,
          );
        }
      }
    }
  } else {
    throw err;
  }
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
      .catch(errorHandler);

    const verified = await verifyJwt(jwt, key.getPublicKey(), {
      ...options,
      algorithms: ['RS256'],
    }).catch(errorHandler);

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
