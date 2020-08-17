import jwks from 'jwks-rsa';
import { createAuthToken } from '@block65/auth-token';
import bs58 from 'bs58';
import type {
  ErrorRequestHandler,
  NextFunction,
  Request,
  RequestHandler,
  Response,
} from 'express';
import expressJwt from 'express-jwt';
import { expressAsyncWrap } from '@block65/express-async-wrapper';
import { AuthProviderError } from './errors/auth-provider-error';
import { TokenUnsuitableError } from './errors/token-unsuitable-error';
import { MissingAuthorizationError } from './errors/missing-authorization-error';
import { TokenExpiredError } from './errors/token-expired-error';
import { TokenInvalidError } from './errors/token-invalid-error';

export function uuidToUserId(uuid: string): string {
  if (uuid.length !== 36) {
    throw new Error('Invalid UUID string');
  }
  const buff = Buffer.from(uuid.replace(/-/g, ''), 'hex');
  if (buff.length !== 16) {
    throw new Error('Invalid UUID buffer');
  }
  return bs58.encode(buff);
}

export function userIdToUuid(userId: string): string {
  const str = bs58.decode(userId).toString('hex');
  return [
    str.slice(0, 8),
    str.slice(8, 12),
    str.slice(12, 16),
    str.slice(16, 20),
    str.slice(20),
  ].join('-');
}

export function expressAwsCognito(
  region: string,
  userPoolId: string,
): (RequestHandler | ErrorRequestHandler)[] {
  if (!region) {
    throw new Error('Missing/undefined issuer argument');
  }

  const issuer = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
  const jwksUri = `${issuer}/.well-known/jwks.json`;

  const jwtCheck = expressJwt({
    algorithms: ['RS256'],
    issuer,
    credentialsRequired: true,
    resultProperty: 'locals.auth',
    secret: jwks.expressJwtSecret({
      jwksUri,
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      handleSigningKeyError: (err, cb): void => {
        cb(
          err &&
            new AuthProviderError('Error handling JWT signing key', err).debug({
              region,
              userPoolId,
            }),
        );
      },
    }),
  });

  return [
    (req: Request, res: Response, next: NextFunction): void => {
      if (req.header('authorization')) {
        jwtCheck(req, res, next);
      } else {
        next();
      }
    },
    (
      err: expressJwt.UnauthorizedError | Error,
      req: Request,
      res: Response,
      next: NextFunction,
    ): void => {
      if (err instanceof expressJwt.UnauthorizedError) {
        switch (err.code) {
          case 'credentials_bad_scheme':
          case 'credentials_bad_format': {
            next(
              new MissingAuthorizationError(
                `Invalid credential scheme or format`,
                err,
              ),
            );
            break;
          }
          case 'invalid_token': {
            next(
              new TokenInvalidError(`Invalid token`, err).debug({
                code: err.code,
                inner: err.inner,
              }),
            );
            break;
          }
          default: {
            if ('inner' in err) {
              switch ((err.inner as Error).name) {
                case 'TokenExpiredError': {
                  next(
                    new TokenExpiredError(`Token Expired: ${err.code}`, err),
                  );
                  break;
                }
                default: {
                  next(new TokenInvalidError(`Token Error: ${err.code}`, err));
                  break;
                }
              }
            } else {
              next(
                new TokenInvalidError(
                  'Not Authorized due to unknown error',
                  err,
                ),
              );
            }
          }
        }
      } else {
        next(err);
      }
    },
    expressAsyncWrap(
      async (req, res, next): Promise<void> => {
        const [scheme = '', jwt = ''] =
          req.header('authorization')?.split(' ') || [];

        if (scheme.toLowerCase() !== 'bearer') {
          throw new MissingAuthorizationError(
            'Expected Authorization method: Bearer',
          );
        }

        if (!jwt) {
          throw new MissingAuthorizationError(
            'Invalid or Missing Bearer token',
          );
        }

        const claims: Record<string, unknown> = res.locals.auth;

        const userId =
          typeof claims.sub === 'string'
            ? await uuidToUserId(claims.sub)
            : undefined;

        if (claims.token_use !== 'access') {
          throw new TokenUnsuitableError(`Unsuitable Token Use`).debug({
            auth: res.locals.auth,
            claims,
          });
        }

        res.locals.token = createAuthToken({
          jwt,
          ips: Array.from(new Set([req.ip, ...req.ips])),
          claims,
          userId,
        });
        next();
      },
    ),
  ];
}
