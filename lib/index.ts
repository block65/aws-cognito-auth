import jwks from 'jwks-rsa';
import type {
  ErrorRequestHandler,
  NextFunction,
  Request,
  RequestHandler,
  Response,
} from 'express';
import { createToken, StandardClaims, UserClaims } from '@colacube/auth-token';
import bs58 from 'bs58';
import { expressAsyncWrap } from '@colacube/express-async-wrapper';
import expressJwt, { UnauthorizedError } from 'express-jwt';
import { NotAuthorizedError } from './not-authorized-error';
import { AuthProviderError } from './auth-provider-error';
import { TokenUnsuitableError } from './token-unsuitable-error';
import { MissingAuthorizationError } from './missing-authorization-error';
import { TokenExpiredError } from './token-expired-error';
import { TokenError } from './token-error';

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

  const jwtCheck: expressJwt.RequestHandler = expressJwt({
    resultProperty: 'locals.auth',
    credentialsRequired: true,
    secret: jwks.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri,
      handleSigningKeyError: (err, cb): void => {
        cb(err && new AuthProviderError('Error handling JWT signing key', err).debug(
          {region, userPoolId}
        ));
      },
    }),
    issuer,
    algorithms: ['RS256'],
  });

  return [
    (req: Request, res: Response, next: NextFunction): void => {  debugger;
      if (req.headers.authorization) {
        jwtCheck(req, res, next);
      } else {
        next();
      }
    },
    (
      err: UnauthorizedError | Error,
      req: Request,
      res: Response,
      next: NextFunction,
    ): void => {
      if (err instanceof UnauthorizedError) {
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
            next(new TokenError(`Invalid token`, err).debug(err));
            break;
          }
          default: {
            if ('inner' in err) {
              // @ts-ignore
              switch (err.inner.name) {
                case 'TokenExpiredError': {
                  next(new TokenExpiredError(`Token Expired: ${err.code}`, err));
                  break;
                }
                default: {
                  next(new NotAuthorizedError(`Token Error: ${err.code}`, err));
                  break;
                }
              }
            } else {
              next(new TokenError('Not Authorized due to unknown error', err));
            }
          }
        }
      } else {
        next(err);
      }
    },
    expressAsyncWrap(
      async (req, res, next): Promise<void> => {
        const [scheme, jwt] = (req.header('authorization') || '').split(' ');
        if (scheme.toLowerCase() !== 'bearer' || !jwt) {
          next(
            new MissingAuthorizationError(
              'Missing or Invalid Authorization Header',
            ),
          );
        } else {
          const claims: StandardClaims & UserClaims = res.locals.auth;

          const userId =
            claims.sub && claims.username ? await uuidToUserId(claims.sub) : '';

          if (claims.token_use !== 'access') {
            throw new TokenUnsuitableError(`Unsuitable Token Use`).debug({
              auth: res.locals.auth,
              claims,
            });
          }

          res.locals.token = createToken({
            jwt,
            ips: Array.from(new Set([req.ip, ...req.ips])),
            userId,
            claims,
          });
          next();
        }
      },
    ),
  ];
}
