import * as express from 'express';
import type { NextFunction, Request, Response } from 'express';
import { expressAwsCognito } from '../lib';
import { MissingAuthorizationError } from '../lib/errors/missing-authorization-error';
import { TokenInvalidError } from '../lib/errors/token-invalid-error';

const makeMockRequest = (
  options: { headers?: Record<string, string> } = {},
): Request =>
  (({
    body: {},
    cookies: {},
    query: {},
    params: {},
    headers: options.headers || {},
    method: 'get',
    url: '/',
    listeners: () => [],
    get: jest.fn(),
    resume: jest.fn().mockReturnThis(),
    ...options,
  } as unknown) as Request);

const makeMockResponse = (): Response =>
  (({
    setHeader: jest.fn().mockReturnThis(),
    status: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    end: jest.fn().mockReturnThis(),
  } as unknown) as Response);

function testApp(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<any> {
  const app = express();
  app.use(expressAwsCognito('local', 'issuer'));

  return new Promise((resolve) => {
    app(req, res, (err: any) => {
      next(err);
      resolve();
    });
  });
}

test('should throw MissingAuthorizationError with invalid headers ', async () => {
  expect.assertions(1);
  await testApp(makeMockRequest(), makeMockResponse(), (err: any) => {
    expect(err).toBeInstanceOf(MissingAuthorizationError);
  });
});

test('should throw MissingAuthorizationError with no headers ', async () => {
  expect.assertions(2);
  await testApp(
    makeMockRequest({
      headers: {
        authorization: 'OMG DED',
      },
    }),
    makeMockResponse(),
    (err: any) => {
      expect(err).toBeInstanceOf(MissingAuthorizationError);
      expect(err.message).toContain('Invalid');
    },
  );
});

test('should throw MissingAuthorizationError with missing JWT ', async () => {
  expect.assertions(2);
  await testApp(
    makeMockRequest({
      headers: {
        authorization: 'Bearer',
      },
    }),
    makeMockResponse(),
    (err: any) => {
      expect(err).toBeInstanceOf(MissingAuthorizationError);
      expect(err.message).toContain('Invalid');
    },
  );
});

test('should throw TokenError with bad JWT ', async () => {
  expect.assertions(2);
  await testApp(
    makeMockRequest({
      headers: {
        authorization: 'Bearer DED',
      },
    }),
    makeMockResponse(),
    (err: any) => {
      expect(err).toBeInstanceOf(TokenInvalidError);
      expect(err.message).toContain('Invalid');
    },
  );
});

test('should throw TokenError with fake JWT ', async () => {
  expect.assertions(2);
  await testApp(
    makeMockRequest({
      headers: {
        authorization:
          'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      },
    }),
    makeMockResponse(),
    (err: any) => {
      expect(err).toBeInstanceOf(TokenInvalidError);
      expect(err.debug()).toMatchObject({
        code: 'invalid_token',
        inner: expect.any(Error),
      });
      // expect(err.message).toContain('Invalid');
    },
  );
});
