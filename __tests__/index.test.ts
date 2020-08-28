import type { NextFunction, Request, Response } from 'express';
import express from 'express';
import { expressAwsCognito } from '../lib';
import { MissingAuthorizationError } from '../lib/errors/missing-authorization-error';
import { TokenInvalidError } from '../lib/errors/token-invalid-error';

function makeMockRequest(
  options: { headers?: Record<string, string> } = {},
): Request {
  return ({
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
  } as unknown) as Request;
}

function makeMockResponse(): Response {
  return ({
    setHeader: jest.fn().mockReturnThis(),
    status: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    end: jest.fn().mockReturnThis(),
  } as unknown) as Response;
}

function testApp(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<unknown> {
  const app = express();
  app.use(expressAwsCognito({ region: 'local', userPoolId: 'issuer' }));

  return new Promise((resolve) => {
    app(req, res, (err: unknown) => {
      next(err);
      resolve();
    });
  });
}

test('should throw MissingAuthorizationError with invalid headers ', async () => {
  await testApp(makeMockRequest(), makeMockResponse(), (err: any) => {
    expect(err).toBeInstanceOf(MissingAuthorizationError);
  });
  expect.assertions(1);
});

test('should throw MissingAuthorizationError with no headers ', async () => {
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
  expect.assertions(2);
});

test('should throw MissingAuthorizationError with missing JWT ', async () => {
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
  expect.assertions(2);
});

test('should throw TokenError with bad JWT ', async () => {
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
  expect.assertions(2);
});

test('should throw TokenError with fake JWT ', async () => {
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
  expect.assertions(2);
});
