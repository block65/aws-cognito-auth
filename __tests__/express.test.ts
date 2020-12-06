import type { NextFunction, Request, Response } from 'express';
import express from 'express';
import { MissingAuthorizationError } from '../lib/errors/missing-authorization-error';
import { TokenInvalidError } from '../lib/errors/token-invalid-error';
import { TokenUnsuitableError } from '../lib/errors/token-unsuitable-error';
import { expressAwsCognito } from '../lib/express';

function mockReq(options: { headers?: Record<string, string> } = {}): Request {
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

function mockRes(): Response {
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

  return new Promise<void>((resolve) => {
    app(req, res, (err: unknown) => {
      next(err);
      resolve();
    });
  });
}

describe('express', () => {
  test('should throw MissingAuthorizationError with invalid headers', async () => {
    await testApp(mockReq(), mockRes(), (err: any) => {
      expect(err).toBeInstanceOf(MissingAuthorizationError);
    });
    expect.assertions(1);
  });

  test('should throw MissingAuthorizationError with no headers', async () => {
    await testApp(
      mockReq({
        headers: {
          authorization: 'OMG DED',
        },
      }),
      mockRes(),
      (err: any) => {
        expect(err).toBeInstanceOf(MissingAuthorizationError);
        expect(err.message).toContain('Bearer');
      },
    );
    expect.assertions(2);
  });

  test('should throw MissingAuthorizationError with missing JWT ', async () => {
    await testApp(
      mockReq({
        headers: {
          authorization: 'Bearer',
        },
      }),
      mockRes(),
      (err: any) => {
        expect(err).toBeInstanceOf(MissingAuthorizationError);
        expect(err.message).toContain('Invalid');
      },
    );
    expect.assertions(2);
  });

  test('should throw TokenError with bad JWT ', async () => {
    await testApp(
      mockReq({
        headers: {
          authorization: 'Bearer DED',
        },
      }),
      mockRes(),
      (err: any) => {
        expect(err).toBeInstanceOf(TokenInvalidError);
        expect(err.message).toContain('parse');
      },
    );
    expect.assertions(2);
  });

  test('should throw TokenError with fake JWT ', async () => {
    await testApp(
      mockReq({
        headers: {
          authorization:
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        },
      }),
      mockRes(),
      (err: any) => {
        expect(err).toBeInstanceOf(TokenUnsuitableError);
        // expect(err.debug()).toMatchObject({
        //   code: 'invalid_token',
        //   inner: expect.any(Error),
        // });
        // expect(err.message).toContain('Invalid');
      },
    );
    expect.assertions(1);
  });
});
