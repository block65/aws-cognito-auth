import { TokenUnsuitableError } from './token-unsuitable-error.js';

export class TokenExpiredError extends TokenUnsuitableError {
  public constructor(message: string, err?: Error) {
    super(message, err);
    this.setName('ExpiredTokenError');
  }
}
