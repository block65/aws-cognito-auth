import { Status } from '@block65/custom-error';
import { TokenUnsuitableError } from './token-unsuitable-error.js';

export class TokenExpiredError extends TokenUnsuitableError {
  public code = Status.UNAUTHENTICATED;
}
