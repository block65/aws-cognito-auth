import { CustomError, Status } from '@block65/custom-error';

export class TokenUnsuitableError extends CustomError {
  public code = Status.INVALID_ARGUMENT;
}
