import { CustomError, Status } from '@block65/custom-error';

export class TokenUnsuitableError extends CustomError {
  code = Status.INVALID_ARGUMENT;
}
