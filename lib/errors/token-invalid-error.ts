import { CustomError, Status } from '@block65/custom-error';

export class TokenInvalidError extends CustomError {
  code = Status.INVALID_ARGUMENT;
}
