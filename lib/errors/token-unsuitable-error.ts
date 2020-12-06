import { CustomError, Status } from '@block65/custom-error';

export class TokenUnsuitableError extends CustomError {
  public constructor(message: string, err?: Error) {
    super(message, err);
    this.setName('UnsuitableTokenError');
    this.statusCode = Status.INVALID_ARGUMENT;
  }
}
