import { CustomError, Status } from '@block65/custom-error';

export class TokenInvalidError extends CustomError {
  public constructor(message: string, err?: Error) {
    super(message, err);
    this.setName('TokenError');
    this.statusCode = Status.INVALID_ARGUMENT;
    this.sensitive = true;
  }
}
