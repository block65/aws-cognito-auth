import { CustomError, Status } from '@block65/custom-error';

export class AuthProviderError extends CustomError {
  public constructor(message: string, err?: Error) {
    super(message, err);
    this.setName('AuthProviderError');
    this.statusCode = Status.UNAVAILABLE;
    this.sensitive = true;
  }
}
