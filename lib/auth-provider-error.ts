import { CustomError } from '@colacube/custom-error';

export class AuthProviderError extends CustomError {
  public constructor(message: string, err?: Error) {
    super(message, err);
    this.setName('AuthProviderError');
    this.statusCode = 500;
    this.internal = true;
  }
}
