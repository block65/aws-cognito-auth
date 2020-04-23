import { CustomError } from '@colacube/custom-error';

export class TokenUnsuitableError extends CustomError {
  public constructor(message: string, err?: Error) {
    super(message, err);
    this.setName('UnsuitableTokenError');
    this.statusCode = 400;
  }
}
