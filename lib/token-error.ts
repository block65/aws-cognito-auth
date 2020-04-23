import { CustomError } from '@colacube/custom-error';

export class TokenError extends CustomError {
  public constructor(message: string, err?: Error) {
    super(message, err);
    this.setName('TokenError');
    this.statusCode = 400;
    this.internal = true;
  }
}
