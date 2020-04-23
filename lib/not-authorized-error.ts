import { CustomError } from '@colacube/custom-error';

export class NotAuthorizedError extends CustomError {
  public constructor(message: string, err?: Error) {
    super(message, err);
    this.setName('NotAuthorizedError');
    this.statusCode = 401;
    this.internal = true;
  }
}
