import { CustomError, Status } from '@block65/custom-error';

export class MissingAuthorizationError extends CustomError {
  public constructor(message: string, err?: Error) {
    super(message, err);
    this.setName('MissingAuthorizationError');
    this.statusCode = Status.UNAUTHENTICATED;
  }
}
