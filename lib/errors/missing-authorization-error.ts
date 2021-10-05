import { CustomError, Status } from '@block65/custom-error';

export class MissingAuthorizationError extends CustomError {
  public code = Status.UNAUTHENTICATED;
}
