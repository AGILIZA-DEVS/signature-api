/**
 * Type-safe error handling utility
 */
export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  return 'Unknown error occurred';
}

/**
 * Check if value is defined (not null or undefined)
 */
export function isDefined<T>(value: T | null | undefined): value is T {
  return value !== null && value !== undefined;
}

/**
 * Assert that value is defined, throw error if not
 */
export function assertDefined<T>(value: T | null | undefined, message: string): asserts value is T {
  if (!isDefined(value)) {
    throw new Error(message);
  }
}