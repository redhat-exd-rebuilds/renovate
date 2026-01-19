import { logger } from '../logger';

/**
 * Patterns for CI status checks that are not test-related.
 * These are excluded when determining if relevant CI checks exist.
 */
const nonTestStatusCheckPatterns = [
  'renovate/',
  'dependabot',
  'codecov/',
  'coveralls',
  'vercel',
  'netlify',
  'chromatic',
  'percy',
  'snyk',
  'fossa',
  'mergify',
  'bors',
];

/**
 * Detects if any CI status check names appear to be relevant (non-excluded).
 * Excludes known non-test services like Renovate, Codecov, Dependabot, etc.
 */
export function hasRelevantStatusChecks(checkNames: string[]): boolean {
  if (!checkNames || checkNames.length === 0) {
    return false;
  }

  const relevantChecks = checkNames.filter((name) => {
    const lowerName = name.toLowerCase();
    return !nonTestStatusCheckPatterns.some((pattern) =>
      lowerName.includes(pattern),
    );
  });

  logger.debug(
    { checkNames, relevantChecks },
    'hasRelevantStatusChecks evaluation',
  );

  return relevantChecks.length > 0;
}
