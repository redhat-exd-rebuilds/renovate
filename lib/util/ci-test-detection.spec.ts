import { hasRelevantStatusChecks } from './ci-test-detection';

describe('util/ci-test-detection', () => {
  describe('hasRelevantStatusChecks', () => {
    it('returns false for empty array', () => {
      expect(hasRelevantStatusChecks([])).toBe(false);
    });

    it('returns false for null/undefined', () => {
      expect(hasRelevantStatusChecks(null as any)).toBe(false);
      expect(hasRelevantStatusChecks(undefined as any)).toBe(false);
    });

    it('returns true for test-related checks', () => {
      expect(hasRelevantStatusChecks(['ci/test', 'build'])).toBe(true);
      expect(hasRelevantStatusChecks(['GitHub Actions / test'])).toBe(true);
      expect(hasRelevantStatusChecks(['lint', 'typecheck'])).toBe(true);
    });

    it('returns false for only excluded checks', () => {
      expect(hasRelevantStatusChecks(['renovate/stability-days'])).toBe(false);
      expect(hasRelevantStatusChecks(['codecov/patch'])).toBe(false);
      expect(hasRelevantStatusChecks(['dependabot'])).toBe(false);
      expect(hasRelevantStatusChecks(['vercel'])).toBe(false);
      expect(hasRelevantStatusChecks(['netlify'])).toBe(false);
    });

    it('returns true when mix of excluded and relevant checks', () => {
      expect(
        hasRelevantStatusChecks(['renovate/stability-days', 'ci/test']),
      ).toBe(true);
      expect(
        hasRelevantStatusChecks(['codecov/patch', 'build', 'vercel']),
      ).toBe(true);
    });

    it('is case insensitive for exclusions', () => {
      expect(hasRelevantStatusChecks(['Renovate/something'])).toBe(false);
      expect(hasRelevantStatusChecks(['CODECOV/patch'])).toBe(false);
    });
  });
});
