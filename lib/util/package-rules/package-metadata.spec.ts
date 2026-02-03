import { PackageMetadataMatcher } from './package-metadata';

describe('util/package-rules/package-metadata', () => {
  const matcher = new PackageMetadataMatcher();

  describe('matches', () => {
    it('returns null when matchPackageMetadata is not set', () => {
      const result = matcher.matches(
        { packageMetadata: { lockFile: 'rhel8/rpms.lock.yaml' } },
        {},
      );
      expect(result).toBeNull();
    });

    it('returns false when dependency has no packageMetadata', () => {
      const result = matcher.matches(
        {},
        { matchPackageMetadata: { lockFile: 'rhel8/rpms.lock.yaml' } },
      );
      expect(result).toBeFalse();
    });

    it('returns false when packageMetadata is explicitly undefined', () => {
      const result = matcher.matches(
        { packageMetadata: undefined },
        { matchPackageMetadata: { lockFile: 'rhel8/rpms.lock.yaml' } },
      );
      expect(result).toBeFalse();
    });

    it('returns true when all keys match', () => {
      const result = matcher.matches(
        {
          packageMetadata: {
            lockFile: 'rhel8/rpms.lock.yaml',
            component: 'base',
          },
        },
        { matchPackageMetadata: { lockFile: 'rhel8/rpms.lock.yaml' } },
      );
      expect(result).toBeTrue();
    });

    it('returns true when all specified keys match', () => {
      const result = matcher.matches(
        {
          packageMetadata: {
            lockFile: 'rhel8/rpms.lock.yaml',
            component: 'base',
            env: 'prod',
          },
        },
        {
          matchPackageMetadata: {
            lockFile: 'rhel8/rpms.lock.yaml',
            component: 'base',
          },
        },
      );
      expect(result).toBeTrue();
    });

    it('returns false when a key does not match', () => {
      const result = matcher.matches(
        {
          packageMetadata: {
            lockFile: 'rhel9/rpms.lock.yaml',
            component: 'base',
          },
        },
        { matchPackageMetadata: { lockFile: 'rhel8/rpms.lock.yaml' } },
      );
      expect(result).toBeFalse();
    });

    it('returns false when a key is missing from dependency metadata', () => {
      const result = matcher.matches(
        { packageMetadata: { component: 'base' } },
        { matchPackageMetadata: { lockFile: 'rhel8/rpms.lock.yaml' } },
      );
      expect(result).toBeFalse();
    });

    it('returns true for exact match', () => {
      const result = matcher.matches(
        { packageMetadata: { lockFile: 'rhel8/rpms.lock.yaml' } },
        { matchPackageMetadata: { lockFile: 'rhel8/rpms.lock.yaml' } },
      );
      expect(result).toBeTrue();
    });

    it('returns null for empty matchPackageMetadata', () => {
      const result = matcher.matches(
        { packageMetadata: { lockFile: 'rhel8/rpms.lock.yaml' } },
        { matchPackageMetadata: {} },
      );
      expect(result).toBeNull();
    });
  });
});
