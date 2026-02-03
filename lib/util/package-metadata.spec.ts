import { createUpgradeKey, serializePackageMetadata } from './package-metadata';

describe('util/package-metadata', () => {
  describe('serializePackageMetadata', () => {
    it('returns empty string for undefined', () => {
      expect(serializePackageMetadata(undefined)).toBe('');
    });

    it('returns empty string for empty object', () => {
      expect(serializePackageMetadata({})).toBe('');
    });

    it('serializes single key', () => {
      expect(
        serializePackageMetadata({ lockFile: 'rhel8/rpms.lock.yaml' }),
      ).toBe('{"lockFile":"rhel8/rpms.lock.yaml"}');
    });

    it('sorts keys deterministically', () => {
      const result1 = serializePackageMetadata({
        lockFile: 'rhel8/rpms.lock.yaml',
        component: 'base',
      });
      const result2 = serializePackageMetadata({
        component: 'base',
        lockFile: 'rhel8/rpms.lock.yaml',
      });
      expect(result1).toBe(result2);
      expect(result1).toBe(
        '{"component":"base","lockFile":"rhel8/rpms.lock.yaml"}',
      );
    });

    it('produces identical output for identical input', () => {
      const metadata = { lockFile: 'rhel9/rpms.lock.yaml', component: 'base' };
      expect(serializePackageMetadata(metadata)).toBe(
        serializePackageMetadata(metadata),
      );
    });

    it('throws error for non-string values', () => {
      expect(() => serializePackageMetadata({ key: 123 } as any)).toThrow(
        'packageMetadata value for key "key" must be a string, got number',
      );
    });

    it('throws error for null values', () => {
      expect(() => serializePackageMetadata({ key: null } as any)).toThrow(
        'packageMetadata value for key "key" must be a string, got object',
      );
    });

    it('throws error for boolean values', () => {
      expect(() => serializePackageMetadata({ key: true } as any)).toThrow(
        'packageMetadata value for key "key" must be a string, got boolean',
      );
    });
  });

  describe('createUpgradeKey', () => {
    it('returns traditional key when no metadata', () => {
      const result = createUpgradeKey(
        'package.json',
        'lodash',
        '4.17.0',
        undefined,
      );
      expect(result).toBe('package.json:lodash:4.17.0');
    });

    it('returns traditional key for empty metadata', () => {
      const result = createUpgradeKey('package.json', 'lodash', '4.17.0', {});
      expect(result).toBe('package.json:lodash:4.17.0');
    });

    it('returns extended key when metadata present', () => {
      const result = createUpgradeKey('rpms.in.yaml', 'rsync', '3.1.3-6.el8', {
        lockFile: 'rhel8/rpms.lock.yaml',
      });
      expect(result).toBe(
        'rpms.in.yaml:rsync:3.1.3-6.el8:{"lockFile":"rhel8/rpms.lock.yaml"}',
      );
    });

    it('returns different keys for same package with different metadata', () => {
      const key1 = createUpgradeKey('rpms.in.yaml', 'rsync', '3.1.3-6.el8', {
        lockFile: 'rhel8/rpms.lock.yaml',
      });
      const key2 = createUpgradeKey('rpms.in.yaml', 'rsync', '3.2.3-20.el9', {
        lockFile: 'rhel9/rpms.lock.yaml',
      });
      expect(key1).not.toBe(key2);
    });

    it('returns same key for identical metadata regardless of insertion order', () => {
      const key1 = createUpgradeKey('rpms.in.yaml', 'rsync', '3.1.3-6.el8', {
        lockFile: 'rhel8/rpms.lock.yaml',
        component: 'base',
      });
      const key2 = createUpgradeKey('rpms.in.yaml', 'rsync', '3.1.3-6.el8', {
        component: 'base',
        lockFile: 'rhel8/rpms.lock.yaml',
      });
      expect(key1).toBe(key2);
    });
  });
});
