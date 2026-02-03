import { extractAllPackageFiles } from './extract';

describe('modules/manager/rpm-lockfile/extract', () => {
  describe('extractAllPackageFiles()', () => {
    it('returns null for empty package files list', async () => {
      const result = await extractAllPackageFiles({}, []);
      expect(result).toBeNull();
    });
  });
});
