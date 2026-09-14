import { extractPackageFile } from './extract.ts';

describe('modules/manager/rpm-lockfile/extract', () => {
  describe('extractPackageFile()', () => {
    it('always returns empty yaml', async () => {
      await expect(extractPackageFile('', 'rpms.in.yaml')).resolves.toEqual({
        deps: [],
        lockFiles: ['rpms.lock.yaml'],
      });
    });

    it('always returns empty yml', async () => {
      await expect(extractPackageFile('', 'rpms.in.yml')).resolves.toEqual({
        deps: [],
        lockFiles: ['rpms.lock.yml'],
      });
    });
  });
});
