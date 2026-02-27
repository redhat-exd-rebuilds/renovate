import { join } from 'upath';
import { mockExecAll } from '../../../../test/exec-util.ts';
import { fs } from '../../../../test/util.ts';
import { GlobalConfig } from '../../../config/global.ts';
import type { RepoGlobalConfig } from '../../../config/types.ts';
import * as fsUtils from '../../../util/fs/index.ts';
import { updateArtifacts } from './artifacts.ts';

vi.mock('../../../util/fs');

const adminConfig: RepoGlobalConfig = {
  localDir: join('/tmp/github/some/repo'),
  cacheDir: join('/tmp/cache'),
};

describe('modules/manager/rpm-lockfile/artifacts', () => {
  describe('updateArtifacts()', () => {
    beforeEach(() => {
      GlobalConfig.set(adminConfig);
    });

    it('returns null if not in lockFileMaintenance', async () => {
      expect(
        await updateArtifacts({
          packageFileName: 'rpms.in.yaml',
          updatedDeps: [],
          newPackageFileContent: '',
          config: {
            updateType: 'major',
          },
        }),
      ).toBeNull();
    });

    it('returns null if the lock file is the same after update', async () => {
      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValue('Current rpms.lock.yaml');
      vi.spyOn(fsUtils, 'getSiblingFileName').mockReturnValue('rpms.lock.yaml');

      expect(
        await updateArtifacts({
          packageFileName: 'rpms.in.yaml',
          updatedDeps: [],
          newPackageFileContent: '',
          config: {
            updateType: 'lockFileMaintenance',
          },
        }),
      ).toBeNull();

      expect(execSnapshots).toMatchObject([
        { cmd: 'rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml' },
      ]);
    });

    it('returns updated rpms.lock.yaml', async () => {
      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');
      vi.spyOn(fsUtils, 'getSiblingFileName').mockReturnValue('rpms.lock.yaml');

      expect(
        await updateArtifacts({
          packageFileName: 'rpms.in.yaml',
          updatedDeps: [],
          newPackageFileContent: '',
          config: {
            updateType: 'lockFileMaintenance',
          },
        }),
      ).toEqual([
        {
          file: {
            type: 'addition',
            path: 'rpms.lock.yaml',
            contents: 'New rpms.lock.yaml',
            previousContents: 'Current rpms.lock.yaml',
          },
        },
      ]);

      expect(execSnapshots).toMatchObject([
        { cmd: 'rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml' },
      ]);
    });

    it('returns updated rpms.lock.yaml for Containerfile', async () => {
      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');
      vi.spyOn(fsUtils, 'getSiblingFileName').mockReturnValue('rpms.lock.yaml');

      expect(
        await updateArtifacts({
          packageFileName: 'rpms.in.yaml',
          updatedDeps: [],
          newPackageFileContent: '',
          config: {
            updateType: 'lockFileMaintenance',
          },
        }),
      ).toEqual([
        {
          file: {
            type: 'addition',
            path: 'rpms.lock.yaml',
            contents: 'New rpms.lock.yaml',
            previousContents: 'Current rpms.lock.yaml',
          },
        },
      ]);

      expect(execSnapshots).toMatchObject([
        { cmd: 'rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml' },
      ]);
    });
  });
});
