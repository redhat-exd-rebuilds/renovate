import { join } from 'upath';
import { mockExecAll } from '../../../../test/exec-util';
import { fs } from '../../../../test/util';
import { GlobalConfig } from '../../../config/global';
import type { RepoGlobalConfig } from '../../../config/types';
import { updateArtifacts } from '.';

jest.mock('../../../util/fs');

const adminConfig: RepoGlobalConfig = {
  localDir: join('/tmp/github/some/repo'),
  cacheDir: join('/tmp/cache'),
};

describe('modules/manager/rpm/artifacts', () => {
  describe('updateArtifacts()', () => {
    beforeEach(() => {
      GlobalConfig.set(adminConfig);
    });

    it('returns null if the lock file is the same after update', async () => {
      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValue('Current rpms.lock.yaml');

      expect(
        await updateArtifacts({
          packageFileName: 'rpms.lock.yaml',
          updatedDeps: [],
          newPackageFileContent: '',
          config: {
            updateType: 'lockFileMaintenance',
          },
        }),
      ).toBeNull();

      expect(execSnapshots).toMatchObject([]);
    });

    it('returns updated rpms.lock.yaml', async () => {
      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');

      expect(
        await updateArtifacts({
          packageFileName: 'rpms.lock.yaml',
          updatedDeps: [],
          newPackageFileContent: '',
          config: {},
        }),
      ).toEqual([
        {
          file: {
            type: 'addition',
            path: 'rpms.lock.yaml',
            contents: 'New rpms.lock.yaml',
          },
        },
      ]);

      expect(execSnapshots).toMatchObject([]);
    });

    it('returns updated rpms.lock.yaml for Containerfile', async () => {
      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');

      expect(
        await updateArtifacts({
          packageFileName: 'rpms.lock.yaml',
          updatedDeps: [],
          newPackageFileContent: '',
          config: {},
        }),
      ).toEqual([
        {
          file: {
            type: 'addition',
            path: 'rpms.lock.yaml',
            contents: 'New rpms.lock.yaml',
          },
        },
      ]);

      expect(execSnapshots).toMatchObject([]);
    });
  });
});
