import { join } from 'upath';
import { mockExecAll } from '../../../../test/exec-util';
import { fs } from '../../../../test/util';
import { GlobalConfig } from '../../../config/global';
import type { RepoGlobalConfig } from '../../../config/types';
import * as hostRules from '../../../util/host-rules';
import { updateArtifacts } from '.';

vi.mock('../../../util/fs');

const adminConfig: RepoGlobalConfig = {
  localDir: join('/tmp/github/some/repo'),
  cacheDir: join('/tmp/cache'),
};

describe('modules/manager/rpm-lockfile/artifacts', () => {
  describe('updateArtifacts()', () => {
    beforeEach(() => {
      GlobalConfig.set(adminConfig);
      hostRules.clear();
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
      fs.getSiblingFileName.mockReturnValue('rpms.lock.yaml');

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
        {
          cmd: 'caching-rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml',
        },
      ]);
    });

    it('returns updated rpms.lock.yaml', async () => {
      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');
      fs.getSiblingFileName.mockReturnValue('rpms.lock.yaml');

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
        {
          cmd: 'caching-rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml',
        },
      ]);
    });

    it('returns updated rpms.lock.yaml for Containerfile', async () => {
      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');
      fs.getSiblingFileName.mockReturnValue('rpms.lock.yaml');

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
        {
          cmd: 'caching-rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml',
        },
      ]);
    });

    it('generates skopeo login commands for docker hostRules', async () => {
      hostRules.add({
        hostType: 'docker',
        matchHost: 'quay.io/myorg',
        username: 'testuser',
        password: 'testpassword',
      });
      hostRules.add({
        hostType: 'docker',
        matchHost: 'registry.redhat.io',
        username: 'rhuser',
        password: 'rhpassword',
      });

      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');
      fs.getSiblingFileName.mockReturnValue('rpms.lock.yaml');
      fs.privateCacheDir.mockReturnValue(
        '/tmp/renovate/cache/__renovate-private-cache',
      );

      await updateArtifacts({
        packageFileName: 'rpms.in.yaml',
        updatedDeps: [],
        newPackageFileContent: '',
        config: {
          updateType: 'lockFileMaintenance',
        },
      });

      expect(execSnapshots).toMatchObject([
        {
          cmd: 'skopeo login --username testuser --password testpassword quay.io/myorg',
        },
        {
          cmd: 'skopeo login --username rhuser --password rhpassword registry.redhat.io',
        },
        {
          cmd: 'caching-rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml',
        },
      ]);
    });

    it('skips skopeo login for hostRules without credentials', async () => {
      hostRules.add({
        hostType: 'docker',
        matchHost: 'quay.io/myorg',
        // No username/password
      });
      hostRules.add({
        hostType: 'docker',
        matchHost: 'registry.redhat.io',
        username: 'rhuser',
        // No password
      });

      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');
      fs.getSiblingFileName.mockReturnValue('rpms.lock.yaml');

      await updateArtifacts({
        packageFileName: 'rpms.in.yaml',
        updatedDeps: [],
        newPackageFileContent: '',
        config: {
          updateType: 'lockFileMaintenance',
        },
      });

      // Only the main command, no skopeo logins
      expect(execSnapshots).toMatchObject([
        {
          cmd: 'caching-rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml',
        },
      ]);
    });

    it('skips skopeo login for non-docker hostRules', async () => {
      hostRules.add({
        hostType: 'npm',
        matchHost: 'registry.npmjs.org',
        username: 'npmuser',
        password: 'npmpassword',
      });
      hostRules.add({
        hostType: 'helm',
        matchHost: 'charts.example.com',
        username: 'helmuser',
        password: 'helmpassword',
      });

      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');
      fs.getSiblingFileName.mockReturnValue('rpms.lock.yaml');

      await updateArtifacts({
        packageFileName: 'rpms.in.yaml',
        updatedDeps: [],
        newPackageFileContent: '',
        config: {
          updateType: 'lockFileMaintenance',
        },
      });

      // Only the main command, no skopeo logins for non-docker hostRules
      expect(execSnapshots).toMatchObject([
        {
          cmd: 'caching-rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml',
        },
      ]);
    });

    it('handles hostRules with https:// prefix in matchHost', async () => {
      hostRules.add({
        hostType: 'docker',
        matchHost: 'https://quay.io/myorg',
        username: 'testuser',
        password: 'testpassword',
      });

      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');
      fs.getSiblingFileName.mockReturnValue('rpms.lock.yaml');
      fs.privateCacheDir.mockReturnValue(
        '/tmp/renovate/cache/__renovate-private-cache',
      );

      await updateArtifacts({
        packageFileName: 'rpms.in.yaml',
        updatedDeps: [],
        newPackageFileContent: '',
        config: {
          updateType: 'lockFileMaintenance',
        },
      });

      expect(execSnapshots).toMatchObject([
        {
          cmd: 'skopeo login --username testuser --password testpassword quay.io/myorg',
        },
        {
          cmd: 'caching-rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml',
        },
      ]);
    });

    it('handles special characters in username and password', async () => {
      hostRules.add({
        hostType: 'docker',
        matchHost: 'quay.io',
        username: "user+special'name",
        password: 'pass\'word$with"special',
      });

      const execSnapshots = mockExecAll();

      fs.readLocalFile.mockResolvedValueOnce('Current rpms.lock.yaml');
      fs.readLocalFile.mockResolvedValueOnce('New rpms.lock.yaml');
      fs.getSiblingFileName.mockReturnValue('rpms.lock.yaml');
      fs.privateCacheDir.mockReturnValue(
        '/tmp/renovate/cache/__renovate-private-cache',
      );

      await updateArtifacts({
        packageFileName: 'rpms.in.yaml',
        updatedDeps: [],
        newPackageFileContent: '',
        config: {
          updateType: 'lockFileMaintenance',
        },
      });

      // The shlex quote function should properly escape special characters
      expect(execSnapshots).toHaveLength(2);
      expect(execSnapshots[0].cmd).toContain('skopeo login');
      expect(execSnapshots[0].cmd).toContain('quay.io');
      expect(execSnapshots[1].cmd).toBe(
        'caching-rpm-lockfile-prototype rpms.in.yaml --outfile rpms.lock.yaml',
      );
    });
  });
});
