import { Fixtures } from '../../../../test/fixtures';
import { fs } from '../../../../test/util';
import { extractPackageFile } from '.';

jest.mock('../../../util/fs');

const lockFile0yaml = Fixtures.get('rpms.lock.0.yaml');

describe('modules/manager/rpm/extract', () => {
  describe('extractPackageFile()', () => {
    it('returns empty dependencies for empty yaml', async () => {
      expect(await extractPackageFile('', 'rpms.in.yaml')).toEqual({
        deps: [],
        lockFiles: ['rpms.lock.yaml'],
      });
    });

    it('extracts multiple dependencies', async () => {
      fs.localPathExists.mockResolvedValueOnce(true);
      fs.readLocalFile.mockResolvedValueOnce(lockFile0yaml);

      const res = await extractPackageFile('', 'rpms.in.yaml');
      expect(res?.deps).toHaveLength(24);
      expect(res).toMatchSnapshot({
        deps: [
          {
            depName: 'cargo',
            packageName: 'cargo',
            currentValue: '1.75.0-1.el9',
            currentVersion: '1.75.0-1.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'cpp',
            packageName: 'cpp',
            currentValue: '11.4.1-3.el9',
            currentVersion: '11.4.1-3.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'gcc',
            packageName: 'gcc',
            currentValue: '11.4.1-3.el9',
            currentVersion: '11.4.1-3.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'glibc-devel',
            packageName: 'glibc-devel',
            currentValue: '2.34-100.el9_4.4',
            currentVersion: '2.34-100.el9_4.4',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'glibc-headers',
            packageName: 'glibc-headers',
            currentValue: '2.34-100.el9_4.4',
            currentVersion: '2.34-100.el9_4.4',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'kernel-headers',
            packageName: 'kernel-headers',
            currentValue: '5.14.0-427.42.1.el9_4',
            currentVersion: '5.14.0-427.42.1.el9_4',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'libmpc',
            packageName: 'libmpc',
            currentValue: '1.2.1-4.el9',
            currentVersion: '1.2.1-4.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'libxcrypt-devel',
            packageName: 'libxcrypt-devel',
            currentValue: '4.4.18-3.el9',
            currentVersion: '4.4.18-3.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'llvm-libs',
            packageName: 'llvm-libs',
            currentValue: '17.0.6-5.el9',
            currentVersion: '17.0.6-5.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'rust',
            packageName: 'rust',
            currentValue: '1.75.0-1.el9',
            currentVersion: '1.75.0-1.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'rust-std-static',
            packageName: 'rust-std-static',
            currentValue: '1.75.0-1.el9',
            currentVersion: '1.75.0-1.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'binutils',
            packageName: 'binutils',
            currentValue: '2.35.2-43.el9',
            currentVersion: '2.35.2-43.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'binutils-gold',
            packageName: 'binutils-gold',
            currentValue: '2.35.2-43.el9',
            currentVersion: '2.35.2-43.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'elfutils-debuginfod-client',
            packageName: 'elfutils-debuginfod-client',
            currentValue: '0.190-2.el9',
            currentVersion: '0.190-2.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'glibc',
            packageName: 'glibc',
            currentValue: '2.34-100.el9_4.4',
            currentVersion: '2.34-100.el9_4.4',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'glibc-common',
            packageName: 'glibc-common',
            currentValue: '2.34-100.el9_4.4',
            currentVersion: '2.34-100.el9_4.4',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'glibc-langpack-en',
            packageName: 'glibc-langpack-en',
            currentValue: '2.34-100.el9_4.4',
            currentVersion: '2.34-100.el9_4.4',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'glibc-minimal-langpack',
            packageName: 'glibc-minimal-langpack',
            currentValue: '2.34-100.el9_4.4',
            currentVersion: '2.34-100.el9_4.4',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'libedit',
            packageName: 'libedit',
            currentValue: '3.1-38.20210216cvs.el9',
            currentVersion: '3.1-38.20210216cvs.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'libpkgconf',
            packageName: 'libpkgconf',
            currentValue: '1.7.3-10.el9',
            currentVersion: '1.7.3-10.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'make',
            packageName: 'make',
            currentValue: '1:4.3-8.el9',
            currentVersion: '1:4.3-8.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'pkgconf',
            packageName: 'pkgconf',
            currentValue: '1.7.3-10.el9',
            currentVersion: '1.7.3-10.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'pkgconf-m4',
            packageName: 'pkgconf-m4',
            currentValue: '1.7.3-10.el9',
            currentVersion: '1.7.3-10.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
          {
            depName: 'pkgconf-pkg-config',
            packageName: 'pkgconf-pkg-config',
            currentValue: '1.7.3-10.el9',
            currentVersion: '1.7.3-10.el9',
            datasource: 'rpm-lockfile',
            versioning: 'rpm',
          },
        ],
      });
    });
  });
});
