import type { Osv, OsvOffline } from '@renovatebot/osv-offline';
import { mockFn } from 'jest-mock-extended';
import type { RenovateConfig } from '../../../../test/util';
import { logger } from '../../../../test/util';
import { getConfig } from '../../../config/defaults';
import { DockerDatasource } from '../../../modules/datasource/docker';
import type { PackageFile } from '../../../modules/manager/types';
import { ContainerVulnerabilities } from './container-vulnerabilities';

const getVulnerabilitiesMock =
  mockFn<typeof OsvOffline.prototype.getVulnerabilities>();
const createMock = jest.fn();

jest.mock('@renovatebot/osv-offline', () => {
  return {
    __esModule: true,
    OsvOffline: class {
      static create() {
        return createMock();
      }
    },
  };
});

jest.spyOn(DockerDatasource.prototype, 'getConfigDigest');
jest.spyOn(DockerDatasource.prototype, 'getImageConfigFull');

describe('workers/repository/process/container-vulnerabilities', () => {
  describe('create()', () => {
    it('works', async () => {
      await expect(ContainerVulnerabilities.create()).resolves.not.toThrow();
    });

    it('throws when osv-offline error', async () => {
      createMock.mockRejectedValue(new Error());

      await expect(ContainerVulnerabilities.create()).rejects.toThrow();
    });
  });

  describe('appendVulnerabilityPackageRules()', () => {
    let config: RenovateConfig;
    let vulnerabilities: ContainerVulnerabilities;
    const testVulnerability: Osv.Vulnerability = {
      schema_version: '1.2.3',
      id: 'GHSA-22cc-w7xm-rfhx',
      modified: '2024-06-21T19:36:07.296811Z',
      published: '2024-06-20T19:53:30Z',
      aliases: ['CVE-2019-7617', 'PYSEC-2019-178'],
      related: [
        'CGA-2ph7-wp75-g3rf',
        'CGA-326j-45xp-qqrg',
        'CGA-3727-xg6m-m6g6',
      ],
      summary: 'redis-py Race Condition vulnerability',
      details:
        'redis-py before 4.5.3, as used in ChatGPT and other products, leaves a connection open after canceling',
      severity: [
        {
          type: 'CVSS_V3',
          score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        },
      ],
      affected: [
        {
          package: {
            ecosystem: 'docker',
            name: 'quay.io/prometheus/node-exporter',
          },
        },
      ],
    };

    beforeAll(async () => {
      createMock.mockResolvedValue({
        getVulnerabilities: getVulnerabilitiesMock,
      });
      vulnerabilities = await ContainerVulnerabilities.create();
    });

    beforeEach(() => {
      config = getConfig();
      config.packageRules = [];
    });

    it('non-dockerfile manager', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        nvm: [
          {
            deps: [{ depName: 'node', datasource: 'pypi' }],
            packageFile: 'some-file',
          },
        ],
      };

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );
      expect(logger.logger.info).toHaveBeenCalledWith(
        'Dependency node has a non-docker datasource, skipping',
      );
    });

    it('dependency name is unset', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [{ depName: '', datasource: 'docker' }],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([]);

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );
      expect(logger.logger.warn).toHaveBeenCalledWith(
        'Dependency name is unset, skipping',
      );
    });

    it('images not specified via digest', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([]);

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );
      expect(logger.logger.info).toHaveBeenCalledWith(
        'Image quay.io/test/repo is not specified via digest, skipping',
      );
    });

    it('no vulnerabilities found in osv database', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([]);

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );
      expect(logger.logger.trace).toHaveBeenCalledWith(
        'No vulnerabilities found in OSV database for quay.io/test/repo',
      );
    });

    it('failed to get image timestamp', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([testVulnerability]);

      const mockedGetConfigDigest = DockerDatasource.prototype
        .getConfigDigest as jest.Mock;
      mockedGetConfigDigest.mockResolvedValueOnce('a1b2c3');
      mockedGetConfigDigest.mockResolvedValueOnce('d1e2f3');
      const mockedGetImageConfigFull = DockerDatasource.prototype
        .getImageConfigFull as jest.Mock;
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-24T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '' }),
        headers: { 'Content-Type': 'application/json' },
      });

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );

      expect(logger.logger.warn).toHaveBeenCalledWith(
        'Failed to get "created" timestamp of quay.io/test/repo@sha256:abcd or quay.io/test/repo@sha256:defa',
      );
    });

    it('malformed image reference', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'malformed-image',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([testVulnerability]);

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );
      expect(logger.logger.warn).toHaveBeenCalledWith(
        'cannot split malformed-image@sha256:abcd to registry, repo, digest',
      );
    });

    it('cannot get config digest', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };

      getVulnerabilitiesMock.mockResolvedValueOnce([testVulnerability]);

      const mockedGetConfigDigest = DockerDatasource.prototype
        .getConfigDigest as jest.Mock;
      mockedGetConfigDigest.mockResolvedValueOnce('a1b2c3');
      mockedGetConfigDigest.mockResolvedValueOnce(null);
      const mockedGetImageConfigFull = DockerDatasource.prototype
        .getImageConfigFull as jest.Mock;
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-24T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );

      expect(logger.logger.warn).toHaveBeenCalledWith(
        'cannot get config digest of quay.io/test/repo@sha256:defa',
      );
      expect(logger.logger.warn).toHaveBeenCalledWith(
        'Failed to get "created" timestamp of quay.io/test/repo@sha256:abcd or quay.io/test/repo@sha256:defa',
      );
    });

    it('cannot get image config', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };

      getVulnerabilitiesMock.mockResolvedValueOnce([testVulnerability]);
      const mockedGetConfigDigest = DockerDatasource.prototype
        .getConfigDigest as jest.Mock;
      mockedGetConfigDigest.mockResolvedValueOnce('a1b2c3');
      mockedGetConfigDigest.mockResolvedValueOnce('d1e2f3');
      const mockedGetImageConfigFull = DockerDatasource.prototype
        .getImageConfigFull as jest.Mock;
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-24T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });
      mockedGetImageConfigFull.mockResolvedValueOnce(null);

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );

      expect(logger.logger.warn).toHaveBeenCalledWith(
        'cannot get image config of quay.io/test/repo@sha256:defa',
      );
      expect(logger.logger.warn).toHaveBeenCalledWith(
        'Failed to get "created" timestamp of quay.io/test/repo@sha256:abcd or quay.io/test/repo@sha256:defa',
      );
    });

    it('no vulnerabilities apply', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([testVulnerability]);

      const mockedGetConfigDigest = DockerDatasource.prototype
        .getConfigDigest as jest.Mock;
      mockedGetConfigDigest.mockResolvedValueOnce('a1b2c3');
      mockedGetConfigDigest.mockResolvedValueOnce('d1e2f3');
      const mockedGetImageConfigFull = DockerDatasource.prototype
        .getImageConfigFull as jest.Mock;
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-23T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-24T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );

      expect(logger.logger.debug).toHaveBeenCalledWith(
        'No vulnerabilities apply for quay.io/test/repo',
      );
    });

    it('withdrawn vulnerability', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([
        {
          ...testVulnerability,
          withdrawn: '2024-10-29T18:17:00Z',
        },
      ]);

      const mockedGetConfigDigest = DockerDatasource.prototype
        .getConfigDigest as jest.Mock;
      mockedGetConfigDigest.mockResolvedValueOnce('a1b2c3');
      mockedGetConfigDigest.mockResolvedValueOnce('d1e2f3');
      const mockedGetImageConfigFull = DockerDatasource.prototype
        .getImageConfigFull as jest.Mock;
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2023-11-23T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-24T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );

      expect(logger.logger.debug).toHaveBeenCalledWith(
        'Skipping withdrawn vulnerability GHSA-22cc-w7xm-rfhx',
      );
    });

    it('vulnerability no published date', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      const { published, ...rest } = testVulnerability;
      getVulnerabilitiesMock.mockResolvedValueOnce([rest]);

      const mockedGetConfigDigest = DockerDatasource.prototype
        .getConfigDigest as jest.Mock;
      mockedGetConfigDigest.mockResolvedValueOnce('a1b2c3');
      mockedGetConfigDigest.mockResolvedValueOnce('d1e2f3');
      const mockedGetImageConfigFull = DockerDatasource.prototype
        .getImageConfigFull as jest.Mock;
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2023-11-23T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-24T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );

      expect(logger.logger.debug).toHaveBeenCalledWith(
        "Vulnerability GHSA-22cc-w7xm-rfhx doesn't have a defined published date, skipping",
      );
    });

    it('vulnerability matches criteria', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([testVulnerability]);

      const mockedGetConfigDigest = DockerDatasource.prototype
        .getConfigDigest as jest.Mock;
      mockedGetConfigDigest.mockResolvedValueOnce('a1b2c3');
      mockedGetConfigDigest.mockResolvedValueOnce('d1e2f3');
      const mockedGetImageConfigFull = DockerDatasource.prototype
        .getImageConfigFull as jest.Mock;
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2023-11-23T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-24T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );

      expect(logger.logger.debug).toHaveBeenCalledWith(
        'Vulnerability GHSA-22cc-w7xm-rfhx matches the criteria',
      );
    });

    it('exception while fetching vulnerabilities', async () => {
      const err = new Error('unknown');
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockRejectedValueOnce(err);

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );
      expect(logger.logger.warn).toHaveBeenCalledWith(
        { err },
        'Error fetching vulnerability information for quay.io/test/repo',
      );
    });

    it('check created package rule', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([testVulnerability]);

      const mockedGetConfigDigest = DockerDatasource.prototype
        .getConfigDigest as jest.Mock;
      mockedGetConfigDigest.mockResolvedValueOnce('a1b2c3');
      mockedGetConfigDigest.mockResolvedValueOnce('d1e2f3');
      const mockedGetImageConfigFull = DockerDatasource.prototype
        .getImageConfigFull as jest.Mock;
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2023-11-23T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-24T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );

      expect(config.packageRules).toHaveLength(1);
      expect(config.packageRules).toMatchObject([
        {
          matchDatasources: ['docker'],
          matchJsonata: [
            "currentDigest = 'sha256:abcd' and newDigest = 'sha256:defa' and depName = 'quay.io/test/repo'",
          ],
          isVulnerabilityAlert: true,
          vulnerabilitySeverity: 'HIGH',
          prBodyNotes: [
            '\n' +
              '\n' +
              '---\n' +
              '\n' +
              '### redis-py Race Condition vulnerability\n' +
              '[CVE-2019-7617](https://nvd.nist.gov/vuln/detail/CVE-2019-7617) / [GHSA-22cc-w7xm-rfhx](https://github.com/advisories/GHSA-22cc-w7xm-rfhx) / PYSEC-2019-178\n' +
              '\n' +
              '<details>\n' +
              '<summary>More information</summary>\n' +
              '\n' +
              '#### Details\n' +
              'redis-py before 4.5.3, as used in ChatGPT and other products, leaves a connection open after canceling\n' +
              '\n' +
              '#### Severity\n' +
              '- CVSS Score: 8.1 / 10 (High)\n' +
              '- Vector String: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`\n' +
              '\n' +
              '#### References\n' +
              'No references.\n' +
              '\n' +
              'This data is provided by [OSV](https://osv.dev/vulnerability/GHSA-22cc-w7xm-rfhx) and the [GitHub Advisory Database](https://github.com/github/advisory-database) ([CC-BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md)).\n' +
              '</details>',
          ],
        },
      ]);
    });

    it('creates multiple package rules for vulnerabilities', async () => {
      const packageFiles: Record<string, PackageFile[]> = {
        dockerfile: [
          {
            deps: [
              {
                depName: 'quay.io/test/repo',
                datasource: 'docker',
                currentDigest: 'sha256:abcd',
                updates: [{ newDigest: 'sha256:defa' }],
              },
            ],
            packageFile: 'some-file',
          },
        ],
      };
      getVulnerabilitiesMock.mockResolvedValueOnce([
        testVulnerability,
        {
          ...testVulnerability,
          id: 'GHSA-abcd',
          summary: 'New vulnerability',
        },
      ]);

      const mockedGetConfigDigest = DockerDatasource.prototype
        .getConfigDigest as jest.Mock;
      mockedGetConfigDigest.mockResolvedValueOnce('a1b2c3');
      mockedGetConfigDigest.mockResolvedValueOnce('d1e2f3');
      const mockedGetImageConfigFull = DockerDatasource.prototype
        .getImageConfigFull as jest.Mock;
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2023-11-23T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });
      mockedGetImageConfigFull.mockResolvedValueOnce({
        statusCode: 200,
        body: JSON.stringify({ created: '2024-11-24T18:45:30.123Z' }),
        headers: { 'Content-Type': 'application/json' },
      });

      await vulnerabilities.appendVulnerabilityPackageRules(
        config,
        packageFiles,
      );

      expect(config.packageRules).toHaveLength(2);
    });
  });
});
