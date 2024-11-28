import { OsvOffline } from '@renovatebot/osv-offline';
import type { Osv } from '@renovatebot/osv-offline';
import is from '@sindresorhus/is';
import type { CvssScore } from 'vuln-vects';
import { parseCvssVector } from 'vuln-vects';
import { getManagerConfig, mergeChildConfig } from '../../../config';
import type { PackageRule, RenovateConfig } from '../../../config/types';
import { logger } from '../../../logger';
import { DockerDatasource } from '../../../modules/datasource/docker';
import type {
  PackageDependency,
  PackageFile,
} from '../../../modules/manager/types';
import { findGithubToken } from '../../../util/check-token';
import { find } from '../../../util/host-rules';
import { sanitizeMarkdown } from '../../../util/markdown';
import * as p from '../../../util/promises';
import { regEx } from '../../../util/regex';
import { titleCase } from '../../../util/string';
import type { ContainerVulnerability, SeverityDetails } from './types';

export class ContainerVulnerabilities {
  /* tslint:disable:no-unused-variable */
  private osvOffline: OsvOffline | undefined;
  private dockerDatasource: DockerDatasource;

  private constructor() {
    this.dockerDatasource = new DockerDatasource();
  }

  private async initialize(): Promise<void> {
    // hard-coded logic to use authentication for github.com based on the githubToken for api.github.com
    const token = findGithubToken(
      find({
        hostType: 'github',
        url: 'https://api.github.com/',
      }),
    );

    this.osvOffline = await OsvOffline.create(token);
  }

  static async create(): Promise<ContainerVulnerabilities> {
    const instance = new ContainerVulnerabilities();
    await instance.initialize();
    return instance;
  }

  async appendVulnerabilityPackageRules(
    config: RenovateConfig,
    packageFiles: Record<string, PackageFile[]>,
  ): Promise<void> {
    const dependencyVulnerabilities = await this.fetchDependencyVulnerabilities(
      config,
      packageFiles,
    );

    config.packageRules ??= [];

    for (const vulnerability of dependencyVulnerabilities) {
      const rule = this.vulnerabilityToPackageRules(vulnerability);
      if (is.nullOrUndefined(rule)) {
        continue;
      }
      config.packageRules.push(rule);
    }
  }

  private async fetchDependencyVulnerabilities(
    config: RenovateConfig,
    packageFiles: Record<string, PackageFile[]>,
  ): Promise<ContainerVulnerability[]> {
    const managers = Object.keys(packageFiles);

    // TODO: should we also include other docker managers: devcontainer, docker-compose ?
    if (!managers.includes('dockerfile')) {
      logger.info(
        'Dockerfile manager is not detected, skipping container vulnerability check',
      );
      return [];
    }
    const managerConfig = getManagerConfig(config, 'dockerfile');

    const queue = packageFiles['dockerfile'].map(
      (pFile) => (): Promise<ContainerVulnerability[]> =>
        this.fetchDockerfilePackageFileVulnerabilities(managerConfig, pFile),
    );

    logger.debug(
      { queueLength: queue.length },
      'fetchDependencyVulnerabilities starting',
    );
    const result = (await p.all(queue)).flat();
    logger.debug('fetchDependencyVulnerabilities finished');
    return result;
  }

  private async fetchDockerfilePackageFileVulnerabilities(
    managerConfig: RenovateConfig,
    pFile: PackageFile,
  ): Promise<ContainerVulnerability[]> {
    const { packageFile } = pFile;
    const packageFileConfig = mergeChildConfig(managerConfig, pFile);
    const { manager } = packageFileConfig;
    const queue = pFile.deps.map(
      (dep) => (): Promise<ContainerVulnerability[] | null> =>
        this.fetchDependencyVulnerability(packageFileConfig, dep),
    );
    logger.trace(
      { manager, packageFile, queueLength: queue.length },
      'fetchDockerfilePackageFileVulnerabilities starting with concurrency',
    );

    const result = (await p.all(queue)).flat();
    logger.trace(
      { packageFile },
      'fetchDockerfilePackageFileVulnerabilities finished',
    );
    return result.filter(is.truthy);
  }

  private async fetchDependencyVulnerability(
    packageFileConfig: RenovateConfig & PackageFile,
    dep: PackageDependency,
  ): Promise<ContainerVulnerability[] | null> {
    await new Promise((resolve) => setTimeout(resolve, 0));

    const depName = dep.depName ?? '';
    if (depName === '') {
      logger.warn('Dependency name is unset, skipping');
      return null;
    }
    const oldDigest = dep.currentDigest ?? '';
    const newDigest = this.getNewDigest(dep);
    if (oldDigest === '' || newDigest === '') {
      logger.info(`Image ${depName} is not specified via digest, skipping`);
      return null;
    }

    // TODO: query osv-offline here to get all vulnerabilities of a given repo
    try {
      // this is a wrong call, it will change when docker support is osv-offline is implemented
      const OSVContainerVulnerabilities =
        await this.osvOffline?.getVulnerabilities('Go', depName);

      // creating a dummy vulnerability here for testing purposes.
      // The final format will likely be a bit different since we're working with different data than other ecosystems
      // but it's OK for now.
      // We assume that OSVContainerVulnerabilities only contains vulnerabilities that affect the
      // analyzed repo. OSV query will be responsible for this filter.
      // OSVContainerVulnerabilities = [
      //   {
      //     schema_version: '1.2.3',
      //     id: 'GHSA-22cc-w7xm-rfhx',
      //     modified: '2024-06-21T19:36:07.296811Z',
      //     published: '2024-06-20T19:53:30Z',
      //     aliases: ['CVE-2019-7617', 'PYSEC-2019-178'],
      //     related: [
      //       'CGA-2ph7-wp75-g3rf',
      //       'CGA-326j-45xp-qqrg',
      //       'CGA-3727-xg6m-m6g6',
      //     ],
      //     summary: 'redis-py Race Condition vulnerability',
      //     details:
      //       'redis-py before 4.5.3, as used in ChatGPT and other products, leaves a connection open after canceling',
      //     severity: [
      //       {
      //         type: 'CVSS_V3',
      //         score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
      //       },
      //     ],
      //     affected: [
      //       {
      //         package: {
      //           ecosystem: 'docker',
      //           // We will use package name to hold docker repo for now
      //           name: 'quay.io/prometheus/node-exporter',
      //         },
      //       },
      //     ],
      //   },
      // ];

      if (
        is.nullOrUndefined(OSVContainerVulnerabilities) ||
        is.emptyArray(OSVContainerVulnerabilities)
      ) {
        logger.trace(`No vulnerabilities found in OSV database for ${depName}`);
        return null;
      }

      const oldImage = `${depName}@${oldDigest}`;
      const newImage = `${depName}@${newDigest}`;
      logger.debug({ oldImage, newImage }, 'CVE remediated images');
      const oldImageCreated = await this.getImageReleaseTime(oldImage);
      const newImageCreated = await this.getImageReleaseTime(newImage);

      logger.debug(
        { oldImageCreated, newImageCreated },
        '"created" metadata of the container images',
      );
      if (
        !(
          typeof oldImageCreated === 'string' && oldImageCreated.trim() !== ''
        ) ||
        !(typeof newImageCreated === 'string' && newImageCreated.trim() !== '')
      ) {
        logger.warn(
          `Failed to get "created" timestamp of ${oldImage} or ${newImage}`,
        );
        return null;
      }

      const filteredOsvVulnerabilities =
        this.filterOSVVulnerabilitiesBasedOnCreatedDate(
          OSVContainerVulnerabilities,
          new Date(oldImageCreated),
          new Date(newImageCreated),
        );

      const vulnerabilities: ContainerVulnerability[] = [];
      for (const osvVulnerability of filteredOsvVulnerabilities) {
        vulnerabilities.push({
          config: packageFileConfig,
          oldDigest,
          newDigest,
          depName,
          vulnerability: osvVulnerability,
          datasource: dep.datasource!,
        });
      }

      if (
        is.nullOrUndefined(vulnerabilities) ||
        is.emptyArray(vulnerabilities)
      ) {
        logger.debug(`No vulnerabilities apply for ${depName}`);
        return null;
      }

      return vulnerabilities;
    } catch (err) {
      logger.warn(
        { err },
        `Error fetching vulnerability information for ${depName}`,
      );
      return null;
    }
  }

  private getNewDigest(dependency: PackageDependency): string {
    if (!dependency.updates || dependency.updates.length === 0) {
      return '';
    }

    for (const update of dependency.updates) {
      if (update.newDigest) {
        return update.newDigest;
      }
    }

    return '';
  }

  private async getImageReleaseTime(imageRef: string): Promise<string | null> {
    const res = this.splitImageRef(imageRef);

    if (res === null) {
      logger.warn(`cannot split ${imageRef} to registry, repo, digest`);
      return null;
    }
    const [registry, repo, digest] = res;
    logger.trace({ registry, repo, digest }, 'registry repo digest');
    const configDigest = await this.dockerDatasource.getConfigDigest(
      registry,
      repo,
      digest,
    );
    if (configDigest === null) {
      logger.warn(`cannot get config digest of ${imageRef}`);
      return null;
    }

    const imageConfig = await this.dockerDatasource.getImageConfigFull(
      registry,
      repo,
      configDigest,
    );

    if (imageConfig && typeof imageConfig.body === 'string') {
      const body = JSON.parse(imageConfig.body);
      return body.created;
    } else {
      logger.warn(`cannot get image config of ${imageRef}`);
      return null;
    }
  }

  private splitImageRef(input: string): [string, string, string] | null {
    const [url, ...parts] = input.split('/');
    const rest = parts.join('/');
    const [repository, digest] = rest.split('@');

    if (
      !(typeof url === 'string' && url.trim() !== '') ||
      !(typeof repository === 'string' && repository.trim() !== '') ||
      !(typeof digest === 'string' && digest.trim() !== '')
    ) {
      logger.warn({ url, repository, digest }, 'failed to split the image url');
      return null;
    }

    return [`https://${url}`, repository, digest];
  }

  private filterOSVVulnerabilitiesBasedOnCreatedDate(
    osvVulnerabilities: Osv.Vulnerability[],
    oldImageCreated: Date,
    newImageCreated: Date,
  ): Osv.Vulnerability[] {
    const filteredOsvVulnerabilities = [];

    for (const osvVulnerability of osvVulnerabilities) {
      if (osvVulnerability.withdrawn) {
        logger.debug(`Skipping withdrawn vulnerability ${osvVulnerability.id}`);
        continue;
      }
      if (osvVulnerability.published === undefined) {
        logger.debug(
          `Vulnerability ${osvVulnerability.id} doesn't have a defined published date, skipping`,
        );
        continue;
      }
      const vulnerabilityCreated = new Date(osvVulnerability.published);

      if (
        oldImageCreated < vulnerabilityCreated &&
        vulnerabilityCreated <= newImageCreated
      ) {
        logger.debug(
          `Vulnerability ${osvVulnerability.id} matches the criteria`,
        );
        filteredOsvVulnerabilities.push(osvVulnerability);
      }
    }

    return filteredOsvVulnerabilities;
  }

  private vulnerabilityToPackageRules(
    vul: ContainerVulnerability,
  ): PackageRule | null {
    const { config, oldDigest, newDigest, depName, vulnerability, datasource } =
      vul;
    const severityDetails = this.extractSeverityDetails(vulnerability);
    const jsonataMatch = `currentDigest = '${oldDigest}' and newDigest = '${newDigest}' and depName = '${depName}'`;

    return {
      matchDatasources: [datasource],
      matchJsonata: [jsonataMatch],
      isVulnerabilityAlert: true,
      vulnerabilitySeverity: severityDetails.severityLevel,
      prBodyNotes: this.generatePrBodyNotes(vulnerability),
      force: {
        ...config.vulnerabilityAlerts,
      },
    };
  }

  // method almost completely copied from vulnerabilities.ts
  private extractSeverityDetails(
    vulnerability: Osv.Vulnerability,
  ): SeverityDetails {
    let severityLevel = 'UNKNOWN';
    let score = 'Unknown';

    const cvssVector =
      vulnerability.severity?.find((e) => e.type === 'CVSS_V3')?.score ??
      (vulnerability.severity?.[0]?.score as string);

    if (cvssVector) {
      const [baseScore, severity] = this.evaluateCvssVector(cvssVector);
      severityLevel = severity.toUpperCase();
      score = baseScore
        ? `${baseScore} / 10 (${titleCase(severityLevel)})`
        : 'Unknown';
    } else if (
      vulnerability.id.startsWith('GHSA-') &&
      vulnerability.database_specific?.severity
    ) {
      const severity = vulnerability.database_specific.severity as string;
      severityLevel = severity.toUpperCase();
    }

    return {
      cvssVector,
      score,
      severityLevel,
    };
  }

  // method almost completely copied from vulnerabilities.ts
  private evaluateCvssVector(vector: string): [string, string] {
    logger.debug({ vector }, 'this is my vector');
    try {
      const parsedCvss: CvssScore = parseCvssVector(vector);
      const severityLevel = parsedCvss.cvss3OverallSeverityText;

      return [parsedCvss.baseScore.toFixed(1), severityLevel];
    } catch {
      logger.debug(`Error processing CVSS vector ${vector}`);
    }

    return ['', ''];
  }

  // method almost completely copied from vulnerabilities.ts
  private generatePrBodyNotes(vulnerability: Osv.Vulnerability): string[] {
    let aliases = [vulnerability.id].concat(vulnerability.aliases ?? []).sort();
    aliases = aliases.map((id) => {
      if (id.startsWith('CVE-')) {
        return `[${id}](https://nvd.nist.gov/vuln/detail/${id})`;
      } else if (id.startsWith('GHSA-')) {
        return `[${id}](https://github.com/advisories/${id})`;
      } else if (id.startsWith('GO-')) {
        return `[${id}](https://pkg.go.dev/vuln/${id})`;
      } else if (id.startsWith('RUSTSEC-')) {
        return `[${id}](https://rustsec.org/advisories/${id}.html)`;
      }

      return id;
    });

    let content = '\n\n---\n\n### ';
    content += vulnerability.summary ? `${vulnerability.summary}\n` : '';
    content += `${aliases.join(' / ')}\n`;
    content += `\n<details>\n<summary>More information</summary>\n`;

    const details = vulnerability.details?.replace(
      regEx(/^#{1,4} /gm),
      '##### ',
    );
    content += `#### Details\n${details ?? 'No details.'}\n`;

    content += '#### Severity\n';
    const severityDetails = this.extractSeverityDetails(vulnerability);

    if (severityDetails.cvssVector) {
      content += `- CVSS Score: ${severityDetails.score}\n`;
      content += `- Vector String: \`${severityDetails.cvssVector}\`\n`;
    } else {
      content += `${titleCase(severityDetails.severityLevel)}\n`;
    }

    content += `\n#### References\n${
      vulnerability.references
        ?.map((ref) => {
          return `- [${ref.url}](${ref.url})`;
        })
        .join('\n') ?? 'No references.'
    }`;

    let attribution = '';
    if (vulnerability.id.startsWith('GHSA-')) {
      attribution = ` and the [GitHub Advisory Database](https://github.com/github/advisory-database) ([CC-BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md))`;
    } else if (vulnerability.id.startsWith('GO-')) {
      attribution = ` and the [Go Vulnerability Database](https://github.com/golang/vulndb) ([CC-BY 4.0](https://github.com/golang/vulndb#license))`;
    } else if (vulnerability.id.startsWith('PYSEC-')) {
      attribution = ` and the [PyPI Advisory Database](https://github.com/pypa/advisory-database) ([CC-BY 4.0](https://github.com/pypa/advisory-database/blob/main/LICENSE))`;
    } else if (vulnerability.id.startsWith('RUSTSEC-')) {
      attribution = ` and the [Rust Advisory Database](https://github.com/RustSec/advisory-db) ([CC0 1.0](https://github.com/rustsec/advisory-db/blob/main/LICENSE.txt))`;
    }
    content += `\n\nThis data is provided by [OSV](https://osv.dev/vulnerability/${vulnerability.id})${attribution}.\n`;
    content += `</details>`;

    return [sanitizeMarkdown(content)];
  }
}
