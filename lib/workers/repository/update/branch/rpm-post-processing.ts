import is from '@sindresorhus/is';
import { logger } from '../../../../logger';
import { RedHatRPMLockfile } from '../../../../modules/manager/rpm/schema';
import type {
  PackageDependency,
  UpdateArtifactsResult,
} from '../../../../modules/manager/types';
import * as p from '../../../../util/promises';
import { parseSingleYaml } from '../../../../util/yaml';
import type { BranchConfig, BranchUpgradeConfig } from '../../../types';
import { RpmVulnerabilities } from '../../process/rpm-vulnerabilities';
import type {
  DependencyVulnerabilities,
  Vulnerability,
} from '../../process/types';

export async function postProcessRPMs(
  result: UpdateArtifactsResult[] | null,
  config: BranchConfig,
): Promise<UpdateArtifactsResult[] | null> {
  logger.debug('RPM lockfile maintenance post-processing');
  const upgrade = getUpgrade(result, config);
  if (result === null) {
    logger.debug('No RPM updates have been proposed');
    return null;
  }

  const packages = parseLockfilePackages(result);
  if (packages.length === 0) {
    logger.warn('No RPM packages could be parsed');
    return null;
  }

  // skipping the rest of the logic if it's not a vulnerability alert
  if (!config.isVulnerabilityAlert) {
    return result;
  }

  const rpmVulnerabilities = await RpmVulnerabilities.create();
  const vulnerabilities = await createVulnerabilities(
    packages,
    rpmVulnerabilities,
  );
  logger.debug(`Found ${vulnerabilities.length} vulnerabilities`);

  if (vulnerabilities.length === 0) {
    logger.debug('No RPM vulnerabilities found');
    return null;
  }

  applyVulnerabilityPRNotes(
    vulnerabilities,
    config,
    upgrade,
    rpmVulnerabilities,
  );

  return result;
}

export function getUpgrade(
  result: UpdateArtifactsResult[] | null,
  config: BranchConfig,
): BranchUpgradeConfig {
  if (result === null) {
    logger.warn('No result provided, returning first upgrade');
    return config.upgrades[0];
  }
  const matchingUpgrades: BranchUpgradeConfig[] = [];
  for (const res of result) {
    if (res?.file?.type === 'addition') {
      const path = res.file.path;

      for (const upgrade of config.upgrades) {
        if (upgrade.lockFiles?.includes(path)) {
          matchingUpgrades.push(upgrade);
        }
      }
    }
  }

  const uniqueUpgrades = Array.from(
    new Map(
      matchingUpgrades.map((upgrade) => [upgrade.packageFile, upgrade]),
    ).values(),
  );
  if (uniqueUpgrades.length > 1) {
    logger.warn(
      `Found ${uniqueUpgrades.length} matching upgrades, returning first one`,
    );
    return uniqueUpgrades[0];
  }
  if (uniqueUpgrades.length === 0) {
    logger.warn('No matching upgrades found, returning first upgrade');
    return config.upgrades[0];
  }

  return uniqueUpgrades[0];
}

export function parseLockfilePackages(
  results: UpdateArtifactsResult[],
): PackageDependency[] {
  const oldPackages = new Map<string, PackageDependency>();
  const newPackages = new Map<string, PackageDependency>();
  for (const result of results) {
    if (result?.file?.type !== 'addition') {
      continue;
    }
    const oldLockFileContent = result.file.previousContents;
    const newLockFileContent = result.file.contents;

    if (
      typeof oldLockFileContent === 'string' &&
      typeof newLockFileContent === 'string'
    ) {
      try {
        const oldLockFile = parseSingleYaml(oldLockFileContent, {
          customSchema: RedHatRPMLockfile,
        });
        const newLockFile = parseSingleYaml(newLockFileContent, {
          customSchema: RedHatRPMLockfile,
        });
        for (const arch of oldLockFile.arches) {
          for (const dependency of arch.packages) {
            const key = `${arch.arch}-${dependency.name}`;
            oldPackages.set(key, {
              depName: dependency.name,
              packageName: dependency.name,
              currentValue: dependency.evr,
              currentVersion: dependency.evr,
              versioning: 'rpm',
              datasource: 'rpm-lockfile',
            });
          }
        }

        for (const arch of newLockFile.arches) {
          for (const dependency of arch.packages) {
            const key = `${arch.arch}-${dependency.name}`;
            newPackages.set(key, {
              depName: dependency.name,
              packageName: dependency.name,
              currentValue: dependency.evr,
              currentVersion: dependency.evr,
              versioning: 'rpm',
              datasource: 'rpm-lockfile',
            });
          }
        }
        // Add new versions from the new lockfile
        for (const [key, oldPackage] of oldPackages.entries()) {
          const newPackage = newPackages.get(key);
          if (newPackage) {
            oldPackage.newValue = newPackage.currentVersion;
            oldPackage.newVersion = newPackage.currentVersion;
          }
        }
      } catch {
        logger.debug(`Error parsing lockfile: ${result.file.path}`);
      }
    }
  }
  // include only packages where the version has changed
  const updatedPackages = Array.from(oldPackages.values()).filter(
    (pkg) => pkg.newVersion && pkg.currentVersion !== pkg.newVersion,
  );

  return updatedPackages;
}

export async function createVulnerabilities(
  packages: PackageDependency[],
  rpmVulns: RpmVulnerabilities,
): Promise<Vulnerability[]> {
  const dummyPackageFileConfig = {
    packageFile: 'dummy.spec',
    deps: [],
    manager: 'rpm-lockfile',
    datasource: 'rpm-lockfile',
  };

  const queue = packages.map(
    (pkg) => (): Promise<DependencyVulnerabilities | null> =>
      rpmVulns.fetchDependencyVulnerability(dummyPackageFileConfig, pkg, true),
  );

  const results = await p.all(queue);
  const filteredResults = results.filter(is.truthy);
  const allVulnerabilities = filteredResults.flatMap(
    (result) => result.vulnerabilities,
  );
  const uniqueVulnerabilities = Array.from(
    new Map(
      allVulnerabilities.map((vuln) => [vuln.vulnerability.id, vuln]),
    ).values(),
  );

  return uniqueVulnerabilities;
}

export function applyVulnerabilityPRNotes(
  vulnerabilities: Vulnerability[],
  config: BranchConfig,
  upgrade: BranchUpgradeConfig,
  rpmVulns: RpmVulnerabilities,
): void {
  // this function is called multiple times for each lockfile in a PR, so we don't know
  // the final number of vulnerabilities in each isolated run. This can create a side
  // effect where first few vulnerabilities will have a description but the rest won't.

  const truncated =
    vulnerabilities.length + (config.prBodyNotes?.length ?? 0) > 10;
  const prBodyNotesList: string[] = [];

  for (const vulnerability of vulnerabilities) {
    const prBodyNotes = rpmVulns.generatePrBodyNotes(
      vulnerability.vulnerability,
      vulnerability.affected,
      truncated,
      false,
    );

    prBodyNotesList.push(...prBodyNotes);
  }

  config.prBodyNotes = [...(config.prBodyNotes ?? []), ...prBodyNotesList];
  upgrade.prBodyNotes = [...(upgrade.prBodyNotes ?? []), ...prBodyNotesList];
}
