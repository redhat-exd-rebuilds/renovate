import { logger } from '../../../logger';
import { getSiblingFileName } from '../../../util/fs';
import type { PackageFileContent } from '../types';
import { parseSingleYaml } from '../../../util/yaml';
import { readLocalFile, localPathExists } from '../../../util/fs';
import { RedHatRPMLockfile } from './schema';
import type { RedHatRPMLockfileDefinition } from './schema';
import type { PackageDependency } from '../types';
import { exec } from '../../../util/exec';
import type { ExecOptions } from '../../../util/exec/types';

async function getUpdatedLockfile() {
  const cmd: string[] = [];
  const packageFileName = "rpms.in.yaml";
  const outputName = "rpms.lock.tmp.yaml";

  if (await localPathExists(outputName)) {
    // Only generate the temporary lockfile once
    return;
  }

  cmd.push(`rpm-lockfile-prototype ${packageFileName} --outfile ${outputName}`);

  const execOptions: ExecOptions = {
    cwdFile: packageFileName,
  }

  try {
    await exec(cmd, execOptions);
  } catch (err) {
    logger.debug({ err }, 'Unable to refresh RPM lockfile for datasource');
  }
}

export async function extractPackageFile(
  content: string,
  packageFile: string,
): Promise<PackageFileContent | null> {
  logger.debug(`rpm.extractPackageFile(${packageFile})`);

  const extension = packageFile.split('.').pop();
  const lockFile = getSiblingFileName(packageFile, `rpms.lock.${extension}`);

  logger.debug(`RPM lock file: ${lockFile}`);

  let lockFileContent = await readLocalFile(lockFile, 'utf8');
  let deps: PackageDependency[] = [];

  if (lockFileContent !== null) {
    try {
      let lockFile: RedHatRPMLockfileDefinition = parseSingleYaml(lockFileContent, { customSchema: RedHatRPMLockfile });

      logger.debug(`Lock file version: ${lockFile.lockfileVersion}`);

      for (const arch of lockFile.arches) {
        let arch_deps: PackageDependency[] = arch.packages.map((dependency) => {
          return {
            depName: dependency.name,
            packageName: dependency.name,
            currentValue: dependency.evr,
            currentVersion: dependency.evr,
            versioning: "rpm",
            datasource: "rpm-lockfile",
          }
        });

        for (const dep of arch_deps) {
          if (deps.findIndex((d) => d.depName == dep.depName) == -1) {
            deps.push(dep);
          }
        }
      }
    } catch (e) {
      logger.debug({ lockFile }, `Error parsing ${lockFile}: ${e}`);
    }
  }

  // Generate a new temporary lockfile, so that RPMLockfileDatasource
  // can pick it up later to avoid performance problems of generating
  // the lockfile multiple times.
  await getUpdatedLockfile();

  return {
    lockFiles: [lockFile],
    deps: deps,
  };
}
