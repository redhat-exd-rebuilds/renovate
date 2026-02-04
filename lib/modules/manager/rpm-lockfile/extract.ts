import { logger } from '../../../logger/index.ts';
import { getSiblingFileName } from '../../../util/fs/index.ts';
import type { PackageFileContent } from '../types.ts';

export async function extractPackageFile(
  content: string,
  packageFile: string,
): Promise<PackageFileContent | null> {
  logger.debug(`rpm.extractPackageFile(${packageFile})`);

  const extension = packageFile.split('.').pop();
  const lockFile = getSiblingFileName(packageFile, `rpms.lock.${extension}`);

  await Promise.resolve();

  logger.debug(`RPM lock file: ${lockFile}`);

  return {
    lockFiles: [lockFile],
    deps: [],
  };
}
