import { TEMPORARY_ERROR } from '../../../constants/error-messages';
import { logger } from '../../../logger';
import { deleteLocalFile, readLocalFile } from '../../../util/fs';
import type { UpdateArtifact, UpdateArtifactsResult } from '../types';

export async function updateArtifacts({
  packageFileName,
  updatedDeps,
  newPackageFileContent,
  config,
}: UpdateArtifact): Promise<UpdateArtifactsResult[] | null> {
  logger.debug(`rpm.updateArtifacts(${packageFileName})`);
  const outputName = 'rpms.lock.tmp.yaml';

  logger.debug(`RPM lock file: ${packageFileName}`);

  const existingLockFileContent = await readLocalFile(packageFileName, 'utf8');

  logger.debug(`Updating ${packageFileName}`);

  try {
    await deleteLocalFile(packageFileName);
    const newLockFileContent = await readLocalFile(outputName, 'utf8');

    if (existingLockFileContent === newLockFileContent) {
      logger.debug(`${packageFileName} is unchanged`);
      return null;
    }

    logger.debug(`Returning updated ${packageFileName}`);

    return [
      {
        file: {
          type: 'addition',
          path: packageFileName,
          contents: newLockFileContent,
        },
      },
    ];
  } catch (err) {
    if (err.message === TEMPORARY_ERROR) {
      throw err;
    }
    logger.debug({ err }, `Failed to update ${packageFileName} file`);
    return [
      {
        artifactError: {
          fileName: packageFileName,
          stderr: `${String(err.stdout)}\n${String(err.stderr)}`,
        },
      },
    ];
  }
}
