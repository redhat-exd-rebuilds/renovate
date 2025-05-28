import { TEMPORARY_ERROR } from '../../../constants/error-messages';
import { logger } from '../../../logger';
import { exec } from '../../../util/exec';
import type { ExecOptions } from '../../../util/exec/types';
import {
  deleteLocalFile,
  getSiblingFileName,
  readLocalFile,
} from '../../../util/fs';
import type { UpdateArtifact, UpdateArtifactsResult } from '../types';

export async function updateArtifacts({
  packageFileName,
  updatedDeps,
  newPackageFileContent,
  config,
}: UpdateArtifact): Promise<UpdateArtifactsResult[] | null> {
  logger.debug(`rpm.updateArtifacts(${packageFileName})`);
  const extension = packageFileName.split('.').pop();
  const inFileName = getSiblingFileName(
    packageFileName,
    `rpms.in.${extension}`,
  );

  const outputName = 'rpms.lock.tmp.yaml';

  logger.debug(`RPM lock file: ${packageFileName}`);

  const existingLockFileContent = await readLocalFile(packageFileName, 'utf8');

  logger.debug(`Updating ${packageFileName}`);

  const cmd: string[] = [];

  try {
    await deleteLocalFile(packageFileName);

    cmd.push(
      `caching-rpm-lockfile-prototype ${inFileName} --outfile ${packageFileName}`,
    );

    // Do not set cwdFile in ExecOptions, because packageFileName
    // and lockFileName already contain the (optional) subfolder.
    // Setting cwdFile would descend into that subfolder and
    // we'd have it set twice.
    const execOptions: ExecOptions = {};

    await exec(cmd, execOptions);

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
