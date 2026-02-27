import { TEMPORARY_ERROR } from '../../../constants/error-messages.ts';
import { logger } from '../../../logger/index.ts';
import { exec } from '../../../util/exec/index.ts';
import type { ExecOptions } from '../../../util/exec/types.ts';
import {
  deleteLocalFile,
  getSiblingFileName,
  readLocalFile,
} from '../../../util/fs/index.ts';
import type { UpdateArtifact, UpdateArtifactsResult } from '../types.ts';

export async function updateArtifacts({
  packageFileName,
  updatedDeps,
  newPackageFileContent,
  config,
}: UpdateArtifact): Promise<UpdateArtifactsResult[] | null> {
  logger.debug(`rpm.updateArtifacts(${packageFileName})`);
  const isLockFileMaintenance = config.updateType === 'lockFileMaintenance';

  if (!isLockFileMaintenance) {
    logger.debug('Must be in lockFileMaintenance for rpm manager');
    return null;
  }

  const extension = packageFileName.split('.').pop();
  const lockFileName = getSiblingFileName(
    packageFileName,
    `rpms.lock.${extension}`,
  );

  logger.debug(`RPM lock file: ${lockFileName}`);

  const existingLockFileContent = await readLocalFile(lockFileName, 'utf8');

  logger.debug(`Updating ${lockFileName}`);

  const cmd: string[] = [];

  try {
    await deleteLocalFile(lockFileName);

    cmd.push(
      `rpm-lockfile-prototype ${packageFileName} --outfile ${lockFileName}`,
    );

    // Do not set cwdFile in ExecOptions, because packageFileName
    // and lockFileName already contain the (optional) subfolder.
    // Setting cwdFile would descend into that subfolder and
    // we'd have it set twice.
    const execOptions: ExecOptions = {
      extraEnv: {
        DNF_VAR_SSL_CLIENT_KEY: process.env.DNF_VAR_SSL_CLIENT_KEY,
        DNF_VAR_SSL_CLIENT_CERT: process.env.DNF_VAR_SSL_CLIENT_CERT,
        DNF_VAR_SSL_AUTH_CLIENT_KEY: process.env.DNF_VAR_SSL_AUTH_CLIENT_KEY,
        DNF_VAR_SSL_AUTH_CLIENT_CERT: process.env.DNF_VAR_SSL_AUTH_CLIENT_CERT,
      },
    };

    await exec(cmd, execOptions);

    const newLockFileContent = await readLocalFile(lockFileName, 'utf8');

    if (existingLockFileContent === newLockFileContent) {
      logger.debug(`${lockFileName} is unchanged`);
      return null;
    }

    logger.debug(`Returning updated ${lockFileName}`);

    return [
      {
        file: {
          type: 'addition',
          path: lockFileName,
          contents: newLockFileContent,
          previousContents: existingLockFileContent,
        },
      },
    ];
  } catch (err) {
    if (err.message === TEMPORARY_ERROR) {
      throw err;
    }
    logger.debug({ err }, `Failed to update ${lockFileName} file`);
    return [
      {
        artifactError: {
          lockFile: lockFileName,
          stderr: `${String(err.stdout)}\n${String(err.stderr)}`,
        },
      },
    ];
  }
}
