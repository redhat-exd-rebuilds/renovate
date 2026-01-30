import { quote } from 'shlex';
import upath from 'upath';
import { TEMPORARY_ERROR } from '../../../constants/error-messages';
import { logger } from '../../../logger';
import { exec } from '../../../util/exec';
import type { ExecOptions } from '../../../util/exec/types';
import {
  deleteLocalFile,
  getSiblingFileName,
  privateCacheDir,
  readLocalFile,
} from '../../../util/fs';
import * as hostRules from '../../../util/host-rules';
import { DockerDatasource } from '../../datasource/docker';
import type { UpdateArtifact, UpdateArtifactsResult } from '../types';

// Return the path to the skopeo auth file in the private cache directory.
// This prevents credential leakage between repositories.
function skopeoAuthFile(): string {
  return upath.join(privateCacheDir(), 'skopeo-auth.json');
}

// Generate skopeo login commands for all docker hostRules with credentials.
// This allows rpm-lockfile-prototype (which uses skopeo internally) to
// authenticate to container registries.
// Note: skopeo will use REGISTRY_AUTH_FILE env var set in execOptions.
function generateSkopeoLoginCommands(): string[] {
  const cmds: string[] = [];
  const dockerHostRules = hostRules.findAll({ hostType: DockerDatasource.id });

  logger.debug(
    `Found ${dockerHostRules.length} docker host rule(s) for skopeo login`,
  );

  for (const rule of dockerHostRules) {
    const { matchHost, username, password } = rule;

    if (matchHost && username && password) {
      const registry = matchHost.replace(/^https?:\/\//, '');
      logger.debug(`Generating skopeo login for registry: ${registry}`);

      cmds.push(
        `skopeo login --username ${quote(username)} --password ${quote(password)} ${quote(registry)}`,
      );
    }
  }

  return cmds;
}

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

    // Generate skopeo login commands for docker registries
    const skopeoLoginCmds = generateSkopeoLoginCommands();
    cmd.push(...skopeoLoginCmds);

    cmd.push(
      `caching-rpm-lockfile-prototype ${packageFileName} --outfile ${lockFileName}`,
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
        // Point skopeo/containers to use our private auth file (only if we have logins)
        ...(skopeoLoginCmds.length > 0 && {
          REGISTRY_AUTH_FILE: skopeoAuthFile(),
        }),
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
