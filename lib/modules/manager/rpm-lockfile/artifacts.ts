import { dirname, join } from 'upath';
import { logger } from '../../../logger';
import { readLocalFile } from '../../../util/fs';
import type { UpdateArtifact, UpdateArtifactsResult } from '../types';
import { getNewLockFileContent, getOriginalInputFileContent } from './common';

export async function updateArtifacts({
  packageFileName,
  updatedDeps,
  newPackageFileContent,
  config,
}: UpdateArtifact): Promise<UpdateArtifactsResult[] | null> {
  logger.debug(
    {
      packageFileName,
      depCount: updatedDeps.length,
      deps: updatedDeps.map((d) => ({
        depName: d.depName,
        currentValue: d.currentValue,
        newValue: d.newValue,
      })),
    },
    'rpm-lockfile.updateArtifacts()',
  );

  // packageFileName is the input file (rpms.in.yaml or rpms.in.yml)
  const dir = dirname(packageFileName);
  const lockFileName = dir ? join(dir, 'rpms.lock.yaml') : 'rpms.lock.yaml';

  // Get the cached new lock file content from extract phase
  // The tool was already run once during extract, no need to run again
  const newLockContent = getNewLockFileContent(lockFileName);

  if (!newLockContent) {
    logger.debug(
      { lockFileName },
      'No cached lock file content found, skipping artifact update',
    );
    return null;
  }

  logger.debug({ lockFileName }, 'Returning cached lock file content');

  const results: UpdateArtifactsResult[] = [
    {
      file: {
        type: 'addition',
        path: lockFileName,
        contents: newLockContent,
      },
    },
  ];

  // Restore the original input file content to remove the temporary marker
  // added by updateDependency
  let originalContent: string | undefined =
    getOriginalInputFileContent(packageFileName);
  // Fallback: read from disk (might be needed if cache was cleared)
  originalContent ??=
    (await readLocalFile(packageFileName, 'utf8')) ?? undefined;

  if (originalContent) {
    logger.debug({ packageFileName }, 'Restoring original input file content');
    results.push({
      file: {
        type: 'addition',
        path: packageFileName,
        contents: originalContent,
      },
    });
  }

  return results;
}
