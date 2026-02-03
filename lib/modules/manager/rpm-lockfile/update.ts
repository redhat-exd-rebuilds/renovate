import { logger } from '../../../logger';
import type { UpdateDependencyConfig } from '../types';

/**
 * For rpm-lockfile, the input file (rpms.in.yaml) doesn't contain version info.
 * The versions are only in the lockfile (rpms.lock.yaml).
 *
 * This function adds a temporary marker to the input file to signal that an
 * update is in progress. The actual lockfile update happens in updateArtifacts,
 * which also restores the original input file content.
 */
export function updateDependency({
  fileContent,
  upgrade,
}: UpdateDependencyConfig): string | null {
  logger.debug(
    { depName: upgrade.depName, newValue: upgrade.newValue },
    'rpm-lockfile.updateDependency()',
  );

  // Add a temporary marker comment to signal that an update happened.
  // This marker will be removed by updateArtifacts which restores the original content.
  // The marker includes a timestamp to ensure uniqueness.
  const marker = `# rpm-lockfile-update: ${upgrade.depName} ${Date.now()}\n`;

  return marker + fileContent;
}
