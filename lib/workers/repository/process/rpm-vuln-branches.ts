import type { RenovateConfig } from '../../../config/types.ts';
import { logger } from '../../../logger/index.ts';
import { clone } from '../../../util/clone.ts';
import type { BranchConfig } from '../../types.ts';

// This function clones the RPM lockfilemaintenance branches and turns them into vulnerability branches
// this approach is very hacky and potentially dangerous, but is reasonable for a downstream-only solution
export function createRPMLockFileVulnerabilityBranches(
  branches: BranchConfig[],
  config: RenovateConfig,
): [BranchConfig[], string[]] {
  if (config.rpmVulnerabilityAlerts === false) {
    return [branches, branches.map((branch) => branch.branchName)];
  }

  const resultBranches = [...branches];
  for (const branch of branches) {
    if (!(branch.isLockFileMaintenance && branch.manager === 'rpm-lockfile')) {
      continue;
    }
    logger.debug(
      { branch: branch.branchName },
      'RPM lockfile maintenance branch found',
    );

    const copiedBranch = clone(branch);
    // change some settings to make the it a vulnerability branch
    copiedBranch.schedule = [];
    copiedBranch.branchName = `${branch.branchName}-vulnerability`;
    copiedBranch.branchTopic = `${branch.branchTopic}-vulnerability`;
    copiedBranch.commitMessage = `${branch.commitMessage} [SECURITY]`;
    copiedBranch.commitMessageSuffix = '[SECURITY]';
    copiedBranch.prTitle = `${branch.prTitle} [SECURITY]`;
    copiedBranch.isVulnerabilityAlert = true;
    copiedBranch.vulnerabilityFixStrategy = 'lowest';
    copiedBranch.rpmVulnerabilityAutomerge = config.rpmVulnerabilityAutomerge;

    // Set properties for all upgrades
    for (const upgrade of copiedBranch.upgrades) {
      upgrade.schedule = [];
      upgrade.branchName = `${branch.branchName}-vulnerability`;
      upgrade.branchTopic = `${branch.branchTopic}-vulnerability`;
      upgrade.commitMessageSuffix = '[SECURITY]';
      upgrade.isVulnerabilityAlert = true;
      upgrade.vulnerabilityFixStrategy = 'lowest';
    }

    if (
      copiedBranch.upgrades.length === 1 &&
      copiedBranch.upgrades[0].manager === 'rpm-lockfile'
    ) {
      // There is only one update to RPM lockfile,
      // so the config stays the same and the PR will be title 'Refresh RPM lockfiles'
    } else {
      // There is more than one lockfile update in the repo,
      // so to make it less confusing, we choose the original PR title for lock file updates
      copiedBranch.prTitle = 'Lock file maintenance [SECURITY]';
    }

    // Add the vulnerability branch BEFORE the original branch
    const originalBranchIndex = resultBranches.findIndex(
      (resultBranch) => resultBranch.branchName === branch.branchName,
    );
    if (originalBranchIndex === -1) {
      resultBranches.push(copiedBranch);
    } else {
      resultBranches.splice(originalBranchIndex, 0, copiedBranch);
    }
  }
  const branchNames = resultBranches.map((branch) => branch.branchName);
  return [resultBranches, branchNames];
}
