import type { RenovateConfig } from '../../../config/types';
import { logger } from '../../../logger';
import { clone } from '../../../util/clone';
import type { BranchConfig } from '../../types';

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
    copiedBranch.upgrades[0].schedule = [];
    copiedBranch.branchName = `${branch.branchName}-vulnerability`;
    copiedBranch.upgrades[0].branchName = `${branch.branchName}-vulnerability`;
    copiedBranch.branchTopic = `${branch.branchTopic}-vulnerability`;
    copiedBranch.upgrades[0].branchTopic = `${branch.branchTopic}-vulnerability`;
    copiedBranch.commitMessage = `${branch.commitMessage} [SECURITY]`;
    copiedBranch.upgrades[0].commitMessageSuffix = '[SECURITY]';
    copiedBranch.commitMessageSuffix = '[SECURITY]';
    copiedBranch.prTitle = `${branch.prTitle} [SECURITY]`;
    copiedBranch.isVulnerabilityAlert = true;
    copiedBranch.upgrades[0].isVulnerabilityAlert = true;
    copiedBranch.vulnerabilitySeverity = 'UNKNOWN';
    copiedBranch.upgrades[0].vulnerabilitySeverity = 'UNKNOWN';
    copiedBranch.vulnerabilityFixStrategy = 'lowest';
    copiedBranch.upgrades[0].vulnerabilityFixStrategy = 'lowest';

    resultBranches.push(copiedBranch);
  }
  const branchNames = resultBranches.map((branch) => branch.branchName);
  return [resultBranches, branchNames];
}
