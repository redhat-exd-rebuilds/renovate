import { logger } from '../../../../logger';
import type { UpdateArtifactsResult } from '../../../../modules/manager/types';
import type { BranchConfig } from '../../../types';

export function postProcessRPMVulnerabilities(
  result: UpdateArtifactsResult[] | null,
  config: BranchConfig,
): UpdateArtifactsResult[] | null {
  logger.debug('RPM vulnerability post-processing');
  if (result === null) {
    logger.debug('No RPM updates have been proposed');
    return result;
  }

  // TODO: parse the result, find vulnerabilities, render the PR body
  // DUMMY CODE. Simulation of found vulnerabilities.
  if (
    config.branchName ===
    'renovate/lock-file-maintenance-rpms.in.yaml-vulnerability'
  ) {
    // if vulnerability is found, update the PR message with the information
    config.prHeader = 'RPM vulnerability post-processing';
  } else {
    // if no vulnerability is found, pretend that the lockfilemaintenance is a no-op
    // This way no PR will be created and the evaluation should be safe and consistent
    return null;
  }

  return result;
}
