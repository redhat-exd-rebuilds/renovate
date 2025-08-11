import type { RenovateConfig } from '../../../config/types';
import type { BranchConfig } from '../../types';
import { createRPMLockFileVulnerabilityBranches } from './rpm-vuln-branches';

vi.mock('../../../logger', () => ({ logger: { debug: vi.fn() } }));
vi.mock('../../../util/clone', () => ({
  clone: (obj: any) => JSON.parse(JSON.stringify(obj)),
}));

describe('workers/repository/process/rpm-vuln-branches', () => {
  const baseBranch: BranchConfig = {
    branchName: 'rpm-lockfile-maintenance',
    baseBranch: 'main',
    manager: 'rpm-lockfile',
    isLockFileMaintenance: true,
    upgrades: [
      {
        branchName: 'rpm-lockfile-maintenance',
        branchTopic: 'topic',
        manager: 'rpm-lockfile',
        schedule: ['after 1am'],
        commitMessageSuffix: '',
        isVulnerabilityAlert: false,
        vulnerabilitySeverity: undefined,
        vulnerabilityFixStrategy: undefined,
      },
    ],
    branchTopic: 'topic',
    commitMessage: 'chore: rpm lockfile maintenance',
    commitMessageSuffix: '',
    prTitle: 'chore: rpm lockfile maintenance',
    isVulnerabilityAlert: false,
    vulnerabilitySeverity: undefined,
    vulnerabilityFixStrategy: undefined,
  };

  it('returns original branches if rpmVulnerabilityAlerts is false', () => {
    const config: RenovateConfig = { rpmVulnerabilityAlerts: false } as any;
    const branches = [baseBranch];
    const result = createRPMLockFileVulnerabilityBranches(branches, config);
    expect(result).toBe(branches);
  });

  it('returns original branches if no rpm-lockfile maintenance branch', () => {
    const config: RenovateConfig = { rpmVulnerabilityAlerts: true } as any;
    const branches = [
      { ...baseBranch, manager: 'npm', isLockFileMaintenance: false },
    ];
    const result = createRPMLockFileVulnerabilityBranches(branches, config);
    expect(result).toEqual(branches);
    expect(result).toHaveLength(1);
  });

  it('duplicates and mutates rpm-lockfile maintenance branch', () => {
    const config: RenovateConfig = { rpmVulnerabilityAlerts: true } as any;
    const branches = [baseBranch];
    const result = createRPMLockFileVulnerabilityBranches(branches, config);
    expect(result).toHaveLength(2);
    const vulnBranch = result[1];
    expect(vulnBranch.branchName).toBe(
      'rpm-lockfile-maintenance-vulnerability',
    );
    expect(vulnBranch.upgrades[0].branchName).toBe(
      'rpm-lockfile-maintenance-vulnerability',
    );
    expect(vulnBranch.branchTopic).toBe('topic-vulnerability');
    expect(vulnBranch.upgrades[0].branchTopic).toBe('topic-vulnerability');
    expect(vulnBranch.commitMessage).toBe(
      'chore: rpm lockfile maintenance [SECURITY]',
    );
    expect(vulnBranch.upgrades[0].commitMessageSuffix).toBe('[SECURITY]');
    expect(vulnBranch.commitMessageSuffix).toBe('[SECURITY]');
    expect(vulnBranch.prTitle).toBe(
      'chore: rpm lockfile maintenance [SECURITY]',
    );
    expect(vulnBranch.isVulnerabilityAlert).toBe(true);
    expect(vulnBranch.upgrades[0].isVulnerabilityAlert).toBe(true);
    expect(vulnBranch.vulnerabilitySeverity).toBe('UNKNOWN');
    expect(vulnBranch.upgrades[0].vulnerabilitySeverity).toBe('UNKNOWN');
    expect(vulnBranch.vulnerabilityFixStrategy).toBe('lowest');
    expect(vulnBranch.upgrades[0].vulnerabilityFixStrategy).toBe('lowest');

    const origBranch = result[0];
    expect(origBranch).toEqual(baseBranch);
  });
});
