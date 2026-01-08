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
        vulnerabilityFixStrategy: undefined,
      },
    ],
    branchTopic: 'topic',
    commitMessage: 'chore: rpm lockfile maintenance',
    commitMessageSuffix: '',
    prTitle: 'chore: rpm lockfile maintenance',
    isVulnerabilityAlert: false,
    vulnerabilityFixStrategy: undefined,
  };

  it('returns original branches if rpmVulnerabilityAlerts is false', () => {
    const config: RenovateConfig = { rpmVulnerabilityAlerts: false } as any;
    const branches = [baseBranch];
    const [resultBranches, branchNames] =
      createRPMLockFileVulnerabilityBranches(branches, config);
    expect(resultBranches).toBe(branches);
    expect(branchNames).toEqual(branches.map((b) => b.branchName));
  });

  it('returns original branches if no rpm-lockfile maintenance branch', () => {
    const config: RenovateConfig = { rpmVulnerabilityAlerts: true } as any;
    const branches = [
      { ...baseBranch, manager: 'npm', isLockFileMaintenance: false },
    ];
    const [resultBranches, branchNames] =
      createRPMLockFileVulnerabilityBranches(branches, config);
    expect(resultBranches).toEqual(branches);
    expect(resultBranches).toHaveLength(1);
    expect(branchNames).toEqual(branches.map((b) => b.branchName));
  });

  it('duplicates and mutates rpm-lockfile maintenance branch', () => {
    const config: RenovateConfig = { rpmVulnerabilityAlerts: true } as any;
    const branches = [baseBranch];
    const [resultBranches, branchNames] =
      createRPMLockFileVulnerabilityBranches(branches, config);
    expect(resultBranches).toHaveLength(2);
    expect(branchNames).toHaveLength(2);
    expect(branchNames).toEqual(resultBranches.map((b) => b.branchName));

    // Vulnerability branch is inserted BEFORE the original branch
    const vulnBranch = resultBranches[0];
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
    expect(vulnBranch.vulnerabilityFixStrategy).toBe('lowest');
    expect(vulnBranch.upgrades[0].vulnerabilityFixStrategy).toBe('lowest');

    // Verify schedule is cleared
    expect(vulnBranch.schedule).toEqual([]);
    expect(vulnBranch.upgrades[0].schedule).toEqual([]);

    // Original branch is now at index 1
    const origBranch = resultBranches[1];
    expect(origBranch).toEqual(baseBranch);
  });

  it('handles multiple rpm-lockfile maintenance branches', () => {
    const config: RenovateConfig = { rpmVulnerabilityAlerts: true } as any;
    const branch1 = { ...baseBranch, branchName: 'rpm-lockfile-maintenance-1' };
    const branch2 = { ...baseBranch, branchName: 'rpm-lockfile-maintenance-2' };
    const nonRpmBranch = {
      ...baseBranch,
      manager: 'npm',
      isLockFileMaintenance: false,
    };
    const branches = [branch1, nonRpmBranch, branch2];

    const [resultBranches, branchNames] =
      createRPMLockFileVulnerabilityBranches(branches, config);

    expect(resultBranches).toHaveLength(5); // 2 vuln + 3 original
    expect(branchNames).toHaveLength(5);
    expect(branchNames).toEqual(resultBranches.map((b) => b.branchName));

    // First vulnerability branch should be inserted before first original branch
    expect(resultBranches[0].branchName).toBe(
      'rpm-lockfile-maintenance-1-vulnerability',
    );
    expect(resultBranches[1].branchName).toBe('rpm-lockfile-maintenance-1');

    // Non-RPM branch should be at index 2
    expect(resultBranches[2]).toBe(nonRpmBranch);

    // Second vulnerability branch should be inserted before second original branch
    expect(resultBranches[3].branchName).toBe(
      'rpm-lockfile-maintenance-2-vulnerability',
    );
    expect(resultBranches[4].branchName).toBe('rpm-lockfile-maintenance-2');
  });

  it('preserves original branch properties unchanged', () => {
    const config: RenovateConfig = { rpmVulnerabilityAlerts: true } as any;
    const originalBranch = {
      ...baseBranch,
      schedule: ['after 2am'],
      customProperty: 'should-be-preserved',
    };
    const branches = [originalBranch];

    const [resultBranches] = createRPMLockFileVulnerabilityBranches(
      branches,
      config,
    );

    const vulnBranch = resultBranches[0];
    const preservedOriginalBranch = resultBranches[1];

    // Original branch should be completely unchanged
    expect(preservedOriginalBranch).toEqual(originalBranch);
    expect(preservedOriginalBranch.schedule).toEqual(['after 2am']);
    expect((preservedOriginalBranch as any).customProperty).toBe(
      'should-be-preserved',
    );

    // Vulnerability branch should have modified properties
    expect(vulnBranch.schedule).toEqual([]);
    expect(vulnBranch.isVulnerabilityAlert).toBe(true);
  });

  it('sets rpmVulnerabilityAutomerge from config', () => {
    const config: RenovateConfig = {
      rpmVulnerabilityAlerts: true,
      rpmVulnerabilityAutomerge: 'HIGH',
    } as any;
    const branches = [baseBranch];

    const [resultBranches] = createRPMLockFileVulnerabilityBranches(
      branches,
      config,
    );

    const vulnBranch = resultBranches[0];
    expect(vulnBranch.rpmVulnerabilityAutomerge).toBe('HIGH');
  });

  it('sets rpmVulnerabilityAutomerge to undefined when config is undefined', () => {
    const config: RenovateConfig = {
      rpmVulnerabilityAlerts: true,
    } as any;
    const branches = [baseBranch];

    const [resultBranches] = createRPMLockFileVulnerabilityBranches(
      branches,
      config,
    );

    const vulnBranch = resultBranches[0];
    expect(vulnBranch.rpmVulnerabilityAutomerge).toBe(undefined);
  });
});
