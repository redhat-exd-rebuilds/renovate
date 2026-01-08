import { RedHatRPMLockfile } from '../../../../modules/manager/rpm-lockfile/schema';
import { parseSingleYaml } from '../../../../util/yaml';
import * as updatesTableModule from '../pr/body/updates-table';
import {
  applyVulnerabilityPRNotes,
  createUpdatesTable,
  createVulnerabilities,
  determineSeverityAutomerge,
  getUpgrade,
  parseLockfilePackages,
  postProcessRPMs,
} from './rpm-post-processing';
import { RpmVulnerabilities } from './rpm-vulnerabilities';

describe('workers/repository/update/branch/rpm-post-processing', () => {
  describe('parseLockfilePackages()', () => {
    const oldYaml = `
lockfileVersion: 1
lockfileVendor: RedHat
arches:
  - arch: x86_64
    packages:
      - url: http://example/p1
        repoid: base
        size: 123
        checksum: abc
        name: pkg1
        evr: "1.0"
        sourcerpm: src1
      - url: http://example/p2
        repoid: base
        size: 456
        checksum: def
        name: pkg2
        evr: "2.0"
        sourcerpm: src2
`;

    const newYamlChanged = `
lockfileVersion: 1
lockfileVendor: RedHat
arches:
  - arch: x86_64
    packages:
      - url: http://example/p1
        repoid: base
        size: 123
        checksum: abc
        name: pkg1
        evr: "1.1"
        sourcerpm: src1
      - url: http://example/p2
        repoid: base
        size: 456
        checksum: def
        name: pkg2
        evr: "2.0"
        sourcerpm: src2
`;

    it('returns only packages with changed versions', () => {
      const results = [
        {
          file: {
            type: 'addition',
            path: 'packages.lock.yaml',
            previousContents: oldYaml,
            contents: newYamlChanged,
          },
        },
      ];
      const pkgs = parseLockfilePackages(results as any);
      expect(pkgs).toHaveLength(1);
      expect(pkgs[0]).toMatchObject({
        depName: 'pkg1',
        packageName: 'pkg1',
        currentVersion: '1.0',
        newVersion: '1.1',
        versioning: 'rpm',
        datasource: 'rpm-lockfile',
      });
    });

    it('parses our sample lockfile with schema', () => {
      const parsed = parseSingleYaml(oldYaml, {
        customSchema: RedHatRPMLockfile,
      });
      expect(parsed.arches[0].arch).toBe('x86_64');
      expect(parsed.arches[0].packages).toHaveLength(2);
    });

    it('returns empty on parse error', () => {
      const results = [
        {
          file: {
            type: 'addition',
            path: 'packages.lock.yaml',
            previousContents: 'not: valid: yaml: 1',
            contents: 'also: invalid: 2',
          },
        },
      ];
      const pkgs = parseLockfilePackages(results as any);
      expect(pkgs).toEqual([]);
    });
  });

  describe('createVulnerabilities()', () => {
    it('flattens and de-duplicates by vulnerability id', async () => {
      const packages = [
        {
          depName: 'pkg1',
          packageName: 'pkg1',
          currentVersion: '1.0',
          currentValue: '1.0',
          newVersion: '1.1',
          newValue: '1.1',
          versioning: 'rpm',
          datasource: 'rpm-lockfile',
        },
        {
          depName: 'pkg2',
          packageName: 'pkg2',
          currentVersion: '2.0',
          currentValue: '2.0',
          newVersion: '2.1',
          newValue: '2.1',
          versioning: 'rpm',
          datasource: 'rpm-lockfile',
        },
      ];

      const rpmVulns: Partial<RpmVulnerabilities> = {
        fetchDependencyVulnerability: vi
          .fn()
          .mockResolvedValueOnce({
            vulnerabilities: [
              {
                vulnerability: { id: 'VULN-1' },
                affected: {},
              },
              {
                vulnerability: { id: 'VULN-2' },
                affected: {},
              },
            ],
          })
          .mockResolvedValueOnce({
            vulnerabilities: [
              {
                vulnerability: { id: 'VULN-2' },
                affected: {},
              },
              {
                vulnerability: { id: 'VULN-3' },
                affected: {},
              },
            ],
          }),
      } as any;

      const vulns = await createVulnerabilities(
        packages as any,
        rpmVulns as unknown as RpmVulnerabilities,
      );
      expect(vulns.map((v) => v.vulnerability.id).sort()).toEqual([
        'VULN-1',
        'VULN-2',
        'VULN-3',
      ]);
    });
  });

  describe('applyVulnerabilityPRNotes()', () => {
    it('appends notes to config and upgrade', () => {
      const rpmVulns: Partial<RpmVulnerabilities> = {
        generatePrBodyNotes: vi.fn().mockReturnValue(['note-a', 'note-b']),
      } as any;

      const config: any = {
        upgrades: [{ prBodyNotes: ['existing'] }],
      };

      const upgrade: any = { prBodyNotes: ['existing-upgrade'] };

      const vulnerabilities: any[] = [
        { vulnerability: { id: 'A' }, affected: {} },
        { vulnerability: { id: 'B' }, affected: {} },
      ];

      applyVulnerabilityPRNotes(
        vulnerabilities as any,
        config,
        upgrade,
        rpmVulns as any,
      );

      expect(config.prBodyNotes).toEqual([
        'note-a',
        'note-b',
        'note-a',
        'note-b',
      ]);
      expect(upgrade.prBodyNotes).toEqual([
        'existing-upgrade',
        'note-a',
        'note-b',
        'note-a',
        'note-b',
      ]);
    });

    it('passes truncated=true when total notes would exceed 10', () => {
      const gen = vi.fn().mockReturnValue(['n']);
      const rpmVulns: Partial<RpmVulnerabilities> = {
        generatePrBodyNotes: gen,
      } as any;

      const config: any = {
        prBodyNotes: new Array(9).fill('e'),
      };
      const upgrade: any = { prBodyNotes: [] };
      const vulnerabilities: any[] = [
        { vulnerability: { id: 'A' }, affected: {} },
        { vulnerability: { id: 'B' }, affected: {} },
      ];

      applyVulnerabilityPRNotes(
        vulnerabilities as any,
        config,
        upgrade,
        rpmVulns as any,
      );

      // called twice, with truncated true and isFirst flag as false
      expect(gen).toHaveBeenCalledTimes(2);
      const args = gen.mock.calls[0];
      expect(args[2]).toBe(true);
      expect(args[3]).toBe(false);
    });
  });

  describe('getUpgrade()', () => {
    it('returns first upgrade when result is null', () => {
      const config: any = {
        upgrades: [
          { packageFile: 'package1.spec', lockFiles: ['lock1.yaml'] },
          { packageFile: 'package2.spec', lockFiles: ['lock2.yaml'] },
        ],
      };

      const upgrade = getUpgrade(null, config);
      expect(upgrade).toBe(config.upgrades[0]);
    });

    it('finds matching upgrades based on lockFiles paths', () => {
      const result = [
        {
          file: {
            type: 'addition',
            path: 'packages.lock.yaml',
            previousContents: 'old',
            contents: 'new',
          },
        },
      ];

      const config: any = {
        upgrades: [
          {
            packageFile: 'package1.in.yaml',
            lockFiles: ['different.lock.yaml'],
          },
          {
            packageFile: 'package2.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
        ],
      };

      const upgrade = getUpgrade(result as any, config);
      expect(upgrade).toBe(config.upgrades[1]);
    });

    it('returns first upgrade when no matching upgrades found', () => {
      const result = [
        {
          file: {
            type: 'addition',
            path: 'unmatched.lock.yaml',
            previousContents: 'old',
            contents: 'new',
          },
        },
      ];

      const config: any = {
        upgrades: [
          {
            packageFile: 'package1.spec',
            lockFiles: ['different.lock.yaml'],
          },
          {
            packageFile: 'package2.spec',
            lockFiles: ['another.lock.yaml'],
          },
        ],
      };

      const upgrade = getUpgrade(result as any, config);
      expect(upgrade).toBe(config.upgrades[0]);
    });

    it('handles multiple matching upgrades and returns first unique one', () => {
      const result = [
        {
          file: {
            type: 'addition',
            path: 'packages.lock.yaml',
            previousContents: 'old',
            contents: 'new',
          },
        },
      ];

      const config: any = {
        upgrades: [
          {
            packageFile: 'package1.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
          {
            packageFile: 'package1.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
          {
            packageFile: 'package2.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
        ],
      };

      const upgrade = getUpgrade(result as any, config);
      expect(upgrade.packageFile).toBe('package1.in.yaml');
      expect(upgrade.lockFiles).toEqual(['packages.lock.yaml']);
    });

    it('deduplicates by packageFile and returns first when multiple unique matches', () => {
      const result = [
        {
          file: {
            type: 'addition',
            path: 'packages.lock.yaml',
            previousContents: 'old',
            contents: 'new',
          },
        },
      ];

      const config: any = {
        upgrades: [
          {
            packageFile: 'package1.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
          {
            packageFile: 'package2.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
          {
            packageFile: 'package3.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
        ],
      };

      const upgrade = getUpgrade(result as any, config);
      // Should return the first upgrade when multiple unique upgrades match
      expect(upgrade).toBe(config.upgrades[0]);
    });

    it('ignores non-addition file types', () => {
      const result = [
        {
          file: {
            type: 'deletion',
            path: 'packages.lock.yaml',
          },
        },
        {
          file: {
            type: 'modification',
            path: 'other.lock.yaml',
          },
        },
      ];

      const config: any = {
        upgrades: [
          {
            packageFile: 'package1.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
          {
            packageFile: 'package2.in.yaml',
            lockFiles: ['other.lock.yaml'],
          },
        ],
      };

      const upgrade = getUpgrade(result as any, config);
      // Should fall back to first upgrade since only addition files are processed
      expect(upgrade).toBe(config.upgrades[0]);
    });

    it('handles upgrades without lockFiles property', () => {
      const result = [
        {
          file: {
            type: 'addition',
            path: 'packages.lock.yaml',
            previousContents: 'old',
            contents: 'new',
          },
        },
      ];

      const config: any = {
        upgrades: [
          {
            packageFile: 'package1.in.yaml',
            // No lockFiles property
          },
          {
            packageFile: 'package2.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
        ],
      };

      const upgrade = getUpgrade(result as any, config);
      // Should find the upgrade with matching lockFiles
      expect(upgrade).toBe(config.upgrades[1]);
    });

    it('handles empty lockFiles array', () => {
      const result = [
        {
          file: {
            type: 'addition',
            path: 'packages.lock.yaml',
            previousContents: 'old',
            contents: 'new',
          },
        },
      ];

      const config: any = {
        upgrades: [
          {
            packageFile: 'package1.in.yaml',
            lockFiles: [],
          },
          {
            packageFile: 'package2.in.yaml',
            lockFiles: ['packages.lock.yaml'],
          },
        ],
      };

      const upgrade = getUpgrade(result as any, config);
      // Should find the upgrade with matching lockFiles
      expect(upgrade).toBe(config.upgrades[1]);
    });
  });

  describe('determineSeverityAutomerge()', () => {
    const mockRpmVulns = {
      extractSeverityDetails: vi.fn(),
    } as any;

    beforeEach(() => {
      vi.clearAllMocks();
    });

    it('should set vulnerabilitySeverity to highest severity from vulnerabilities', () => {
      const vulnerabilities = [
        { vulnerability: { id: 'VULN-1' }, affected: {} },
        { vulnerability: { id: 'VULN-2' }, affected: {} },
      ] as any;

      mockRpmVulns.extractSeverityDetails
        .mockReturnValueOnce({ severityLevel: 'medium' })
        .mockReturnValueOnce({ severityLevel: 'high' });

      const config: any = { upgrades: [] };
      const upgrade: any = {};

      determineSeverityAutomerge(
        vulnerabilities,
        config,
        upgrade,
        mockRpmVulns,
      );

      expect(upgrade.vulnerabilitySeverity).toBe('HIGH');
    });

    it('should handle empty vulnerabilities array', () => {
      const vulnerabilities: any[] = [];
      const config: any = { upgrades: [] };
      const upgrade: any = {};

      determineSeverityAutomerge(
        vulnerabilities,
        config,
        upgrade,
        mockRpmVulns,
      );

      expect(upgrade.vulnerabilitySeverity).toBeUndefined();
    });

    describe('automerge behavior', () => {
      it('should enable automerge when rpmVulnerabilityAutomerge is "ALL" and vulnerabilities exist', () => {
        const vulnerabilities = [
          { vulnerability: { id: 'VULN-1' }, affected: {} },
        ] as any;

        mockRpmVulns.extractSeverityDetails.mockReturnValueOnce({
          severityLevel: 'low',
        });

        const config: any = {
          rpmVulnerabilityAutomerge: 'ALL',
          upgrades: [],
        };
        const upgrade: any = {};

        determineSeverityAutomerge(
          vulnerabilities,
          config,
          upgrade,
          mockRpmVulns,
        );

        expect(config.automerge).toBe(true);
        expect(upgrade.vulnerabilitySeverity).toBe('LOW');
      });

      it('should not enable automerge when rpmVulnerabilityAutomerge is "ALL" but no vulnerabilities', () => {
        const vulnerabilities: any[] = [];
        const config: any = {
          rpmVulnerabilityAutomerge: 'ALL',
          upgrades: [],
        };
        const upgrade: any = {};

        determineSeverityAutomerge(
          vulnerabilities,
          config,
          upgrade,
          mockRpmVulns,
        );

        expect(config.automerge).toBeUndefined();
      });

      it('should enable automerge when severity meets threshold for MEDIUM', () => {
        const vulnerabilities = [
          { vulnerability: { id: 'VULN-1' }, affected: {} },
        ] as any;

        mockRpmVulns.extractSeverityDetails.mockReturnValueOnce({
          severityLevel: 'high',
        });

        const config: any = {
          rpmVulnerabilityAutomerge: 'MEDIUM',
          upgrades: [],
        };
        const upgrade: any = {};

        determineSeverityAutomerge(
          vulnerabilities,
          config,
          upgrade,
          mockRpmVulns,
        );

        expect(config.automerge).toBe(true);
        expect(upgrade.vulnerabilitySeverity).toBe('HIGH');
      });

      it('should not enable automerge when severity below threshold for HIGH', () => {
        const vulnerabilities = [
          { vulnerability: { id: 'VULN-1' }, affected: {} },
        ] as any;

        mockRpmVulns.extractSeverityDetails.mockReturnValueOnce({
          severityLevel: 'medium',
        });

        const config: any = {
          rpmVulnerabilityAutomerge: 'HIGH',
          upgrades: [],
        };
        const upgrade: any = {};

        determineSeverityAutomerge(
          vulnerabilities,
          config,
          upgrade,
          mockRpmVulns,
        );

        expect(config.automerge).toBeUndefined();
        expect(upgrade.vulnerabilitySeverity).toBe('MEDIUM');
      });

      it('should enable automerge when severity equals threshold', () => {
        const vulnerabilities = [
          { vulnerability: { id: 'VULN-1' }, affected: {} },
        ] as any;

        mockRpmVulns.extractSeverityDetails.mockReturnValueOnce({
          severityLevel: 'critical',
        });

        const config: any = {
          rpmVulnerabilityAutomerge: 'CRITICAL',
          upgrades: [],
        };
        const upgrade: any = {};

        determineSeverityAutomerge(
          vulnerabilities,
          config,
          upgrade,
          mockRpmVulns,
        );

        expect(config.automerge).toBe(true);
        expect(upgrade.vulnerabilitySeverity).toBe('CRITICAL');
      });

      it('should handle case insensitive rpmVulnerabilityAutomerge config', () => {
        const vulnerabilities = [
          { vulnerability: { id: 'VULN-1' }, affected: {} },
        ] as any;

        mockRpmVulns.extractSeverityDetails.mockReturnValueOnce({
          severityLevel: 'high',
        });

        const config: any = {
          rpmVulnerabilityAutomerge: 'medium',
          upgrades: [],
        };
        const upgrade: any = {};

        determineSeverityAutomerge(
          vulnerabilities,
          config,
          upgrade,
          mockRpmVulns,
        );

        expect(config.automerge).toBe(true);
      });

      it('should not enable automerge when rpmVulnerabilityAutomerge is null', () => {
        const vulnerabilities = [
          { vulnerability: { id: 'VULN-1' }, affected: {} },
        ] as any;

        mockRpmVulns.extractSeverityDetails.mockReturnValueOnce({
          severityLevel: 'critical',
        });

        const config: any = {
          rpmVulnerabilityAutomerge: null,
          upgrades: [],
        };
        const upgrade: any = {};

        determineSeverityAutomerge(
          vulnerabilities,
          config,
          upgrade,
          mockRpmVulns,
        );

        expect(config.automerge).toBeUndefined();
      });

      it('should not enable automerge when rpmVulnerabilityAutomerge is undefined', () => {
        const vulnerabilities = [
          { vulnerability: { id: 'VULN-1' }, affected: {} },
        ] as any;

        mockRpmVulns.extractSeverityDetails.mockReturnValueOnce({
          severityLevel: 'critical',
        });

        const config: any = {
          upgrades: [],
        };
        const upgrade: any = {};

        determineSeverityAutomerge(
          vulnerabilities,
          config,
          upgrade,
          mockRpmVulns,
        );

        expect(config.automerge).toBeUndefined();
      });
    });

    describe('invalid configuration handling', () => {
      it('should log warning for invalid string rpmVulnerabilityAutomerge value', () => {
        const vulnerabilities = [
          { vulnerability: { id: 'VULN-1' }, affected: {} },
        ] as any;

        mockRpmVulns.extractSeverityDetails.mockReturnValueOnce({
          severityLevel: 'high',
        });

        const config: any = {
          rpmVulnerabilityAutomerge: 'INVALID',
          upgrades: [],
        };
        const upgrade: any = {};

        determineSeverityAutomerge(
          vulnerabilities,
          config,
          upgrade,
          mockRpmVulns,
        );

        expect(config.automerge).toBeUndefined();
      });

      it('should handle all valid automerge values', () => {
        const validValues = ['ALL', 'MEDIUM', 'HIGH', 'CRITICAL'];

        for (const value of validValues) {
          const vulnerabilities = [
            { vulnerability: { id: 'VULN-1' }, affected: {} },
          ] as any;

          mockRpmVulns.extractSeverityDetails.mockReturnValueOnce({
            severityLevel: 'critical',
          });

          const config: any = {
            rpmVulnerabilityAutomerge: value,
            upgrades: [],
          };
          const upgrade: any = {};

          determineSeverityAutomerge(
            vulnerabilities,
            config,
            upgrade,
            mockRpmVulns,
          );

          expect(config.automerge).toBe(true);

          // Reset for next iteration
          config.automerge = undefined;
          vi.clearAllMocks();
        }
      });
    });

    describe('severity level ordering', () => {
      it('should correctly order LOW < MEDIUM < HIGH < CRITICAL', () => {
        const testCases = [
          { first: 'low', second: 'medium', expected: 'MEDIUM' },
          { first: 'medium', second: 'high', expected: 'HIGH' },
          { first: 'high', second: 'critical', expected: 'CRITICAL' },
          { first: 'critical', second: 'low', expected: 'CRITICAL' },
        ];

        for (const testCase of testCases) {
          const vulnerabilities = [
            { vulnerability: { id: 'VULN-1' }, affected: {} },
            { vulnerability: { id: 'VULN-2' }, affected: {} },
          ] as any;

          mockRpmVulns.extractSeverityDetails
            .mockReturnValueOnce({ severityLevel: testCase.first })
            .mockReturnValueOnce({ severityLevel: testCase.second });

          const config: any = { upgrades: [] };
          const upgrade: any = {};

          determineSeverityAutomerge(
            vulnerabilities,
            config,
            upgrade,
            mockRpmVulns,
          );

          expect(upgrade.vulnerabilitySeverity).toBe(testCase.expected);

          // Reset for next iteration
          vi.clearAllMocks();
        }
      });
    });
  });

  describe('postProcessRPMs()', () => {
    const buildLockfileResult = (oldEvr: string, newEvr: string) => {
      const oldYaml = `
lockfileVersion: 1
lockfileVendor: RedHat
arches:
  - arch: x86_64
    packages:
      - url: http://example/p1
        repoid: base
        size: 123
        checksum: abc
        name: pkg1
        evr: "${oldEvr}"
        sourcerpm: src1
`;
      const newYaml = oldYaml.replace(`evr: "${oldEvr}"`, `evr: "${newEvr}"`);
      return [
        {
          file: {
            type: 'addition',
            path: 'packages.lock.yaml',
            previousContents: oldYaml,
            contents: newYaml,
          },
        },
      ];
    };

    it('returns null when result is null', async () => {
      const cfg: any = { upgrades: [{}] };
      const res = await postProcessRPMs(null, cfg);
      expect(res).toBeNull();
    });

    it('returns null when no packages parsed', async () => {
      const cfg: any = { upgrades: [{}] };
      const results = [
        {
          file: {
            type: 'deletion',
            path: 'packages.lock.yaml',
          },
        },
      ];
      const res = await postProcessRPMs(results as any, cfg);
      expect(res).toBeNull();
    });

    it('returns original result when isVulnerabilityAlert is false', async () => {
      const cfg: any = {
        upgrades: [{}],
        isVulnerabilityAlert: false,
      };
      const results = buildLockfileResult('1.0', '1.1');
      const res = await postProcessRPMs(results as any, cfg);
      expect(res).toBe(results as any);
    });

    it('returns null when no vulnerabilities found', async () => {
      const fake: Partial<RpmVulnerabilities> = {
        fetchDependencyVulnerability: vi.fn().mockResolvedValue(null),
        generatePrBodyNotes: vi.fn().mockReturnValue([]),
      } as any;
      vi.spyOn(RpmVulnerabilities, 'create').mockResolvedValue(fake as any);

      const cfg: any = { upgrades: [{}], isVulnerabilityAlert: true };
      const results = buildLockfileResult('1.0', '1.1');
      const res = await postProcessRPMs(results as any, cfg);
      expect(res).toBeNull();
    });

    it('applies PR notes and returns original result on vulnerabilities', async () => {
      const fake: Partial<RpmVulnerabilities> = {
        fetchDependencyVulnerability: vi.fn().mockResolvedValue({
          vulnerabilities: [
            { vulnerability: { id: 'A' }, affected: {} },
            { vulnerability: { id: 'B' }, affected: {} },
          ],
        }),
        generatePrBodyNotes: vi.fn().mockReturnValue(['note']),
        extractSeverityDetails: vi
          .fn()
          .mockReturnValue({ severityLevel: 'medium' }),
      } as any;
      vi.spyOn(RpmVulnerabilities, 'create').mockResolvedValue(fake as any);

      const cfg: any = {
        isVulnerabilityAlert: true,
        upgrades: [
          {
            packageFile: 'package.spec',
            lockFiles: ['packages.lock.yaml'],
            prBodyNotes: [],
          },
        ],
      };
      const results = buildLockfileResult('1.0', '1.1');
      const res = await postProcessRPMs(results as any, cfg);
      expect(res).toBe(results as any);
      expect(cfg.prBodyNotes).toEqual(['note', 'note']);
      expect(cfg.upgrades[0].prBodyNotes).toEqual(['note', 'note']);
      // Verify determineSeverityAutomerge was called and set vulnerabilitySeverity
      expect(cfg.upgrades[0].vulnerabilitySeverity).toBe('MEDIUM');
    });
  });

  describe('createUpdatesTable()', () => {
    let mockGetPrUpdatesTable: any;

    beforeEach(() => {
      // Spy on getPrUpdatesTable only for this test suite
      mockGetPrUpdatesTable = vi.spyOn(updatesTableModule, 'getPrUpdatesTable');
    });

    afterEach(() => {
      // Restore the original function after each test
      vi.restoreAllMocks();
    });

    it('should return early when packages array is empty', () => {
      const config: any = {
        branchName: 'test-branch',
        manager: 'rpm',
      };
      const upgrade: any = {
        packageFile: 'package.spec',
      };
      const packages: any[] = [];

      createUpdatesTable(config, upgrade, packages);

      expect(mockGetPrUpdatesTable).not.toHaveBeenCalled();
      expect(config.prHeader).toBeUndefined();
    });

    it('should return early when no packages have version changes', () => {
      const config: any = {
        branchName: 'test-branch',
        manager: 'rpm',
      };
      const upgrade: any = {
        packageFile: 'package.spec',
      };
      const packages = [
        {
          depName: 'pkg1',
          currentVersion: '1.0.0',
          newVersion: '1.0.0', // same version
        },
        {
          depName: 'pkg2',
          currentVersion: undefined, // no current version
          newVersion: '2.0.0',
        },
        {
          depName: 'pkg3',
          currentVersion: '3.0.0',
          newVersion: undefined, // no new version
        },
      ];

      createUpdatesTable(config, upgrade, packages);

      expect(mockGetPrUpdatesTable).not.toHaveBeenCalled();
      expect(config.prHeader).toBeUndefined();
    });

    it('should create updates table with basic functionality', () => {
      const config: any = {
        branchName: 'test-branch',
        manager: 'rpm',
      };
      const upgrade: any = {
        packageFile: 'package.spec',
      };
      const packages = [
        {
          depName: 'pkg1',
          currentVersion: '1.0.0',
          newVersion: '1.1.0',
        },
        {
          depName: 'pkg2',
          currentVersion: '2.0.0',
          newVersion: '2.1.0',
        },
      ];

      mockGetPrUpdatesTable.mockReturnValue(
        '\n\nThis PR contains the following updates:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n| pkg2 | `2.0.0` -> `2.1.0` |\n\n',
      );

      createUpdatesTable(config, upgrade, packages);

      expect(mockGetPrUpdatesTable).toHaveBeenCalledWith({
        manager: 'rpm',
        branchName: 'test-branch',
        baseBranch: undefined,
        prBodyColumns: ['Package', 'Change'],
        upgrades: [
          {
            manager: 'rpm-lockfile',
            branchName: 'test-branch',
            depName: 'pkg1',
            depNameLinked: 'pkg1',
            displayFrom: '1.0.0',
            displayTo: '1.1.0',
            prBodyDefinitions: {
              Package: '{{{depNameLinked}}}',
              Change: '`{{{displayFrom}}}` -> `{{{displayTo}}}`',
            },
          },
          {
            manager: 'rpm-lockfile',
            branchName: 'test-branch',
            depName: 'pkg2',
            depNameLinked: 'pkg2',
            displayFrom: '2.0.0',
            displayTo: '2.1.0',
            prBodyDefinitions: {
              Package: '{{{depNameLinked}}}',
              Change: '`{{{displayFrom}}}` -> `{{{displayTo}}}`',
            },
          },
        ],
      });

      expect(config.prHeader).toBe(
        'This PR contains the following updates:\n\nFile package.spec:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n| pkg2 | `2.0.0` -> `2.1.0` |\n\n',
      );
    });

    it('should append to existing prHeader', () => {
      const config: any = {
        branchName: 'test-branch',
        manager: 'rpm',
        prHeader: 'Existing header content',
      };
      const upgrade: any = {
        packageFile: 'package.spec',
      };
      const packages = [
        {
          depName: 'pkg1',
          currentVersion: '1.0.0',
          newVersion: '1.1.0',
        },
      ];

      mockGetPrUpdatesTable.mockReturnValue(
        '\n\nThis PR contains the following updates:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n\n',
      );

      createUpdatesTable(config, upgrade, packages);

      expect(config.prHeader).toBe(
        'This PR contains the following updates:\n\nFile package.spec:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n\n',
      );
    });

    it('should remove duplicate "This PR contains" text from existing prHeader', () => {
      const config: any = {
        branchName: 'test-branch',
        manager: 'rpm',
        prHeader:
          'Some content\n\nThis PR contains the following updates:\n\nExisting table here',
      };
      const upgrade: any = {
        packageFile: 'package.spec',
      };
      const packages = [
        {
          depName: 'pkg1',
          currentVersion: '1.0.0',
          newVersion: '1.1.0',
        },
      ];

      mockGetPrUpdatesTable.mockReturnValue(
        '\n\nThis PR contains the following updates:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n\n',
      );

      createUpdatesTable(config, upgrade, packages);

      // The duplicate "This PR contains..." text should be removed from the table markdown
      expect(config.prHeader).toBe(
        'Some content\n\nThis PR contains the following updates:\n\nExisting table here\n\nFile package.spec:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n\n',
      );
    });

    it('should clean up prBodyTemplate by removing {{{table}}} placeholder', () => {
      const config: any = {
        branchName: 'test-branch',
        manager: 'rpm',
        prBodyTemplate:
          'Some content before\n\n{{{table}}}\n\nSome content after',
      };
      const upgrade: any = {
        packageFile: 'package.spec',
      };
      const packages = [
        {
          depName: 'pkg1',
          currentVersion: '1.0.0',
          newVersion: '1.1.0',
        },
      ];

      mockGetPrUpdatesTable.mockReturnValue(
        '\n\nThis PR contains the following updates:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n\n',
      );

      createUpdatesTable(config, upgrade, packages);

      expect(config.prBodyTemplate).toBe(
        'Some content before\n\n\n\nSome content after',
      );
    });

    it('should not modify prBodyTemplate if {{{table}}} is not present', () => {
      const config: any = {
        branchName: 'test-branch',
        manager: 'rpm',
        prBodyTemplate: 'Some content without table placeholder',
      };
      const upgrade: any = {
        packageFile: 'package.spec',
      };
      const packages = [
        {
          depName: 'pkg1',
          currentVersion: '1.0.0',
          newVersion: '1.1.0',
        },
      ];

      mockGetPrUpdatesTable.mockReturnValue(
        '\n\nThis PR contains the following updates:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n\n',
      );

      createUpdatesTable(config, upgrade, packages);

      expect(config.prBodyTemplate).toBe(
        'Some content without table placeholder',
      );
    });

    it('should handle packages with mixed version presence correctly', () => {
      const config: any = {
        branchName: 'test-branch',
        manager: 'rpm',
      };
      const upgrade: any = {
        packageFile: 'package.spec',
      };
      const packages = [
        {
          depName: 'pkg1',
          currentVersion: '1.0.0',
          newVersion: '1.1.0',
        },
        {
          depName: 'pkg2',
          currentVersion: '2.0.0',
          // no newVersion - should be filtered out
        },
        {
          depName: 'pkg3',
          // no currentVersion - should be filtered out
          newVersion: '3.1.0',
        },
        {
          depName: 'pkg4',
          currentVersion: '4.0.0',
          newVersion: '4.0.0', // same version - should be filtered out
        },
        {
          depName: 'pkg5',
          currentVersion: '5.0.0',
          newVersion: '5.1.0',
        },
      ];

      mockGetPrUpdatesTable.mockReturnValue(
        '\n\nThis PR contains the following updates:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n| pkg5 | `5.0.0` -> `5.1.0` |\n\n',
      );

      createUpdatesTable(config, upgrade, packages);

      expect(mockGetPrUpdatesTable).toHaveBeenCalledWith({
        manager: 'rpm',
        branchName: 'test-branch',
        baseBranch: undefined,
        prBodyColumns: ['Package', 'Change'],
        upgrades: [
          {
            manager: 'rpm-lockfile',
            branchName: 'test-branch',
            depName: 'pkg1',
            depNameLinked: 'pkg1',
            displayFrom: '1.0.0',
            displayTo: '1.1.0',
            prBodyDefinitions: {
              Package: '{{{depNameLinked}}}',
              Change: '`{{{displayFrom}}}` -> `{{{displayTo}}}`',
            },
          },
          {
            manager: 'rpm-lockfile',
            branchName: 'test-branch',
            depName: 'pkg5',
            depNameLinked: 'pkg5',
            displayFrom: '5.0.0',
            displayTo: '5.1.0',
            prBodyDefinitions: {
              Package: '{{{depNameLinked}}}',
              Change: '`{{{displayFrom}}}` -> `{{{displayTo}}}`',
            },
          },
        ],
      });
    });

    it('should copy config properties to dummy branch config', () => {
      const config: any = {
        branchName: 'test-branch',
        manager: 'rpm',
        baseBranch: 'main',
      };
      const upgrade: any = {
        packageFile: 'package.spec',
      };
      const packages = [
        {
          depName: 'pkg1',
          currentVersion: '1.0.0',
          newVersion: '1.1.0',
        },
      ];

      mockGetPrUpdatesTable.mockReturnValue(
        '\n\nThis PR contains the following updates:\n\n| Package | Change |\n|---|---|\n| pkg1 | `1.0.0` -> `1.1.0` |\n\n',
      );

      createUpdatesTable(config, upgrade, packages);

      expect(mockGetPrUpdatesTable).toHaveBeenCalledWith(
        expect.objectContaining({
          manager: 'rpm',
          branchName: 'test-branch',
          baseBranch: 'main',
          prBodyColumns: ['Package', 'Change'],
        }),
      );
    });
  });
});
