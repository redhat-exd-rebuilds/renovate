import { RedHatRPMLockfile } from '../../../../modules/manager/rpm/schema';
import { parseSingleYaml } from '../../../../util/yaml';
import { RpmVulnerabilities } from '../../process/rpm-vulnerabilities';
import {
  applyVulnerabilityPRNotes,
  createVulnerabilities,
  getUpgrade,
  parseLockfilePackages,
  postProcessRPMs,
} from './rpm-post-processing';

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
    });
  });
});
