import { RedHatRPMLockfile } from '../../../../modules/manager/rpm/schema';
import { parseSingleYaml } from '../../../../util/yaml';
import { RpmVulnerabilities } from '../../process/rpm-vulnerabilities';
import {
  applyVulnerabilityPRNotes,
  createVulnerabilities,
  parseLockfilePackages,
  postProcessRPMVulnerabilities,
} from './rpm-vuln-post-processing';

describe('workers/repository/update/branch/rpm-vuln-post-processing', () => {
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
    it('appends notes to config and first upgrade', () => {
      const rpmVulns: Partial<RpmVulnerabilities> = {
        generatePrBodyNotes: vi.fn().mockReturnValue(['note-a', 'note-b']),
      } as any;

      const config: any = {
        upgrades: [{ prBodyNotes: ['existing'] }],
      };

      const vulnerabilities: any[] = [
        { vulnerability: { id: 'A' }, affected: {} },
        { vulnerability: { id: 'B' }, affected: {} },
      ];

      applyVulnerabilityPRNotes(
        vulnerabilities as any,
        config,
        rpmVulns as any,
      );

      expect(config.prBodyNotes).toEqual([
        'note-a',
        'note-b',
        'note-a',
        'note-b',
      ]);
      expect(config.upgrades[0].prBodyNotes).toEqual([
        'existing',
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
        upgrades: [{ prBodyNotes: new Array(9).fill('e') }],
      };
      const vulnerabilities: any[] = [
        { vulnerability: { id: 'A' }, affected: {} },
        { vulnerability: { id: 'B' }, affected: {} },
      ];

      applyVulnerabilityPRNotes(
        vulnerabilities as any,
        config,
        rpmVulns as any,
      );

      // called twice, with truncated true and isFirst flag as false
      expect(gen).toHaveBeenCalledTimes(2);
      const args = gen.mock.calls[0];
      expect(args[2]).toBe(true);
      expect(args[3]).toBe(false);
    });
  });

  describe('postProcessRPMVulnerabilities()', () => {
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
      const res = await postProcessRPMVulnerabilities(null, cfg);
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
      const res = await postProcessRPMVulnerabilities(results as any, cfg);
      expect(res).toBeNull();
    });

    it('returns null when no vulnerabilities found', async () => {
      const fake: Partial<RpmVulnerabilities> = {
        fetchDependencyVulnerability: vi.fn().mockResolvedValue(null),
        generatePrBodyNotes: vi.fn().mockReturnValue([]),
      } as any;
      vi.spyOn(RpmVulnerabilities, 'create').mockResolvedValue(fake as any);

      const cfg: any = { upgrades: [{}] };
      const results = buildLockfileResult('1.0', '1.1');
      const res = await postProcessRPMVulnerabilities(results as any, cfg);
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

      const cfg: any = { upgrades: [{}] };
      const results = buildLockfileResult('1.0', '1.1');
      const res = await postProcessRPMVulnerabilities(results as any, cfg);
      expect(res).toBe(results as any);
      expect(cfg.prBodyNotes).toEqual(['note', 'note']);
      expect(cfg.upgrades[0].prBodyNotes).toEqual(['note', 'note']);
    });
  });
});
