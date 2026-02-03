import { dirname, join } from 'upath';
import { logger } from '../../../logger';
import { exec } from '../../../util/exec';
import { readLocalFile } from '../../../util/fs';
import { parseSingleYaml } from '../../../util/yaml';
import type { ExtractConfig, PackageFile, PackageFileContent } from '../types';
import {
  clearCachesIfNewRepository,
  setDetectedUpdate,
  setNewLockFileContent,
  setOriginalInputFileContent,
} from './common';
import type { RpmLockfile } from './types';

interface PackageUpdate {
  name: string;
  currentEvr: string;
  newEvr: string;
}

function parseLockFile(content: string): RpmLockfile | null {
  try {
    return parseSingleYaml<RpmLockfile>(content);
  } catch {
    return null;
  }
}

function extractPackagesFromLockfile(
  lockfile: RpmLockfile,
): Map<string, string> {
  const packages = new Map<string, string>();

  for (const arch of lockfile.arches ?? []) {
    for (const pkg of arch.packages ?? []) {
      // Only use first occurrence (skip if already seen from another arch)
      if (!packages.has(pkg.name)) {
        packages.set(pkg.name, pkg.evr);
      }
    }
  }

  return packages;
}

function detectUpdates(
  oldPackages: Map<string, string>,
  newPackages: Map<string, string>,
): PackageUpdate[] {
  const updates: PackageUpdate[] = [];

  for (const [name, newEvr] of newPackages) {
    const currentEvr = oldPackages.get(name);
    if (currentEvr && currentEvr !== newEvr) {
      updates.push({ name, currentEvr, newEvr });
    }
  }

  return updates;
}

export async function extractAllPackageFiles(
  config: ExtractConfig,
  packageFiles: string[],
): Promise<PackageFile[] | null> {
  // Clear caches if this is a new repository (prevents cross-repo contamination)
  // Caches persist across all baseBranches within the same repository because:
  // 1. All baseBranches are extracted first
  // 2. Then datasource lookups happen (needs detectedUpdates)
  // 3. Then updateArtifacts() is called (needs newLockFileCache and originalInputFileCache)
  clearCachesIfNewRepository(config.repository);

  logger.debug(
    { packageFiles },
    'rpm-lockfile.extractAllPackageFiles() - processing files',
  );

  const results: PackageFile[] = [];

  for (const packageFileName of packageFiles) {
    logger.debug({ packageFileName }, 'Processing rpm-lockfile input file');
    const result = await extractSinglePackageFile(
      packageFileName,
      config.baseBranch,
    );
    if (result) {
      results.push({
        ...result,
        packageFile: packageFileName,
      });
    }
  }

  logger.debug(
    { count: results.length },
    'rpm-lockfile.extractAllPackageFiles() - completed',
  );

  return results.length ? results : null;
}

async function extractSinglePackageFile(
  packageFileName: string,
  baseBranch?: string,
): Promise<PackageFileContent | null> {
  logger.debug(
    { packageFileName, baseBranch },
    'rpm-lockfile.extractPackageFile()',
  );

  // packageFileName is the input file (rpms.in.yaml or rpms.in.yml)
  const dir = dirname(packageFileName);
  const lockFileName = dir ? join(dir, 'rpms.lock.yaml') : 'rpms.lock.yaml';
  const inputFileName = packageFileName.split('/').pop()!;

  logger.debug(
    { packageFileName, lockFileName, inputFileName, dir, baseBranch },
    'rpm-lockfile paths',
  );

  // Read and cache the original input file content for later restoration
  const originalInputContent = await readLocalFile(packageFileName, 'utf8');
  if (originalInputContent) {
    setOriginalInputFileContent(packageFileName, originalInputContent);
  }

  // Read current lock file
  const currentLockContent = await readLocalFile(lockFileName, 'utf8');
  if (!currentLockContent) {
    logger.debug(
      { packageFileName, lockFileName },
      'No lock file found for rpm-lockfile input file',
    );
    return null;
  }

  const currentLockfile = parseLockFile(currentLockContent);
  if (!currentLockfile?.arches?.length) {
    logger.debug({ lockFileName }, 'No arches found in current rpm-lockfile');
    return null;
  }

  const currentPackages = extractPackagesFromLockfile(currentLockfile);
  if (!currentPackages.size) {
    logger.debug({ packageFileName }, 'No packages found in rpm-lockfile');
    return null;
  }

  logger.debug(
    { packageFileName, packageCount: currentPackages.size },
    'Found packages in lock file',
  );

  // Run caching-rpm-lockfile-prototype to generate new lock file and detect updates
  let updates: PackageUpdate[] = [];

  try {
    logger.debug(
      { command: `caching-rpm-lockfile-prototype ${inputFileName}`, cwd: dir },
      'Running caching-rpm-lockfile-prototype',
    );

    // Run the tool - it overwrites rpms.lock.yaml in place
    const execResult = await exec(
      `caching-rpm-lockfile-prototype ${inputFileName}`,
      {
        cwdFile: packageFileName,
      },
    );

    logger.debug({ execResult }, 'caching-rpm-lockfile-prototype completed');

    // Read the newly generated lock file
    const newLockContent = await readLocalFile(lockFileName, 'utf8');
    if (newLockContent) {
      const newLockfile = parseLockFile(newLockContent);
      if (newLockfile) {
        const newPackages = extractPackagesFromLockfile(newLockfile);
        updates = detectUpdates(currentPackages, newPackages);

        logger.debug(
          { lockFileName, updateCount: updates.length },
          'Detected updates in lock file',
        );

        // Cache the new lock file content and updates for later use
        if (updates.length) {
          setNewLockFileContent(lockFileName, newLockContent);
          for (const update of updates) {
            setDetectedUpdate(
              lockFileName,
              update.name,
              update.newEvr,
              baseBranch,
            );
            logger.debug(
              {
                lockFileName,
                baseBranch,
                package: update.name,
                from: update.currentEvr,
                to: update.newEvr,
              },
              'Package update detected',
            );
          }
        }
      }
    }
  } catch (err) {
    logger.warn(
      { err, packageFileName },
      'caching-rpm-lockfile-prototype failed',
    );
    // Continue without updates - still return current packages
  }

  // Build deps list
  const deps: PackageFileContent['deps'] = [];

  for (const [name, evr] of currentPackages) {
    deps.push({
      depName: name,
      currentValue: evr,
      datasource: 'rpm-lockfile',
      // Pass lockFile via registryUrls so datasource can find detected updates
      registryUrls: [lockFileName],
      packageMetadata: {
        lockFile: lockFileName,
        ...(baseBranch && { baseBranch }),
      },
    });
  }

  return {
    deps,
    lockFiles: [lockFileName],
  };
}
