// Shared state between extract and datasource

// Map of "baseBranch:lockFile:packageName" -> newVersion
const detectedUpdates = new Map<string, string>();

// Map of lockFile -> new lock file content
const newLockFileCache = new Map<string, string>();

// Map of packageFile -> original content (for restoring after update)
const originalInputFileCache = new Map<string, string>();

// Track current repository to clear caches when moving to a new repository
let currentRepository: string | undefined;

export function setDetectedUpdate(
  lockFile: string,
  packageName: string,
  newVersion: string,
  baseBranch?: string,
): void {
  const key = baseBranch
    ? `${baseBranch}:${lockFile}:${packageName}`
    : `${lockFile}:${packageName}`;
  detectedUpdates.set(key, newVersion);
}

export function getDetectedUpdate(
  lockFile: string,
  packageName: string,
  baseBranch?: string,
): string | undefined {
  const key = baseBranch
    ? `${baseBranch}:${lockFile}:${packageName}`
    : `${lockFile}:${packageName}`;
  return detectedUpdates.get(key);
}

export function clearDetectedUpdates(): void {
  detectedUpdates.clear();
}

export function setNewLockFileContent(lockFile: string, content: string): void {
  newLockFileCache.set(lockFile, content);
}

export function getNewLockFileContent(lockFile: string): string | undefined {
  return newLockFileCache.get(lockFile);
}

export function clearNewLockFileCache(): void {
  newLockFileCache.clear();
}

export function setOriginalInputFileContent(
  packageFile: string,
  content: string,
): void {
  originalInputFileCache.set(packageFile, content);
}

export function getOriginalInputFileContent(
  packageFile: string,
): string | undefined {
  return originalInputFileCache.get(packageFile);
}

export function clearOriginalInputFileCache(): void {
  originalInputFileCache.clear();
}

export function clearCachesIfNewRepository(
  repository: string | undefined,
): void {
  // Clear all caches when moving to a new repository to prevent contamination
  if (repository !== currentRepository) {
    clearDetectedUpdates();
    clearNewLockFileCache();
    clearOriginalInputFileCache();
    currentRepository = repository;
  }
}
