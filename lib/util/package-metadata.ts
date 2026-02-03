/**
 * Serializes packageMetadata to a deterministic string for use in keys.
 * Returns empty string if metadata is undefined or empty.
 * @throws {Error} if any value in metadata is not a string
 */
export function serializePackageMetadata(
  metadata: Record<string, string> | undefined,
): string {
  if (!metadata || Object.keys(metadata).length === 0) {
    return '';
  }
  // Validate all values are strings
  for (const [key, value] of Object.entries(metadata)) {
    if (typeof value !== 'string') {
      throw new Error(
        `packageMetadata value for key "${key}" must be a string, got ${typeof value}`,
      );
    }
  }
  const sortedKeys = Object.keys(metadata).sort();
  const sortedObj = Object.fromEntries(sortedKeys.map((k) => [k, metadata[k]]));
  return JSON.stringify(sortedObj);
}

/**
 * Creates an upgrade key that includes packageMetadata when present.
 */
export function createUpgradeKey(
  packageFile: string,
  depName: string,
  currentValue: string,
  packageMetadata: Record<string, string> | undefined,
): string {
  const baseKey = `${packageFile}:${depName}:${currentValue}`;
  const metadataStr = serializePackageMetadata(packageMetadata);
  return metadataStr ? `${baseKey}:${metadataStr}` : baseKey;
}
