export interface RpmPackage {
  url: string;
  repoid: string;
  size: number;
  checksum: string;
  name: string;
  evr: string;
  sourcerpm: string;
}

export interface RpmArch {
  arch: string;
  packages: RpmPackage[];
  source: unknown[];
  module_metadata: unknown[];
}

export interface RpmLockfile {
  lockfileVersion: number;
  lockfileVendor: string;
  arches: RpmArch[];
}

export interface RpmInputFile {
  contentOrigin?: {
    repofiles?: string[];
  };
  packages?: string[];
  context?: Record<string, unknown>;
}
