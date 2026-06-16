import type { Osv } from '@mintmaker/osv-offline';
import type { RenovateConfig } from '../../../config/types.ts';
import type { PackageFile } from '../../../modules/manager/types.ts';
import type { VersioningApi } from '../../../modules/versioning/index.ts';

export interface Vulnerability {
  packageFileConfig: RenovateConfig & PackageFile;
  packageName: string;
  osvPackageName: string;
  depVersion: string;
  fixedVersion: string | null;
  datasource: string;
  vulnerability: Osv.Vulnerability;
  affected: Osv.Affected;
}

export interface ContainerVulnerability {
  config: RenovateConfig & PackageFile;
  oldDigest: string;
  newDigest: string;
  depName: string;
  vulnerability: Osv.Vulnerability;
  datasource: string;
}

export interface DependencyVulnerabilities {
  versioningApi: VersioningApi;
  vulnerabilities: Vulnerability[];
}

export interface SeverityDetails {
  cvssVector: string;
  score: string;
  severityLevel: string;
}
