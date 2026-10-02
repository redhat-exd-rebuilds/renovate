import type { Category } from '../../../constants/category.ts';
import { RpmDatasource } from '../../datasource/rpm/index.ts';

export { updateArtifacts } from './artifacts.ts';
export { extractPackageFile } from './extract.ts';

export const supportsLockFileMaintenance = true;
export const lockFileMaintenanceIsDelegatedToPackageManager = true;

export const supportedDatasources = [RpmDatasource.id];

export const lockFileNames = ['rpms.lock.yaml', 'rpms.lock.yml'];

export const defaultConfig = {
  managerFilePatterns: ['/(^|/)(rpms\\.in\\.ya?ml)$/'],
  lockFileMaintenance: {
    branchTopic: 'rpm-lockfile-refresh',
    commitMessageAction: 'Refresh RPM lockfiles',
  },
};

export const categories: Category[] = ['rpm'];
