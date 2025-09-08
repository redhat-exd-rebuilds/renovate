import type { Category } from '../../../constants';
import { RpmDatasource } from '../../datasource/rpm';

export { updateArtifacts } from './artifacts';
export { extractPackageFile } from './extract';

export const supportsLockFileMaintenance = true;

export const supportedDatasources = [RpmDatasource.id];

export const defaultConfig = {
  managerFilePatterns: ['/(^|/)(rpms\\.in\\.ya?ml)$/'],
  lockFileMaintenance: {
    commitMessageAction: 'Refresh RPM lockfiles',
  },
};

export const categories: Category[] = ['rpm'];
