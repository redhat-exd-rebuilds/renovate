import type { Category } from '../../../constants';
import { RpmLockfileDatasource } from '../../datasource/rpm-lockfile';

export { extractAllPackageFiles } from './extract';
export { updateArtifacts } from './artifacts';
export { updateDependency } from './update';

export const displayName = 'rpm-lockfile';
export const url = 'https://github.com/konflux-ci/rpm-lockfile-prototype';

export const categories: Category[] = ['rpm'];

export const defaultConfig = {
  managerFilePatterns: ['/rpms\\.in\\.ya?ml$/'],
  versioning: 'rpm',
};

export const supportedDatasources = [RpmLockfileDatasource.id];
