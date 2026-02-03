import is from '@sindresorhus/is';
import type { PackageRule, PackageRuleInputConfig } from '../../config/types';
import { Matcher } from './base';

export class PackageMetadataMatcher extends Matcher {
  override matches(
    { packageMetadata }: PackageRuleInputConfig,
    { matchPackageMetadata }: PackageRule,
  ): boolean | null {
    if (is.undefined(matchPackageMetadata)) {
      return null;
    }
    if (Object.keys(matchPackageMetadata).length === 0) {
      return null;
    }
    if (is.undefined(packageMetadata)) {
      return false;
    }
    for (const [key, value] of Object.entries(matchPackageMetadata)) {
      if (packageMetadata[key] !== value) {
        return false;
      }
    }
    return true;
  }
}
