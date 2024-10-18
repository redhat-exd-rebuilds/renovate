import { Datasource } from "../datasource";
import { GetReleasesConfig, ReleaseResult } from "../types";
import { logger } from "../../../logger";
import { readLocalFile } from "../../../util/fs";
import { RedHatRPMLockfile } from '../../manager/rpm/schema';
import type { RedHatRPMLockfileDefinition } from '../../manager/rpm/schema';
import { parseSingleYaml } from '../../../util/yaml';

export class RPMLockfileDatasource extends Datasource {
  static readonly id = "rpm-lockfile";
  dependencyUpdateData: Map<string, string> = new Map();
  dependencyCheckInitiated = false;

  constructor() {
    super(RPMLockfileDatasource.id);
  }

  async loadUpdatedLockfile() {
    const newLockFileContent = await readLocalFile('rpms.lock.tmp.yaml', 'utf8');

    if (newLockFileContent == null) {
      logger.debug('New lockfile content is null');
      return;
    }

    let lockFile: RedHatRPMLockfileDefinition = parseSingleYaml(newLockFileContent, { customSchema: RedHatRPMLockfile });

    logger.debug(`Lock file version: ${lockFile.lockfileVersion}`);

    for (const dependency of lockFile.arches[0].packages) {
      this.dependencyUpdateData.set(dependency.name, dependency.evr);
    }

    logger.debug(`Number of RPM dependency updates found: ${this.dependencyUpdateData.size}`);
  }

  override async getReleases(getReleasesConfig: GetReleasesConfig): Promise<ReleaseResult | null> {
    if (!this.dependencyCheckInitiated) {
      await this.loadUpdatedLockfile();
      this.dependencyCheckInitiated = true;
    }

    let packageVersion = this.dependencyUpdateData.get(getReleasesConfig.packageName);

    if (packageVersion === undefined) {
      return null;
    }

    return {
      releases: [
        {
          version: packageVersion
        }
      ]
    };
  }
}
