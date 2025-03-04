The `rpm` manager works differently from the rest, since the RPM ecosystem
isn't built on package files and lock files.

The `fileMatch` for `rpm` is actually the lockfile (`rpms.lock.yaml`),
and not the package file (`rpms.in.yaml`) as one would expect.
This is because the package file doesn't specify RPM versions.

During the dependency extraction, a temporary lockfile is generated, named
`rpms.lock.tmp.yaml`. This serves as a fake datasource later.

The dependencies are extracted from the lockfile, not from the package file,
because again, that's where the version numbers are. These dependencies
are later compared to the fake datasource (`rpms.lock.tmp.yaml`) so that
it is possible to generate a list of packages with their current version
and the new (available) version. This enables Renovate to display
a table with dependency updates and allows us to not rely on lockFileMaintenance.

However, it's currently not possible to update RPMs _individually_ due to
dependency resolution happening in `rpm-lockfile-prototype` script, which
doesn't support per-package updates. This is currently a limitation of the whole
RPM ecosystem.

Recommended `packageRules` configuration for the `rpm` manager:

```json
{
  "rpm": {
    "packageRules": [
      {
        "groupName": "RPM updates",
        "matchManagers": ["rpm"],
        "commitMessageAction": "",
        "commitMessageTopic": "RPM updates"
      }
    ],
    "vulnerabilityAlerts": {
      "branchTopic": "rpm-updates"
    },
    "lockFileMaintenance": {
      "enabled": false
    }
  }
}
```

This configuration ensures clean PR titles and commit messages.
If the updates are _not_ grouped, then each PR would contain a single
package in the description while updating the whole lockfile anyway.
`lockFileMaintenance` must be disabled so the PRs include CVE data.
