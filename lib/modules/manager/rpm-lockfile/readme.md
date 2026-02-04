This manager updates RPM lockfiles based on the input file.

The special attribute of this manager is that it only supports LockFileMaintenance, there is no operation to update the RPM input file.

By default, it extracts input file with the name `rpms.in.yaml` with any path prefix and expects the lockfile to be called `rpms.lock.yaml` and be in the same directory.

This manager uses the 3rd party tool `rpm-lockfile-prototype` to perform the new lockfile generation.
