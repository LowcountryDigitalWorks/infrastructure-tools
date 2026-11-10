# REDRIX A4 root issuer trust model

**Status: SYNTHETIC SOURCE MODEL / DATA ONLY / NOT AUTHORIZED / NO ROOT ISSUER INSTALLED**

This fixture model specifies a future fixed Linux package root at `/usr/libexec/ldw-redrix-a4`. It accepts only immutable evidence objects in memory. It does not inspect the host filesystem, invoke code, open sockets, read `/proc`, alter privilege, or produce a trusted runtime result.

## Modeled checks

- Fixed `/`, `/usr`, `/usr/libexec`, and package-root ancestry; root owner/group, exact directory mode, no writable ancestors or symlinks.
- Fixed launcher, inspector, and existing UID-1000 verifier package paths with root ownership/group, exact non-writable mode, one link, and stable device/inode/mode/owner/group/link-count identity across descriptor-before, descriptor-after, and path-after observations. Cross-device package ancestry and inode collisions are refused.
- Separate source-constant Git blob and SHA-256 pins compared with file evidence; manifest claims cannot override those constants.
- Synthetic post-privilege launcher-created channel evidence, distinct receive/send endpoints and unique peer credentials, receiver-measured executable provenance, pidfd/starttime stability, user/PID/mount namespace equality, short monotonic TTL, single-use/replay and sequence checks.
- Caller-selected program/arguments/environment, preopened/inherited/duplicate endpoints, peer UID 0 without pinned executable evidence, and self-asserted `root`/`signature`/authentication claims fail closed.

The hashes in `SYNTHETIC_PIN_FIXTURE` are deliberately fake test constants. They are not hashes of deployed bytes and confer no authority. Even fully matching evidence returns `DATA_ONLY_NOT_AUTHORIZED`; every A4, channel-authentication, runtime-authority, and JIT flag remains false. Synthetic metadata does not model a real socket, kernel peer credentials, pidfd, executable measurement, nonce entropy or durable replay store.

## Separate future gates

A distinct owner/security-approved implementation would still need a fixed immutable root-owned installer and launcher, protected source pin publication and physical byte readback, a real one-shot channel created after privilege with receiver-measured executable provenance, rollback/teardown proof, and independent complete two-snapshot `/proc` FD evidence under reviewed capability and LSM policy. Peer UID 0 is insufficient. This Linux trust domain is separate from Windows Admin Broker #186. The accepted UID-1000 A0/A4 entrypoints, policy thresholds, host, CI controllers, provider, and runner are unchanged.
