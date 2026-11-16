# Atomic profile workspace

The macOS companion opts into a trusted workspace at daemon startup. Existing
single-profile and mobile callers keep their existing behavior. Example:

```sh
reka -profile-root /private/profile-workspace -profile-id alpha \
  -state-root /private/profile-workspace/alpha -edit-dir - -defer-network
```

`-profile-state-subdir` selects `<workspace>/<id>/state` for the separate root
session host. IDs are restricted to 1–64 ASCII letters/digits, dots, underscores
and hyphens, beginning with a letter or digit. RPC never accepts a profile path.
The workspace and namespace directories must be owned by the daemon identity
and not writable by other users. A workspace lock excludes competing daemons.
The privileged host also holds its own workspace lock before creating sockets.

## Control operations

- `GetProfileState {profile_id?: target}` returns `enabled`, `profile_id`,
  `profile_epoch`, `revision`, `runtime_profile`, and optional target metadata.
- `SwitchProfile {profile_id, base_profile, base_epoch, base_revision,
  operation_id, preserve_network, initial_profile?}` returns a durable operation
  result. The operation ID is idempotent, including rejected outcomes. Reusing
  it for different input is an error. Query `GetProfileSwitchOperation` with
  `operation_id` after a lost response; a historical committed result does not
  change the currently selected profile again. Reconcile `GetProfileState`.
- The request envelope may include `profile_id` and `profile_epoch`. Otherwise
  a connection is pinned by Hello. Old contexts reject calls even when the two
  profiles have the same revision. Hello and profile recovery queries are exempt.
- `DeleteInactiveProfile {profile_id, base_profile, base_epoch}` removes only
  an inactive namespace. The initial session namespace and runtime journal
  namespace remain locked until shutdown.

The server takes an exclusive profile gate, cancels and joins the old refresh
manager, then rechecks the base revision. It opens the target's own document,
resource and secret stores, compiles and prepares its effective configuration,
and records switch intent. Activation, the target active revision and the
workspace cursor precede publication to control readers. Pre-commit failure
restores the prior runtime, target active pointer and workspace cursor. A failed
rollback is explicitly marked degraded. Pending journals recover from the
confirmed cursor before another switch can advance its epoch.

`preserve_network: true` keeps the running takeover **mode**, using target local
settings for its other parameters. Any required mode change becomes a new
revision in the target's history. The target must support that mode; for example
TUN DNS hijacking requires a valid DNS configuration. New empty namespaces use
`initial_profile` (or the kernel default) and inherit only local machine settings.

The active cursor is authoritative on cold startup (`-profile-resume`, default
true in CLI); it must point to existing history. Cold startup can still use
`-defer-network`, independent of live switches. The `runtime_profile` anchors
Fake IP mappings and OS recovery journals for the session. Existing connections
and process traffic accounting remain with the runtime; they are not per-profile
configuration history. Changed takeover parameters can rebuild TUN and interrupt
its flows even though the kernel process stays alive.

## Full-history migration

`ExportProfileArchive {reveal: true, base_revision}` exports immutable history,
operation records, subscription validators and last-good usage. It returns an
`archive_hash` and hash/size descriptors for every referenced historic resource.
`ReadResource` requires the same revision, explicit reveal and `archive_hash`
capability for archive/historic blobs. Switching invalidates the capability.

Upload resource chunks into an inactive namespace with `StageResource`'s optional
body `profile_id`; the request envelope still identifies the active context.
Upload the archive into the active namespace, then call
`InstallProfile {profile_id, archive_hash}`. Installation validates document
hashes, locks and resource availability, writes the active pointer last, and
never overwrites an initialized namespace. It does not activate a generation.

For an initial root namespace, the session host copies only authenticated hash
blobs and passes `-profile-archive <hash>`. The GUI prepares this archive from the
quiesced user directory **after** the old daemon has stopped, preserving final
subscription commits. No arbitrary file path is accepted over the control API.
The old user directory stays intact. Once the root workspace runs, other user
profiles migrate into separate root namespaces before switching in the same PID.

Limits: 2,000 revisions, 10,000 operation records, 1,024 subscription records,
96 MiB of raw archive input, 128 MiB encoded archive or individual resource, and
512 MiB including all historic resources. Oversize or invalid migrations fail
without changing the active profile.

## Validation

`internal/daemon/profiles_test.go` covers same-engine switches, equal-revision
context fencing, independent history/selections, subscription cancellation,
archive migration and capabilities, idempotent retries, blocked listener rollback,
surviving SOCKS connections and interrupted switch recovery. The companion's
`ProfileSwitchingTests` exercise real IPC, GUI catalog rollback and full inactive
history import. `test-session-host.py` validates both legacy bootstrap and full
archive bootstrap with test-only private paths, workspace exclusion and process
watchdogs; it does not enable host TUN or system proxy.
