# Revision-bound resource export

The native control API can export a complete four-document snapshot and its
immutable resources without giving a client filesystem access to a privileged
daemon. These methods use the same authenticated control owner as configuration
reads and writes. Neither method accepts a filesystem path.

## Manifest

`ExportManifest` accepts `base_revision` (optional; zero selects the currently
active revision) and `reveal` (default false). It returns:

- `schema_version`, `revision` and `masked` count;
- `profile`, `local`, `sources` and `overlay`, captured consistently;
- `resources`, an ordered, deduplicated list of `{hash, size}`.

Inline configuration credentials are masked unless `reveal: true` is explicit.
Secret-store contents are never exported; a `secret://` reference still requires
its matching destination secret store after restoration. Original subscription
and provider resource bodies may themselves contain credentials, so even a
masked manifest must not be treated as permission to download those bodies.

The reference set includes native profile/source rule sets, source lock root
and provider/geodata resources, and rule-set hashes introduced by overlay set
or insert operations. Orphan staged blobs, unrelated resources from older
revisions and arbitrary paths are excluded. A resource still mentioned in an
active source document remains included even if that source is not imported.

Export checks the referenced content hashes and rejects missing or corrupt
resources. A manifest is bounded to 1024 resources, 128 MiB of total resource
bytes and 15 MiB of serialized manifest JSON. Oversized exports return a clear
`blocked` error rather than an incomplete backup or oversized protocol frame.

## Chunks

`ReadResource` requires:

```json
{
  "base_revision": 12,
  "hash": "<64 lowercase hex SHA-256 characters>",
  "offset": 0,
  "limit": 1048576,
  "reveal": true
}
```

`base_revision` must be nonzero and still active. `limit` is at most 1 MiB; zero
selects the default 1 MiB chunk. `offset` must lie between zero and resource
size, inclusive. The response contains `revision`, `hash`, `offset`, `size`,
base64 `data` and `eof`. Every read verifies the full immutable resource hash;
clients should also check the completed hash and size before writing a backup.

A stale revision returns `conflict`. The caller must discard the partial
snapshot and start with a new manifest. It must not combine documents or
resources from different revisions. No revision pin or persistent export
session is created, and no archive data is retained by the daemon.

Resources larger than 16 MiB, nonregular files, corrupt blobs and symlinks are
rejected. Unix reads traverse descriptor-relative resource directories with
`O_NOFOLLOW`; Windows rejects reparse files and checks resource directories.
Reads do not follow an arbitrary user-supplied path into the daemon's root
filesystem.

Restoration can upload resource bytes through `StageResource` before submitting
the four native documents in the normal validate/plan/commit transaction.
Clients should explicitly disable local network takeover before restoring a
backup onto another machine.
