# Subscription account usage

`ListSubscriptions` and refresh results optionally return `usage`, parsed only
from the root subscription's HTTP `Subscription-Userinfo` response header.
Provider-resource headers cannot replace account usage. These are the service
provider's account counters; they are independent of Reka's local traffic.

```json
{
  "usage": {
    "upload": 1048576,
    "download": 2097152,
    "total": 10737418240,
    "expire_unix": 1893456000,
    "observed_at": "2026-11-16T00:00:00Z"
  }
}
```

Upload/download/total are unsigned 64-bit byte counts. Expire is an unsigned
Unix timestamp in seconds, bounded to year 9999. Missing fields are omitted,
not converted to zero. Explicit `total=0` means that the provider did not set a
quota; clients must not infer unlimited entitlement. `expire=0` means no expiry
was set by the provider, while an omitted expiry remains unknown.

The header uses semicolon-separated `key=value` tokens with optional spaces;
known keys are case-insensitive. Only plain decimal unsigned integers are
accepted. Negative/fractional/overflow values, duplicate known keys (including
identical duplicates across multiple header lines), and invalid expiry values
make that field unknown. `invalid_fields` lists only affected field names, never
header contents or subscription credentials. Unknown keys are ignored. Metadata
larger than 8192 bytes is ignored with `invalid_fields: ["header"]`. Invalid
account metadata never rejects otherwise valid subscription nodes.

A successful HTTP 200 replaces the account declaration, so omitted values
become unknown. A 304 preserves previously observed fields omitted from its
header and can update fields it supplies; explicitly invalid supplied fields
become unknown. A 304 without known metadata preserves the previous observation
timestamp. A failed fetch, conversion or commit retains the last successful
usage and marks the subscription stale. Usage is persisted in the subscription
refresh record and survives process restart. Replacing the subscription spec
marks retained usage stale until a successful refresh.

The macOS subscription card displays used/remaining usage only when both
upload and download are known, bounds progress to 0–100%, distinguishes unknown
from unset quota/expiry, and labels retained stale values as last-success data.
