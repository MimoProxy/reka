# Reference differential harness

This separate Go module pins mihomo v1.19.34. It is a development tool and is not linked into Reka's product binaries. From this directory:

```sh
go run .
```

The process compares ordered rule actions and DNS call counts for 14 cases, plus deterministic observed url-test/fallback/manual choices with controlled health. A mismatch exits nonzero. This is a focused differential suite, not an exhaustive compatibility assertion; known differences are listed in the DNS, automatic-group and Clash import documents.
