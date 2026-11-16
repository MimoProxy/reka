# Owner and inbound routing

Reka supports native `process-path`, `process-path-regex`,
`process-name-wildcard`, `process-path-wildcard`, `in-name`, `in-type`,
`in-port`, `in-user` and `uid` conditions, including their uppercase Clash
forms. They participate in the same ordered, first-match rules, logical
conditions, sub-rules, classical rule sets and route explanations.

Process paths match the complete owner path; process names match its basename.
Exact and wildcard comparisons ignore case. Wildcards follow the pinned mihomo
v1.19.34 byte semantics: `*` matches any span, including path separators, and
`?` matches one byte. Regular expressions use .NET-compatible `regexp2`, ignore
case and have a 50 ms match budget. Unknown owners never match, including a
wildcard or regular expression that could otherwise match an empty string.

`in-name` matches an explicit local listener ID. `in-user` matches the username
authenticated by that listener. Both are case-sensitive. Slash-separated values
are alternatives. `in-type` uses the actual application protocol, such as
`HTTP`, `SOCKS4`, `SOCKS5` or `TUN`; `SOCKS` selects SOCKS4 and SOCKS5. A mixed
listener's protocol is determined per accepted connection. Unknown protocol or
unauthenticated users never match.

`in-port` matches the local proxy listener's port, independently from the
client's source port and destination port. TUN has no proxy listener port and
does not match this condition. `uid` matches the OS-reported owner UID, supplied
by supported platforms or the Android host. UID zero follows the pinned
reference's unknown-owner behavior and never matches. Ports and UIDs accept
single values, inclusive ranges and slash-separated alternatives, up to 28
ranges per expression. Reversed range endpoints are normalized; overflowing
values are rejected.

Local proxy authentication is configured explicitly in the native local layer:

```yaml
listeners:
  - id: authenticated
    type: mixed
    listen: 127.0.0.1:17890
    users:
      - username: Alice
        password: secret://listeners/authenticated/alice
```

The corresponding shared profile can route authenticated clients:

```yaml
schema-version: 1
rules:
  - match: {in-user: Alice}
    outbound: direct
  - match: {all: true}
    outbound: reject
```

An omitted or empty users list keeps an unauthenticated listener. Authentication
credentials are masked in API configuration reads, resolved through SecretStore
and included in the listener's private fingerprint. Changing authentication
restarts that listener, while already accepted connections keep their existing
route. A masked password cannot be reused after changing its username.
Subscription imports do not choose local listening ports or install users.

ASN, DSCP and source-geography predicates remain outside this increment.
