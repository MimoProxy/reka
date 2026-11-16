# Provider override expressions

This directory adapts the standalone expression evaluator from
[MetaCubeX/mihomo v1.19.34](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/adapter/provider/override_expr.go),
distributed under the [GNU GPL version 3 or later](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/LICENSE).
The repository root LICENSE supplies that license text.

Original source SHA-256: `7a4fcd857fb615660374d0d5e5ae870b328457bf25e4902287fdf9aa4d5ed5bc`.

Local changes: package renamed to `providerexpr`; the YAML forwarding wrapper
is replaced by its exact underlying `go.yaml.in/yaml/v3` dependency; attribution
is added; expression streams, array indexes, repeated strings and each statement output have explicit resource budgets; one nonconstant error-format call uses an explicit `%s` for current Go vet. The evaluator has no file, environment, process or network access.
Reka's provider layer validates the output again before creating a snapshot.
The corresponding-source archive includes this source and notice.
