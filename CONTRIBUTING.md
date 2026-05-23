# Contributing

Thanks for your interest in cwe.cr.

## Local development

```sh
shards install
crystal spec                # 79 examples
crystal tool format --check
```

Run an example end-to-end:

```sh
crystal run examples/basic.cr
```

## Submitting changes

1. Fork the repository and create a branch.
2. Add or update specs under `spec/` for any code change.
3. Make sure `crystal spec` and `crystal tool format --check` pass — CI runs both.
4. Open a pull request describing the change and linking to the relevant CWE entry on [cwe.mitre.org](https://cwe.mitre.org) if applicable.

## Reporting issues

Please open an issue with:

- The CWE ID (any of `CWE-79`, `"79"`, `79`, `"cwe-79"`) that triggers the problem.
- The expected result (with a link to the relevant section on cwe.mitre.org if possible).
- The result cwe.cr returned.

## Embedded catalog

cwe.cr embeds the MITRE CWE Research view (view 1000) at compile time from
`src/cwe/data/weaknesses.json`. When MITRE publishes a new catalog version,
regenerate this file rather than editing it by hand.
