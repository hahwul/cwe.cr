+++
title = "cwe.cr"
description = "A Crystal implementation of the MITRE CWE (Common Weakness Enumeration)"
+++

A Crystal library that embeds the **full MITRE CWE catalog** at compile time
and exposes lookup, search, relationship traversal, and JSON serialization.
No network access. No sidecar data files.

| Entity     | Count | Source                                |
|------------|-------|---------------------------------------|
| Weaknesses | 944   | MITRE CSV (view 1000, Research)       |
| Categories | 422   | MITRE XML (`<Category>` entries)      |
| Views      | 59    | MITRE XML (`<View>` entries)          |

## Quick Links

- **[Getting Started](/user-guide/getting-started/)** — installation and first lookup
- **[Lookups](/user-guide/lookups/)** — `CWE.find`, `find!`, indexing, parse_id
- **[Relationships](/user-guide/relationships/)** — parents / children / ancestors / pillar walk
- **[Search & Filters](/user-guide/search-and-filters/)** — full-text & abstraction/status filters
- **[Categories & Views](/user-guide/categories-and-views/)** — beyond Weaknesses
- **[JSON Output](/user-guide/json-output/)** — camelCase serialization shape
- **[API Reference](/api-reference/module/)** — every class and method

## Highlights

- Embedded MITRE catalog v4.20 — 944 Weaknesses, 422 Categories, 59 Views.
- O(1) lookups and O(children) relationship traversal via a pre-built children index.
- Tolerant id parsing — `79`, `"79"`, `"CWE-79"`, `"cwe-79"`, `"CWE_79"`, `"CWE:79"`.
- Rich data per entry: description, consequences, mitigations, detection methods, observed CVEs, OWASP/CAPEC mappings, applicable platforms, alternate terms.
- View-filtered hierarchy walks — restrict to view 1000 (Research) or 1003 (Simplified Mapping).
- Thread-safe lazy initialization of the default catalog.
- camelCase JSON output throughout, suitable for SBOM / SARIF interop.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  cwe:
    github: hahwul/cwe.cr
```

Then run:

```bash
shards install
```

## Quick Example

```crystal
require "cwe"

w = CWE.find!("CWE-79")
w.name        # => "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
w.abstraction # => CWE::Abstraction::Base
w.status      # => CWE::Status::Stable
w.url         # => "https://cwe.mitre.org/data/definitions/79.html"

w.common_consequences.first.scope # => "Confidentiality"
w.parent_relations.map(&.cwe_id).uniq # => [74]
CWE.pillar_of(79).try(&.cwe_id)       # => "CWE-707"
```
