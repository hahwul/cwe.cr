# cwe.cr

A Crystal implementation of the [MITRE CWE](https://cwe.mitre.org/) (Common
Weakness Enumeration). The full CWE Research view (`view 1000`) is embedded at
compile time, so lookups, search, and relationship traversal need no network
access or sidecar data files.

```crystal
require "cwe"

w = CWE.find!("CWE-79")
w.name        # => "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
w.abstraction # => CWE::Abstraction::Base
w.status      # => CWE::Status::Stable
w.url         # => "https://cwe.mitre.org/data/definitions/79.html"

w.common_consequences.first.scope # => "Confidentiality"
w.potential_mitigations.size      # => 12
w.parent_relations.map(&.cwe_id)  # => [74, 74]
```

## Installation

Add to your `shard.yml`:

```yaml
dependencies:
  cwe:
    github: hahwul/cwe.cr
```

Then `shards install`.

## Usage

### Lookups

```crystal
CWE.find!("CWE-79")  # raises CWE::NotFoundError if missing
CWE.find(79)         # returns nil if missing
CWE[79]              # bang variant, same as find!
CWE[79]?             # nil variant, same as find
CWE.includes?("CWE-79") # => true
```

Any of these forms is accepted as an id: `79`, `"79"`, `"CWE-79"`, `"cwe-79"`,
`"CWE_79"`, `"CWE:79"`. Whitespace around the value is tolerated.

### Entry fields

Each `CWE::Weakness` exposes:

| field | type |
|---|---|
| `id`, `cwe_id`, `url` | `Int32`, `"CWE-79"`, `https://...` |
| `name` | `String` |
| `abstraction` | `CWE::Abstraction` (`Pillar`, `Class`, `Base`, `Variant`, `Compound`) |
| `status` | `CWE::Status` (`Stable`, `Draft`, `Incomplete`, `Deprecated`, …) |
| `description`, `extended_description` | `String?` |
| `likelihood_of_exploit` | `String?` |
| `related_weaknesses` | `Array(CWE::Related)` — `ChildOf` / `ParentOf` / `PeerOf` / `CanPrecede` / `CanFollow` |
| `common_consequences` | `Array(CWE::Consequence)` — scope + impact + note |
| `potential_mitigations` | `Array(CWE::Mitigation)` — phase + strategy + description |
| `detection_methods` | `Array(CWE::DetectionMethod)` |
| `observed_examples` | `Array(CWE::ObservedExample)` — CVE references |
| `applicable_platforms` | `Array(CWE::ApplicablePlatform)` |
| `alternate_terms` | `Array(CWE::AlternateTerm)` |
| `modes_of_introduction` | `Array(CWE::ModeOfIntroduction)` |
| `taxonomy_mappings` | `Array(CWE::TaxonomyMapping)` — PLOVER, OWASP, CAPEC, … |
| `related_attack_patterns` | `Array(Int32)` — CAPEC ids |
| `notes` | `Array(CWE::Note)` |

### Walking the hierarchy

```crystal
CWE.parents_of(79)       # => [CWE-74]
CWE.children_of(79)      # => [CWE-80, CWE-81, CWE-83, CWE-84, CWE-85, CWE-86, CWE-87]
CWE.ancestors_of(79)     # nearest-first transitive closure
CWE.descendants_of(79)
CWE.pillar_of(79)        # => CWE-707

# All edges are O(1) lookups via a pre-built index. Pass view_id to restrict
# to a particular CWE view (1000 = Research, 1003 = Simplified Mapping):
CWE.parents_of(79, view_id: 1000)
```

### Search

```crystal
CWE.search_by_name("cross-site scripting") # name-only match
CWE.search("HttpOnly")                     # name + description + alternate terms
CWE.with_abstraction(CWE::Abstraction::Pillar)
CWE.with_status(CWE::Status::Stable)
```

### JSON

```crystal
require "json"

CWE.find!(79).to_json
# {
#   "id": 79,
#   "cweId": "CWE-79",
#   "name": "Improper Neutralization of Input During Web Page Generation (...)",
#   "abstraction": "Base",
#   "status": "Stable",
#   "commonConsequences": [...],
#   "potentialMitigations": [...],
#   ...
# }
```

### Categories and Views

`CWE` includes the full MITRE catalog — not just Weaknesses, but also
Categories (informal groupings, "Mapping Prohibited") and Views (slices of
the catalog organised around a stakeholder's perspective).

```crystal
CWE.category!(227)  # => CWE::Category: "7PK - API Abuse" (10 members)
CWE.view!(1000)     # => CWE::View: "Research Concepts" (Graph)
CWE.members_of(1000) # => Array(CWE::Weakness) — the resolved members

# Unified lookup when you don't know which kind of entity an id refers to:
CWE.entry(79)    # => Weakness
CWE.entry(227)   # => Category
CWE.entry(1000)  # => View
CWE.entry(99999) # => nil
```

### Catalog metadata

```crystal
CWE.catalog_version # => "4.20"
CWE.size            # => 944  (weaknesses)
CWE.categories.size # => 422
CWE.views.size      # => 59
```

## Examples

Runnable scripts under [`examples/`](./examples):

- [`basic.cr`](./examples/basic.cr) — lookups & id parsing
- [`details.cr`](./examples/details.cr) — consequences, mitigations, CVEs
- [`relationships.cr`](./examples/relationships.cr) — parent/child traversal
- [`search.cr`](./examples/search.cr) — full-text & filtered queries
- [`json_output.cr`](./examples/json_output.cr) — JSON serialization

```sh
crystal run examples/basic.cr
```

## Development

Run the test suite:

```sh
crystal spec
```

Regenerate the embedded data blob from a fresh MITRE CWE export:

```sh
# Drop the new CSV at data/cwec.csv (MITRE "view 1000"), then:
crystal run data/build_data.cr
crystal spec
```

The embedded data lives at `src/cwe/data/weaknesses.json` and is read into
the binary at compile time via `{{ read_file(...) }}`.

## License

MIT © [hahwul](https://github.com/hahwul)

This library redistributes data from the
[MITRE Common Weakness Enumeration](https://cwe.mitre.org/), which is
released under MITRE's terms of use. CWE™ is a trademark of The MITRE
Corporation.
