+++
title = "Weakness"
description = "CWE::Weakness — the primary catalog entry type"
weight = 2
+++

`CWE::Weakness` represents a single CWE entry. Instances are constructed
once when the embedded catalog is loaded and are then immutable.

## Fields

| Field                        | Type                            |
|------------------------------|---------------------------------|
| `id`                         | `Int32`                         |
| `name`                       | `String`                        |
| `cwe_id`                     | `String` — `"CWE-79"`          |
| `url`                        | `String` — `https://cwe.mitre.org/data/definitions/79.html` |
| `abstraction`                | `CWE::Abstraction`              |
| `status`                     | `CWE::Status`                   |
| `description`                | `String?`                       |
| `extended_description`       | `String?`                       |
| `likelihood_of_exploit`      | `String?`                       |
| `related_weaknesses`         | `Array(Related)`                |
| `ordinalities`               | `Array(Ordinality)`             |
| `applicable_platforms`       | `Array(ApplicablePlatform)`     |
| `alternate_terms`            | `Array(AlternateTerm)`          |
| `modes_of_introduction`      | `Array(ModeOfIntroduction)`     |
| `common_consequences`        | `Array(Consequence)`            |
| `detection_methods`          | `Array(DetectionMethod)`        |
| `potential_mitigations`      | `Array(Mitigation)`             |
| `observed_examples`          | `Array(ObservedExample)`        |
| `taxonomy_mappings`          | `Array(TaxonomyMapping)`        |
| `related_attack_patterns`    | `Array(Int32)` — CAPEC ids      |
| `notes`                      | `Array(Note)`                   |
| `background_details`         | `Array(String)`                 |
| `functional_areas`           | `Array(String)`                 |
| `affected_resources`         | `Array(String)`                 |
| `exploitation_factors`       | `Array(String)`                 |
| `raw_abstraction`            | `String?` — original CSV value  |
| `raw_status`                 | `String?` — original CSV value  |

See [Types](/api-reference/types/) for the nested struct definitions.

## Edge helpers

```crystal
w.related_with("ChildOf")     # Array(Related)
w.parent_relations            # alias for related_with("ChildOf")
w.child_relations             # ParentOf edges (rare; use Catalog#children_of)
w.peer_relations              # PeerOf
w.can_precede_relations       # CanPrecede
w.can_follow_relations        # CanFollow
```

## Convenience accessors

```crystal
w.owasp_mappings  # TaxonomyMapping entries with taxonomy_name starting with "OWASP"
w.capec_ids       # alias for related_attack_patterns
w.deprecated?     # true if status is Deprecated or name starts with "DEPRECATED:"
w.summary         # "CWE-79: Improper Neutralization of Input ... (Base, Stable)"
```

## Comparable, Equality, Hash

`Weakness` includes `Comparable(Weakness)` and is ordered by numeric id.
Equality is by id, so cross-catalog instances with the same id compare
equal and hash the same:

```crystal
[CWE.find!(79), CWE.find!(20)].sort.first.id  # => 20
CWE.find!(79) == CWE.find!("CWE-79")          # => true

set = Set(CWE::Weakness).new
set << CWE.find!(79)
set << CWE.find!("CWE-79")
set.size # => 1
```

## JSON

```crystal
w.to_json # => camelCase JSON, see /user-guide/json-output/
```

## See also

- [Types](/api-reference/types/) — nested struct types
- [Catalog](/api-reference/catalog/) — how Weaknesses are constructed
