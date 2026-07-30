+++
title = "Search & Filters"
description = "Full-text search and abstraction/status filtering across the catalog"
weight = 4
+++

## Full-text search

`CWE.search` is a case-insensitive substring match across:

- `name`
- `description`
- `extended_description`
- `alternate_terms[*].term` and `.description`

```crystal
CWE.search("HttpOnly").map(&.cwe_id)
# => ["CWE-1004"]

CWE.search("cross-site").map(&.cwe_id)
# => ["CWE-79", "CWE-352", ...]

CWE.search("XSS").map(&.cwe_id)
# Matches "XSS" appearing in any of the searched fields, including alternate
# terms — CWE-79 has it as an alternate term so it's a hit.
```

Empty / whitespace queries return an empty list.

## Name-only search

If you want strong hits only, restrict to the `name` field:

```crystal
CWE.search_by_name("cross-site scripting")
# => [CWE-79, CWE-692]
```

## Filters by abstraction

```crystal
CWE.with_abstraction(CWE::Abstraction::Pillar)
# => all top-level entries (CWE-284, CWE-435, CWE-664, ...)

CWE.with_abstraction(CWE::Abstraction::Variant)
```

The full set of values is:

| Abstraction | Meaning                            |
|-------------|------------------------------------|
| `Pillar`    | Highest-level category             |
| `Class`     | General weakness class             |
| `Base`      | Concrete weakness, abstract enough to apply broadly |
| `Variant`   | Concrete weakness tied to a specific resource or technology |
| `Compound`  | Chain or Composite of several weaknesses (see `structure`) |
| `Other`     | Unknown / future label             |

## Filters by status

```crystal
CWE.with_status(CWE::Status::Stable)
CWE.with_status(CWE::Status::Draft)
CWE.with_status(CWE::Status::Incomplete)
CWE.with_status(CWE::Status::Deprecated)
```

## Sorting / combining

All filter helpers return `Array(CWE::Weakness)`, sorted by numeric id.
Combine with `Enumerable` methods as needed:

```crystal
CWE.with_abstraction(CWE::Abstraction::Base)
   .select(&.common_consequences.any? { |c| c.scope == "Confidentiality" })
   .first(10)
```

## See also

- [API: Catalog](/api-reference/catalog/) — search and filter API
- [API: Types](/api-reference/types/) — `Abstraction`, `Status` enums
