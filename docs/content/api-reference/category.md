+++
title = "Category"
description = "CWE::Category — informal grouping of weaknesses"
weight = 4
+++

`CWE::Category` represents a MITRE Category — an informal grouping of
weaknesses. MITRE marks Categories as *Mapping Prohibited*: they exist
for browsing/aggregation, not for assigning to a CVE.

## Fields

| Field         | Type                            |
|---------------|---------------------------------|
| `id`          | `Int32`                         |
| `name`        | `String`                        |
| `cwe_id`      | `String` — `"CWE-227"`         |
| `url`         | `String`                        |
| `status`      | `CWE::Status`                   |
| `summary`     | `String?`                       |
| `members`     | `Array(Category::Member)`       |
| `member_ids`  | `Array(Int32)` — unique cwe ids of members |
| `raw_status`  | `String?`                       |

## Category::Member

A `<Has_Member>` edge from the catalog. `Category::Member` is a struct
with:

| Field      | Type    |
|------------|---------|
| `cwe_id`   | `Int32` |
| `view_id`  | `Int32` |

JSON keys are `cweId` / `viewId` (camelCase).

## Resolution

To turn member ids into `Weakness` objects:

```crystal
CWE.members_of(cat.id) # => Array(Weakness)
```

Members that point at Categories or Views (rare nesting) are skipped by
`members_of` — use `cat.members` for the raw edges.

## Comparable, Equality, Hash

Same id-based contract as `Weakness`: ordered by id, `==` and `hash`
delegate to id.

## See also

- [User Guide: Categories & Views](/user-guide/categories-and-views/)
- [View](/api-reference/view/)
- [Catalog](/api-reference/catalog/)
