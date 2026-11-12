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

`members_of` skips members that are Categories. Some categories nest them
(SFP cluster 889 holds 960–962), and most Graph views are made only of them.
Two other calls cover those members:

```crystal
CWE.member_entries_of(889)                       # => Array(Weakness | Category | View), as listed
CWE.members_of(889, resolve_categories: true)    # => Weaknesses of nested Categories too
```

`cat.members` keeps the raw edges.

## Comparable, Equality, Hash

Same id-based contract as `Weakness`: ordered by id, `==` and `hash`
delegate to id.

## See also

- [User Guide: Categories & Views](/user-guide/categories-and-views/)
- [View](/api-reference/view/)
- [Catalog](/api-reference/catalog/)
