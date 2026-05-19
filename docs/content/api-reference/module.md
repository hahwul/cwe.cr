+++
title = "CWE module"
description = "Top-level CWE module helpers"
weight = 1
+++

The `CWE` module is the convenience surface — every method here delegates
to `CWE::Catalog.default`. For a longer-lived catalog reference, capture
`CWE.catalog` once.

## Id parsing

| Method                       | Returns      | Notes                          |
|------------------------------|--------------|--------------------------------|
| `CWE.parse_id?(s : String)`  | `Int32?`     | nil on bad input               |
| `CWE.parse_id(s : String)`   | `Int32`      | raises `CWE::ParseError`       |

Recognized forms: `"CWE-79"`, `"cwe-79"`, `"CWE_79"`, `"CWE:79"`, `"79"`,
`"0079"`. Leading/trailing whitespace is stripped.

## Lookups

| Method                 | Returns                                  |
|------------------------|------------------------------------------|
| `CWE.find(id)`         | `Weakness?`                              |
| `CWE.find!(id)`        | `Weakness` (raises `NotFoundError`)      |
| `CWE[id]`              | `Weakness` (raises `NotFoundError`)      |
| `CWE[id]?`             | `Weakness?`                              |
| `CWE.includes?(id)`    | `Bool`                                   |
| `CWE.all`              | `Array(Weakness)`                        |
| `CWE.each { \|w\| ... }` | iterates                               |
| `CWE.size`             | `Int32` (weakness count)                 |
| `CWE.entry(id)`        | `Weakness \| Category \| View \| Nil`    |

## Search & filters

| Method                                        | Returns           |
|-----------------------------------------------|-------------------|
| `CWE.search(q : String)`                      | `Array(Weakness)` |
| `CWE.search_by_name(q : String)`              | `Array(Weakness)` |
| `CWE.with_abstraction(level : Abstraction)`   | `Array(Weakness)` |
| `CWE.with_status(status : Status)`            | `Array(Weakness)` |

## Relationships

All accept an optional `view_id:` filter.

| Method                                | Returns           |
|---------------------------------------|-------------------|
| `CWE.parents_of(id, view_id: nil)`    | `Array(Weakness)` |
| `CWE.children_of(id, view_id: nil)`   | `Array(Weakness)` |
| `CWE.ancestors_of(id, view_id: nil)`  | `Array(Weakness)` |
| `CWE.descendants_of(id, view_id: nil)`| `Array(Weakness)` |
| `CWE.pillar_of(id)`                   | `Weakness?`       |

## Categories & Views

| Method                  | Returns           |
|-------------------------|-------------------|
| `CWE.category(id)`      | `Category?`       |
| `CWE.category!(id)`     | `Category`        |
| `CWE.categories`        | `Array(Category)` |
| `CWE.view(id)`          | `View?`           |
| `CWE.view!(id)`         | `View`            |
| `CWE.views`             | `Array(View)`     |
| `CWE.members_of(id)`    | `Array(Weakness)` (resolved members of a Category or View) |

## Metadata

| Method                  | Returns       |
|-------------------------|---------------|
| `CWE.catalog`           | `Catalog`     |
| `CWE.catalog_version`   | `String` (e.g. `"4.20"`) |

## See also

- [Catalog](/api-reference/catalog/) — the type these methods delegate to
- [Weakness](/api-reference/weakness/) — the primary return type
- [Errors](/api-reference/errors/) — `ParseError`, `NotFoundError`
