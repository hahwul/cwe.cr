+++
title = "Catalog"
description = "CWE::Catalog — the in-memory CWE catalog"
weight = 3
+++

`CWE::Catalog` is the in-memory CWE catalog. The default instance is built
once from the embedded JSON blob and cached for the life of the process.

## Construction

```crystal
CWE::Catalog.default
# Lazy — built on first call from the blob embedded by data/build_data.cr.
# Thread-safe — concurrent first calls won't race on the parse.

CWE::Catalog.from_json(json_string_or_io)
# Build a separate catalog from a JSON document with the same schema.
# Useful for tests or for callers that ship a filtered subset.
```

## Constants

| Constant                            | Value                                   |
|-------------------------------------|-----------------------------------------|
| `CWE::Catalog::EMBEDDED_JSON`       | The full JSON blob, as a String literal |

## Metadata

| Method                  | Returns       |
|-------------------------|---------------|
| `catalog_version`       | `String` — `"4.20"`                    |
| `generated_at`          | `String` — ISO-8601 UTC build timestamp |
| `size`                  | `Int32` — weakness count                |
| `category_count`        | `Int32`                                 |
| `view_count`            | `Int32`                                 |

## Weakness lookups

| Method                  | Returns      |
|-------------------------|--------------|
| `find(id : Int)`        | `Weakness?`  |
| `find(id : String)`     | `Weakness?`  |
| `find!(id : Int)`       | `Weakness`   |
| `find!(id : String)`    | `Weakness`   |
| `[](id)`                | `Weakness`   |
| `[]?(id)`               | `Weakness?`  |
| `includes?(id)`         | `Bool`       |
| `all`                   | `Array(Weakness)` |
| `each { \|w\| ... }`    | iterates     |

## Filters

```crystal
catalog.with_abstraction(CWE::Abstraction::Pillar)
catalog.with_status(CWE::Status::Stable)
```

## Relationships

All accept an optional `view_id:` filter. The `children_of` lookup is
served from a pre-built index — O(children), not O(catalog).

```crystal
catalog.parents_of(id, view_id: nil)
catalog.children_of(id, view_id: nil)
catalog.ancestors_of(id, view_id: nil, max_depth: 32)
catalog.descendants_of(id, view_id: nil, max_depth: 32)
catalog.pillar_of(id)
```

## Search

```crystal
catalog.search(q)         # full-text: name + descriptions + alternate terms
catalog.search_by_name(q) # name only
```

## Categories

```crystal
catalog.all_categories  # Array(Category), sorted
catalog.category(id)    # Category?
catalog.category!(id)   # Category, raises NotFoundError
```

## Views

```crystal
catalog.all_views
catalog.view(id)
catalog.view!(id)
```

## Unified entry

```crystal
catalog.entry(id)      # Weakness | Category | View | Nil
catalog.members_of(id) # Array(Weakness) — resolved members of a Category or View
```

## See also

- [CWE module](/api-reference/module/) — top-level shortcuts that delegate here
- [Weakness](/api-reference/weakness/)
- [Category](/api-reference/category/) and [View](/api-reference/view/)
