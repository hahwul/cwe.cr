+++
title = "Relationships"
description = "Walking the CWE hierarchy — parents, children, ancestors, pillars"
weight = 3
+++

CWE entries form a directed graph via `ChildOf`, `ParentOf`, `PeerOf`,
`CanPrecede`, and `CanFollow` edges. cwe.cr exposes both the raw edges and
resolved-Weakness helpers.

## Direct relationships

```crystal
CWE.parents_of(79)  # => [CWE-74]
CWE.children_of(79) # => [CWE-80, CWE-81, CWE-83, CWE-84, CWE-85, CWE-86, CWE-87]
```

`parents_of` walks `ChildOf` edges from the given id, deduplicated across
views. `children_of` is the inverse, served from a pre-built index — it's
O(children), not O(catalog).

## Transitive closure

```crystal
CWE.ancestors_of(79)   # => [CWE-74, CWE-707] (nearest first)
CWE.descendants_of(79) # => all variants under CWE-79
```

`max_depth` is an optional safety limit (default 32) — the real CWE has
chains of length 3-4, so the limit only matters for pathological inputs.

## Pillars

A *Pillar* is the topmost abstraction class (e.g. CWE-707 "Improper
Neutralization", CWE-664 "Improper Control of a Resource Through its
Lifetime"). `pillar_of` walks up `ChildOf` edges until it finds one:

```crystal
CWE.pillar_of(79).try(&.cwe_id) # => "CWE-707"
```

If `id` is already a Pillar, `pillar_of` returns it unchanged. If the
ancestor chain never reaches a Pillar (a few entries top out at a Class),
the most distant ancestor is returned instead.

## View-filtered walks

CWE catalogs the same edge multiple times — once per view it appears in.
The two most common are:

- **View 1000** — *Research Concepts*, the comprehensive graph view
- **View 1003** — *Weaknesses for Simplified Mapping of Published Vulnerabilities*

To restrict a walk to a single view, pass `view_id:`:

```crystal
CWE.parents_of(79, view_id: 1000)   # => [CWE-74]
CWE.parents_of(79, view_id: 1003)   # => [CWE-74]
CWE.parents_of(79, view_id: 9999)   # => []
CWE.ancestors_of(79, view_id: 1000) # full Research-view chain
```

## Raw edges

When you need the full edge metadata (nature, ordinal, chain id, source
view id), read it off the Weakness directly:

```crystal
w = CWE.find!(79)
w.parent_relations  # => Array(CWE::Related) with `ChildOf` nature
w.peer_relations    # => `PeerOf` edges
w.can_precede_relations
w.can_follow_relations
w.related_with("ChildOf") # generic filter
```

Each `CWE::Related` carries `nature`, `cwe_id`, `view_id`, `ordinal`, and
`chain_id`.

## See also

- [API: Catalog](/api-reference/catalog/) — relationship API
- [API: Weakness](/api-reference/weakness/) — edge accessors
- [API: Types](/api-reference/types/) — `Related` struct
