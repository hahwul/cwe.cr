+++
title = "Categories & Views"
description = "Beyond Weaknesses — MITRE Categories and Views"
weight = 5
+++

CWE includes three kinds of entries:

| Kind       | Example  | Description                              |
|------------|----------|------------------------------------------|
| Weakness   | CWE-79   | A concrete weakness                      |
| Category   | CWE-227  | Informal grouping ("Mapping Prohibited") |
| View       | CWE-1000 | Catalog slice for a stakeholder          |

The default `CWE.find` only returns Weaknesses — Categories and Views need
their own lookups.

## Categories

```crystal
cat = CWE.category!(227)
cat.name        # => "7PK - API Abuse"
cat.status      # => CWE::Status::Draft
cat.member_ids  # => [242, 243, 244, 245, 246, 248, 250, 251, 252, 558]
cat.url         # => "https://cwe.mitre.org/data/definitions/227.html"
```

`CWE.members_of(cat.id)` resolves the member CWE ids to `Weakness`
objects:

```crystal
CWE.members_of(227).map(&.cwe_id)
# => ["CWE-242", "CWE-243", "CWE-244", ...]
```

Iterate all categories:

```crystal
CWE.categories       # => Array(CWE::Category), sorted by id
CWE.categories.size  # => 422
```

## Views

```crystal
v = CWE.view!(1000)
v.name      # => "Research Concepts"
v.type      # => "Graph"
v.status    # => CWE::Status::Draft
v.objective # => "This view is intended to facilitate research..."
v.member_ids.size # => number of top-level pillar entries
```

`CWE.views` returns the sorted list (59 entries).

## Unified entry lookup

If you don't know which kind of entity an id refers to, use `CWE.entry`:

```crystal
CWE.entry(79)    # => CWE::Weakness
CWE.entry(227)   # => CWE::Category
CWE.entry(1000)  # => CWE::View
CWE.entry(99999) # => nil
```

The return type is `Weakness | Category | View | Nil`. Match on it:

```crystal
case e = CWE.entry(id)
in CWE::Weakness then "weakness — #{e.name}"
in CWE::Category then "category — #{e.name}"
in CWE::View     then "view — #{e.name}"
in Nil           then "not found"
end
```

## When Categories and Views are missing

Categories and Views are sourced from MITRE's XML supplement, not the CSV.
If a build is run without the XML present at `data/cwec.xml`, the
embedded catalog will contain Weaknesses only and `CWE.categories` /
`CWE.views` will be empty. The shipping release always includes them.

## See also

- [API: Category](/api-reference/category/)
- [API: View](/api-reference/view/)
- [API: Catalog](/api-reference/catalog/) — lookup helpers
