+++
title = "Getting Started"
description = "Install cwe.cr and look up your first CWE entry"
weight = 1
+++

## Prerequisites

| Requirement | Version    |
|-------------|------------|
| Crystal     | >= 1.20.2  |

cwe.cr is pure Crystal with no native dependencies. The MITRE CWE catalog
is embedded directly into the resulting binary — no runtime data files,
no network calls.

## Installation

Add the dependency to your `shard.yml`:

```yaml
dependencies:
  cwe:
    github: hahwul/cwe.cr
```

Then install:

```bash
shards install
```

## Your First Program

Create `hello.cr`:

```crystal
require "cwe"

w = CWE.find!("CWE-79")
puts w.name        # => Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
puts w.abstraction # => Base
puts w.url         # => https://cwe.mitre.org/data/definitions/79.html
```

Run it:

```bash
crystal run hello.cr
```

## Tolerant id parsing

Any of these forms is accepted as an id:

```crystal
CWE.find(79)
CWE.find("79")
CWE.find("CWE-79")
CWE.find("cwe-79")
CWE.find("CWE_79")
CWE.find("CWE:79")
CWE.find("  CWE-79  ") # whitespace tolerated
```

For details on raising vs non-raising lookups, see **[Lookups](/user-guide/lookups/)**.

## Non-raising lookups

When you can't be sure an id is in the catalog, prefer `find` over `find!`:

```crystal
if w = CWE.find(user_input)
  # use w
else
  # malformed id or not in the catalog
end
```

## Catalog metadata

```crystal
CWE.catalog_version # => "4.20"
CWE.size            # => 944  (weaknesses)
CWE.categories.size # => 422
CWE.views.size      # => 59
```

## Next Steps

- **[Lookups](/user-guide/lookups/)** — `find`, `find!`, `[]`, `[]?`, `includes?`, `parse_id`
- **[Relationships](/user-guide/relationships/)** — walk the catalog hierarchy
- **[Search & Filters](/user-guide/search-and-filters/)** — full-text search and abstraction/status filters
- **[Categories & Views](/user-guide/categories-and-views/)** — beyond Weaknesses
