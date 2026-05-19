+++
title = "Errors"
description = "Exception types raised by cwe.cr"
weight = 7
+++

```crystal
class CWE::Error < Exception
end

class CWE::ParseError < CWE::Error
end

class CWE::NotFoundError < CWE::Error
end
```

## When each is raised

| Exception        | Raised by                                                                   |
|------------------|-----------------------------------------------------------------------------|
| `ParseError`     | `CWE.parse_id`, and the bang lookups when given an unparseable string       |
| `NotFoundError`  | `CWE.find!`, `CWE[]`, `category!`, `view!` when the id isn't in the catalog |

## Handling

```crystal
begin
  CWE.find!(user_input)
rescue CWE::ParseError
  # input wasn't a recognizable CWE id
rescue CWE::NotFoundError
  # id parsed but isn't in the catalog
end
```

Or use the non-raising variants:

```crystal
case CWE.find(user_input)
when CWE::Weakness then # match
else                    # nil
end
```

## See also

- [Lookups](/user-guide/lookups/) — when to use raising vs non-raising
- [CWE module](/api-reference/module/)
