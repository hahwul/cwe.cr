+++
title = "Lookups"
description = "Looking up CWE entries by id — raising and non-raising variants"
weight = 2
+++

## The lookup family

| Form                        | Returns         | On miss                          |
|-----------------------------|-----------------|----------------------------------|
| `CWE.find(id)`              | `Weakness?`     | nil                              |
| `CWE.find!(id)`             | `Weakness`      | raises `CWE::NotFoundError`      |
| `CWE[id]`                   | `Weakness`      | raises `CWE::NotFoundError`      |
| `CWE[id]?`                  | `Weakness?`     | nil                              |
| `CWE.includes?(id)`         | `Bool`          | —                                |
| `CWE.entry(id)`             | `Weakness \| Category \| View \| Nil` | nil          |

All forms accept either an `Int` or a `String`. String forms additionally
raise `CWE::ParseError` from the bang variants if the input is not a
recognizable CWE id.

## Id parsing

```crystal
CWE.parse_id?("CWE-79")  # => 79
CWE.parse_id?("cwe-79")  # => 79
CWE.parse_id?("79")      # => 79
CWE.parse_id?("0079")    # => 79 (leading zeros tolerated)
CWE.parse_id?("garbage") # => nil

CWE.parse_id("garbage")  # raises CWE::ParseError
```

The id pattern is `[Cc][Ww][Ee][-_:\s]?(\d+)` or a bare integer. The
parser does not accept negative numbers, hex, or floating-point.

## Examples

```crystal
# Non-raising
if w = CWE.find("CWE-79")
  puts w.name
end

# Raising — propagate the NotFoundError up the stack
w = CWE.find!(79)

# Indexing — same as find!/find
CWE[79]            # => Weakness
CWE["bogus"]?      # => nil
```

## Checking membership cheaply

`includes?` short-circuits on a bad id without raising:

```crystal
CWE.includes?("CWE-79")    # => true
CWE.includes?("garbage")   # => false (no parse error)
CWE.includes?(999_999)     # => false
```

## See also

- [Relationships](/user-guide/relationships/) — walking from one entry to its parents/children
- [API: CWE module](/api-reference/module/) — all top-level helpers
- [API: Errors](/api-reference/errors/) — `ParseError`, `NotFoundError`
