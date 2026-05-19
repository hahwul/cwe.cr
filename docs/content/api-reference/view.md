+++
title = "View"
description = "CWE::View — a catalog slice for a particular stakeholder"
weight = 5
+++

`CWE::View` represents a MITRE View — a catalog slice organised around a
particular stakeholder (Research, Development, Architecture, Hardware
Design, …). Each view is itself a CWE-numbered entry.

Common views:

| View ID  | Name                                                  |
|----------|-------------------------------------------------------|
| CWE-1000 | Research Concepts (the comprehensive Graph)           |
| CWE-699  | Software Development                                  |
| CWE-1003 | Weaknesses for Simplified Mapping of Published Vulnerabilities |
| CWE-635  | Weaknesses Originally Used by NVD                     |
| CWE-1194 | Hardware Design                                       |

## Fields

| Field         | Type                            |
|---------------|---------------------------------|
| `id`          | `Int32`                         |
| `name`        | `String`                        |
| `cwe_id`      | `String` — `"CWE-1000"`        |
| `url`         | `String`                        |
| `type`        | `String?` — `"Graph"`, `"Slice"`, `"Explicit Slice"`, … |
| `status`      | `CWE::Status`                   |
| `objective`   | `String?`                       |
| `filter`      | `String?` — XPath-like filter for Slice views |
| `members`     | `Array(Category::Member)`       |
| `member_ids`  | `Array(Int32)`                  |
| `raw_status`  | `String?`                       |

## Resolution

```crystal
v = CWE.view!(1000)
CWE.members_of(v.id).first(5).map(&.cwe_id)
# => ["CWE-284", "CWE-435", "CWE-664", "CWE-682", "CWE-691"]
```

## See also

- [User Guide: Categories & Views](/user-guide/categories-and-views/)
- [Category](/api-reference/category/) — same shape with summary instead of objective
- [User Guide: Relationships](/user-guide/relationships/) — view-filtered hierarchy walks
