+++
title = "Types"
description = "Enums and nested struct types"
weight = 6
+++

All structs include `JSON::Serializable` and are emitted with camelCase
keys (see [JSON Output](/user-guide/json-output/)).

## Abstraction

```crystal
enum CWE::Abstraction
  Pillar    # Highest-level category
  Class     # General weakness class
  Base      # Concrete but broadly applicable weakness
  Variant   # Concrete weakness tied to a specific resource/technology
  Compound  # Chain of weaknesses
  Other     # Unknown / future label
end

CWE::Abstraction.parse_label("Base") # => CWE::Abstraction::Base
```

## Status

```crystal
enum CWE::Status
  Stable
  Draft
  Incomplete
  Deprecated
  Obsolete
  Usable
  Other
end

CWE::Status.parse_label("Stable") # => CWE::Status::Stable
```

## Related

```crystal
struct CWE::Related
  nature   : String   # "ChildOf", "ParentOf", "PeerOf", "CanPrecede", "CanFollow", "CanAlsoBe", "StartsWith", "Requires"
  cwe_id   : Int32    # JSON: "cweId"
  view_id  : Int32    # JSON: "viewId"
  ordinal  : String?  # "Primary", "Resultant", …
  chain_id : String?  # JSON: "chainId"
end

rel.primary? # => ordinal == "Primary"
```

## Consequence

```crystal
struct CWE::Consequence
  scope      : String   # "Confidentiality", "Integrity", "Availability", "Access Control", "Authentication", …
  impact     : String?
  likelihood : String?
  note       : String?
end
```

## Mitigation

```crystal
struct CWE::Mitigation
  mitigation_id       : String?   # JSON: "mitigationId"
  phase               : String?   # "Architecture and Design", "Implementation", "Operation", …
  strategy            : String?
  description         : String?
  effectiveness       : String?
  effectiveness_notes : String?   # JSON: "effectivenessNotes"
end
```

## DetectionMethod

```crystal
struct CWE::DetectionMethod
  method              : String
  method_id           : String?   # JSON: "methodId"
  description         : String?
  effectiveness       : String?
  effectiveness_notes : String?
end
```

## ObservedExample

```crystal
struct CWE::ObservedExample
  reference   : String # e.g. "CVE-2024-49038"
  description : String?
  link        : String?
end
```

## AlternateTerm

```crystal
struct CWE::AlternateTerm
  term        : String # "XSS", "HTML Injection", …
  description : String?
end
```

## ModeOfIntroduction

```crystal
struct CWE::ModeOfIntroduction
  phase : String # "Implementation", "Architecture and Design", "Operation", …
  note  : String?
end
```

## ApplicablePlatform

```crystal
struct CWE::ApplicablePlatform
  kind        : String # "Language", "Technology", "OperatingSystem", "Architecture", "Paradigm"
  name        : String?
  class_label : String? # JSON: "class"
  prevalence  : String? # "Often", "Undetermined", "Sometimes", …
  version     : String?
end
```

## TaxonomyMapping

```crystal
struct CWE::TaxonomyMapping
  taxonomy_name : String   # JSON: "taxonomyName" — "OWASP Top Ten 2007", "PLOVER", "CAPEC", …
  entry_id      : String?  # JSON: "entryId"
  entry_name    : String?  # JSON: "entryName"
  mapping_fit   : String?  # JSON: "mappingFit"
end
```

## Ordinality

```crystal
struct CWE::Ordinality
  ordinality  : String # "Primary", "Resultant", "Indirect"
  description : String?
end
```

## Note

```crystal
struct CWE::Note
  type : String? # "Other", "Relationship", "Applicable Platform", "Maintenance", …
  note : String?
end
```

## See also

- [Weakness](/api-reference/weakness/) — uses all of these
- [JSON Output](/user-guide/json-output/) — exact wire format
