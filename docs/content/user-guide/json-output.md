+++
title = "JSON Output"
description = "Serializing Weakness entries to JSON for SBOM / SARIF tooling"
weight = 6
+++

`CWE::Weakness#to_json` emits a stable, camelCase JSON object suitable for
interop with SBOM, SARIF, and other security tooling.

## Shape

```crystal
require "cwe"
require "json"

puts CWE.find!(79).to_json
```

```json
{
  "id": 79,
  "cweId": "CWE-79",
  "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "url": "https://cwe.mitre.org/data/definitions/79.html",
  "abstraction": "Base",
  "status": "Stable",
  "description": "The product does not neutralize ...",
  "extendedDescription": "There are many variants of cross-site scripting ...",
  "relatedWeaknesses": [
    {"nature": "ChildOf", "cweId": 74, "viewId": 1000, "ordinal": "Primary"}
  ],
  "applicablePlatforms": [
    {"kind": "Technology", "class": "Web Based", "prevalence": "Often"}
  ],
  "alternateTerms": [{"term": "XSS", "description": "..."}],
  "modesOfIntroduction": [{"phase": "Implementation"}],
  "commonConsequences": [
    {"scope": "Confidentiality", "impact": "Read Application Data", "note": "..."}
  ],
  "potentialMitigations": [
    {"phase": "Implementation", "strategy": "Output Encoding", "description": "..."}
  ],
  "observedExamples": [
    {"reference": "CVE-2024-49038", "description": "XSS in AI assistant", "link": "..."}
  ],
  "taxonomyMappings": [
    {"taxonomyName": "OWASP Top Ten 2007", "entryId": "A1", "entryName": "Cross Site Scripting (XSS)"}
  ],
  "relatedAttackPatterns": [209, 588, 591, 592, 63, 85]
}
```

## Key conventions

- **camelCase throughout.** Top-level and nested. `cweId`, `viewId`,
  `taxonomyName`, `effectivenessNotes`, `mitigationId`, etc.
- **Empty arrays and nil scalars are omitted.** An entry with no
  `detection_methods` won't have a `detectionMethods` key at all.
- **`class` instead of `classLabel`** on `applicablePlatforms` (we
  serialize the Crystal `class_label` field as `"class"`).
- **Integers for ids.** `cweId` (the string `"CWE-79"`) sits alongside
  `id` (the integer `79`); ids inside nested objects use the integer form.

## Streaming many entries

`to_json` writes incrementally — you can stream the whole catalog without
buffering it in memory:

```crystal
File.open("cwe.jsonl", "w") do |io|
  CWE.each do |w|
    w.to_json(io)
    io << '\n'
  end
end
```

## Round-tripping

The `to_json` output is informational. The catalog itself round-trips via
its internal JSON blob (used by `CWE::Catalog.from_json`); ad-hoc JSON of
a single entry isn't reversible back into a `Weakness`.

## See also

- [API: Weakness](/api-reference/weakness/) — `to_json` signature
- [API: Types](/api-reference/types/) — nested struct keys
