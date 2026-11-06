# Changelog

## Unreleased

### Changed

- The embedded catalog is now built from MITRE's XML (`cwec_vX.Y.xml`)
  alone instead of the view-1000 CSV export plus the XML, and moves from
  CWE 4.20 to **CWE 5.0** (2026-10-28). Notable upstream changes: 45
  weaknesses dropped the parenthesised common name (CWE-79 is now
  "Improper Neutralization of Input During Web Page Generation"), view 1000
  is now "Complete Weakness Hierarchy", Categories are `<Grouping>`s (the
  library still exposes them as `Category`), 15 new weaknesses, 9 new
  categories, 3 new views, a new `Overlaps` relationship, and much of the
  old `Extended_Description` text moved to `Technical_Nuance` (see Added) or
  into consequence / introduction notes and background details. The new
  `<Dimensions>` block and `Diagram` attribute are not carried yet.
- **Behaviour change:** deprecated weaknesses are now part of the catalog
  (28 in CWE 5.0; the CSV export left them out), so `CWE.find(71)` resolves
  and `size` / `all` / `each` / `search` / `with_status` include them.
  Most have no relationships and stay out of hierarchy walks, but CWE 5.0
  keeps a few edges to its three newly deprecated entries: CWE-378 / 379 are
  `ChildOf` CWE-377, CWE-613 is `ChildOf` CWE-672 (view 1003) and
  `Requires`-ed by CWE-352, and some categories still list 377 / 391 / 613,
  so `children_of(672)`, `members_of(724)` etc. can return them, exactly as
  MITRE's XML does. Filter with `reject(&.deprecated?)` for the previous
  set.
- **Behaviour change:** `Mitigation#phase` is the first `<Phase>` /
  `<Custom_Phase>` instead of the CSV's space-joined list (`"Implementation Architecture and
  Design"`, not a valid phase, on 244 mitigations in 4.20 / 263 in 5.0); the
  full list is the new `phases`.
- Embedded JSON grows from 6.50 MB to 6.84 MB.

### Fixed

- Data the CSV export lost or mangled now comes through from the XML
  (counts against CWE 4.20 / 5.0):
  - `Weakness#likelihood_of_exploit` was nil on every entry (185 / 184 set).
  - `Mitigation#mitigation_id` and `DetectionMethod#method_id` were always
    nil (527 / 528 and 483 / 580 set), and `effectiveness_notes` was nil on
    every mitigation and detection method (227 values in 4.20).
  - Double quotes and backslashes were stripped from names and text (1,390
    values in 4.20), e.g. CWE-28 read `Path Traversal: '..filedir'` instead
    of `Path Traversal: '..\filedir'`.
  - CWE-1259's platform read `name: "Processor HardwareTECHNOLOGY
    CLASS:Not Technology-Specific"` (missing `::` separator in the CSV); it
    is `name: "Processor Hardware"`, `class_label: "Not Technology-Specific"`.

- Text the build reads from MITRE's XML kept the file's pretty-printing
  whitespace and ignored the xhtml layout. `ExampleCode#code` lost the line
  breaks and indentation MITRE encodes with `<xhtml:br/>` and nested
  `margin-left` divs and picked up the source tabs instead (CWE-203's Python
  example was no longer valid Python; 1,115 snippets changed). Intro/body
  text, notes, summaries, mapping-note rationale and comments, reference
  sections and citation titles carried stray newlines and tab runs (282
  values). Code is now laid out from its markup (keeping the spacing inside
  a line), and prose collapses whitespace the same way MITRE's CSV export
  does.
- `Consequence` kept only the last `Scope` and `Impact` of each consequence,
  though MITRE's schema allows several of each (527 of the 944 embedded
  entries lost data; CWE-79's first consequence reported `Confidentiality` /
  `Read Application Data` and dropped `Access Control` / `Bypass Protection
  Mechanism`). New `scopes` / `impacts` hold every value in order; `scope` /
  `impact` are now the first of each.
- MITRE's CSV does not escape its `::` entry separator, and the build split on
  every occurrence: a value containing `::` (`std::auto_ptr`, CWE-69's
  `Windows ::DATA`) was truncated, a value ending in `:` left five weaknesses
  (CWE-66, 69, 428, 696, 789) with an observed example missing its link plus a
  bogus one with an empty reference, and an empty phase split 36 mitigations
  (CWE-122, …) into a phase-only and a description-only half.
- `pillar_of` merged the `ChildOf` edges of every CWE view and then picked
  whichever `Pillar` happened to sit last in the traversal, so 188 of the 944
  embedded entries reported a pillar from a hierarchy they do not belong to
  (`CWE.pillar_of(15)` answered `CWE-707` by following a view-700 edge instead
  of `CWE-664`). The walk now prefers Research-view (`1000`) edges and MITRE's
  `Primary` ordinal.
- `children_of` / `descendants_of` resolved children for an id that is not in
  the catalog, while `parents_of` reported a miss for the same id.
- `Catalog.from_json` let `JSON::ParseException` escape for a document that is
  not valid JSON; it is wrapped in `CWE::Error` (with the parse error as its
  `cause`) like every other failure mode.
- `MappingNotes#to_json` dropped `raw_usage`, so a MITRE label newer than the
  `MappingUsage` enum did not survive a round-trip.
- `View#type` documented MITRE's view types as `"Slice"` / `"Explicit Slice"` /
  `"Implicit Slice"`; the enumeration is `"Graph"` / `"Explicit"` / `"Implicit"`.
- README listed `ParentOf` and `CanFollow` — natures MITRE records from the
  other side and never emits — as the contents of `related_weaknesses`.
- Out-of-range integer ids raised `OverflowError` instead of reporting a miss
  (`CWE.find(3_000_000_000_i64)`); every `Int`-keyed lookup and traversal now
  narrows safely.
- `children_of`, `all`, `categories`, `views` and `external_references` handed
  out the catalog's internal arrays, so a caller mutating a result corrupted
  the catalog for the rest of the process. They return copies now.
- `Catalog.from_json` leaked raw `TypeCastError` / `Exception` from `JSON::Any`
  for malformed documents; every path is wrapped in `CWE::Error`, and
  structurally wrong optional nodes degrade to nil / an empty list.
- Duplicate ids in a source document made `size` / `all` disagree with `find`
  and left the children index pointing at shadowed entries.
- `parse_id?` accepted embedded whitespace and repeated separators
  (`"CWE-\n79"`, `"CWE--79"`) despite documenting otherwise.
- Restored `Abstraction::Compound`: it is a member of MITRE's
  `AbstractionEnumeration`, distinct from `Structure`, and seven entries
  (CWE-61, 352, 384, 680, 689, 690, 692) were degrading to `Other`.
- An absent `Structure` attribute now parses as `Simple` (MITRE's schema
  default), matching the `Weakness` constructor.
- Label enums serialize as MITRE labels (`"Base"`) rather than Crystal's
  underscored member names (`"base"`), matching entry-level JSON output.
- `MappingNotes` could not read back its own JSON when `reasons` /
  `suggestions` were empty.
- External references are ordered numerically (`REF-2` before `REF-10`), and a
  citation stored with a malformed id resolves under its `REF-` form.

### Added

- `Mitigation#phases`, `ModeOfIntroduction#phases` and
  `DetectionMethod#phases` — every `<Phase>` and `<Custom_Phase>` (CWE 5.0's
  AI / hardware lifecycle phases such as `Training`, whose `Domain` is not
  kept), in order; `phase` is the first. JSON documents carrying only
  `phase` still load.
- `Weakness#technical_nuance` (`<Technical_Nuance>`, new in CWE 5.0),
  emitted as `technicalNuance` and covered by `search`.
- `Weakness#overlaps_relations` for CWE 5.0's `Overlaps` edges.
- `Weakness#can_also_be_relations`, `#requires_relations` and
  `#starts_with_relations` — the three natures the catalog actually uses that
  had no accessor.
- `Category#deprecated?` and `View#deprecated?`, matching `Weakness#deprecated?`.
- Traversal helpers (`parents_of`, `children_of`, `ancestors_of`,
  `descendants_of`, `pillar_of`, `members_of`) accept string ids
  (`"CWE-79"`), like `find` already did.
- `max_depth` is reachable through `CWE.ancestors_of` / `CWE.descendants_of`.

## v0.1.0

- First release
