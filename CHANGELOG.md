# Changelog

## Unreleased

### Fixed

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
