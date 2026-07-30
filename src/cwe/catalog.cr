require "json"
require "./types"
require "./weakness"
require "./category"
require "./error"

module CWE
  # The in-memory CWE catalog.
  #
  # The default instance (`CWE::Catalog.default`) is built once from the JSON
  # blob embedded at compile time and cached for the life of the process.
  # All `CWE.find`, `CWE.search`, etc. helpers route through this default
  # catalog.
  #
  # Constructing your own `Catalog` (e.g. from a different JSON file or a
  # filtered subset) is supported but rarely necessary — the embedded blob
  # is sourced from the MITRE CWE Research view (`view 1000`), which is the
  # comprehensive set.
  class Catalog
    # Embedded source data. Loaded at compile time so the resulting binary
    # is self-contained — no I/O is required to look up any CWE entry.
    EMBEDDED_JSON = {{ read_file("#{__DIR__}/data/weaknesses.json") }}

    @@default : Catalog?
    @@default_mutex = Mutex.new

    # The catalog backed by the embedded MITRE data. Built on first access;
    # subsequent calls return the cached instance. Thread-safe — concurrent
    # first calls won't race on the lazy parse.
    def self.default : Catalog
      if existing = @@default
        return existing
      end
      @@default_mutex.synchronize do
        @@default ||= from_json(EMBEDDED_JSON)
      end
      @@default.not_nil!
    end

    # The MITRE catalog version string, e.g. `"4.20"`, or `"unknown"` if the
    # build script was not given a sibling XML to read it from.
    getter catalog_version : String
    # ISO-8601 UTC timestamp at which the embedded blob was generated.
    getter generated_at : String

    @by_id : Hash(Int32, Weakness)
    @sorted : Array(Weakness)
    @categories_by_id : Hash(Int32, Category)
    @sorted_categories : Array(Category)
    @views_by_id : Hash(Int32, View)
    @sorted_views : Array(View)
    # Inverted index: for each weakness id, the set of weaknesses that point
    # at it via a `ChildOf` edge. Built once at construction so `children_of`
    # is O(children) instead of O(catalog).
    @children_index : Hash(Int32, Array(Weakness))
    @external_refs_by_id : Hash(String, ExternalReference)
    @sorted_external_refs : Array(ExternalReference)

    def initialize(@catalog_version : String, @generated_at : String,
                   weaknesses : Array(Weakness),
                   categories : Array(Category) = [] of Category,
                   views : Array(View) = [] of View,
                   external_references : Array(ExternalReference) = [] of ExternalReference)
      @by_id = {} of Int32 => Weakness
      weaknesses.each { |w| @by_id[w.id] = w }
      @sorted = weaknesses.sort

      @categories_by_id = {} of Int32 => Category
      categories.each { |c| @categories_by_id[c.id] = c }
      @sorted_categories = categories.sort

      @views_by_id = {} of Int32 => View
      views.each { |v| @views_by_id[v.id] = v }
      @sorted_views = views.sort

      @external_refs_by_id = {} of String => ExternalReference
      external_references.each { |r| @external_refs_by_id[r.reference_id] = r }
      @sorted_external_refs = external_references.sort_by(&.reference_id)

      @children_index = Hash(Int32, Array(Weakness)).new { |h, k| h[k] = [] of Weakness }
      @sorted.each do |w|
        seen_parents = Set(Int32).new
        w.related_weaknesses.each do |r|
          next unless r.nature == "ChildOf"
          next if seen_parents.includes?(r.cwe_id)
          seen_parents << r.cwe_id
          @children_index[r.cwe_id] << w
        end
      end
    end

    # Build a `Catalog` from a JSON document with the schema produced by
    # `data/build_data.cr`. Useful for testing and for callers that ship
    # their own subset.
    def self.from_json(input : String | IO) : Catalog
      doc = ::JSON.parse(input)
      unless doc.as_h?
        raise CWE::Error.new("malformed CWE document: top level must be an object")
      end

      version = raw_s(doc, "catalog_version") || "unknown"
      generated = raw_s(doc, "generated_at") || ""

      unless field(doc, "weaknesses")
        raise CWE::Error.new("malformed CWE document: missing required \"weaknesses\" key")
      end
      ws = entry_array(doc, "weaknesses").map { |w| weakness_from_json(w) }
      cats = entry_array(doc, "categories").map { |c| category_from_json(c) }
      vws = entry_array(doc, "views").map { |v| view_from_json(v) }
      ers = entry_array(doc, "external_references").map { |r| external_reference_from_json(r) }
      new(version, generated, ws, cats, vws, ers)
    end

    # ---------- Defensive JSON access ----------
    #
    # `from_json` is public API, so it has to cope with any document a caller
    # hands it — not just the one `data/build_data.cr` produces. The helpers
    # below degrade a structurally wrong node (a scalar where an object was
    # expected, a string where an array was expected) to nil / an empty list
    # instead of letting `JSON::Any`'s raw `TypeCastError` — or its bare
    # `Exception: Expected Hash for #[]?` — escape. Required fields still
    # raise a wrapped `CWE::Error`.

    # Value at `key`, or nil when `j` is not an object or has no such key.
    private def self.field(j : ::JSON::Any, key : String) : ::JSON::Any?
      j.as_h?.try(&.[key]?)
    end

    # String at `key`, verbatim; nil when absent or not a string.
    private def self.raw_s(j : ::JSON::Any, key : String) : String?
      field(j, key).try(&.as_s?)
    end

    # As `raw_s`, but an empty string reads as "absent".
    private def self.s(j : ::JSON::Any, key : String) : String?
      str = raw_s(j, key)
      str && !str.empty? ? str : nil
    end

    # Int32 at `key`; nil when absent, non-numeric, or out of Int32 range.
    private def self.i32(j : ::JSON::Any, key : String) : Int32?
      n = field(j, key).try(&.as_i64?) || return
      n.to_i32 if Int32::MIN <= n && n <= Int32::MAX
    end

    # Top-level entry list. Absent reads as empty; present-but-not-an-array
    # is a malformed document.
    private def self.entry_array(doc : ::JSON::Any, key : String) : Array(::JSON::Any)
      node = field(doc, key) || return [] of ::JSON::Any
      node.as_a? || raise CWE::Error.new(
        "malformed CWE document: #{key.inspect} must be an array")
    end

    # Object elements of the array at `key`; non-object elements are skipped,
    # an absent or non-array node yields an empty list.
    private def self.objects(j : ::JSON::Any, key : String) : Array(::JSON::Any)
      node = field(j, key) || return [] of ::JSON::Any
      arr = node.as_a? || return [] of ::JSON::Any
      arr.select { |e| !e.as_h?.nil? }
    end

    # String elements of the array at `key`; other elements are skipped.
    private def self.strings(j : ::JSON::Any, key : String) : Array(String)
      node = field(j, key) || return [] of String
      arr = node.as_a? || return [] of String
      arr.compact_map(&.as_s?)
    end

    # Int32 elements of the array at `key`; other elements are skipped.
    private def self.int32s(j : ::JSON::Any, key : String) : Array(Int32)
      node = field(j, key) || return [] of Int32
      arr = node.as_a? || return [] of Int32
      arr.compact_map do |e|
        n = e.as_i64?
        n.to_i32 if n && Int32::MIN <= n && n <= Int32::MAX
      end
    end

    # The object at `key`, or nil when absent or not an object.
    private def self.object(j : ::JSON::Any, key : String) : ::JSON::Any?
      node = field(j, key) || return
      node.as_h? ? node : nil
    end

    private def self.external_reference_from_json(j : ::JSON::Any) : ExternalReference
      ExternalReference.new(
        reference_id: (raw_s(j, "reference_id") ||
                       raise CWE::Error.new("external reference missing reference_id")),
        authors: strings(j, "authors"),
        title: s(j, "title"),
        edition: s(j, "edition"),
        publication: s(j, "publication"),
        publication_year: s(j, "publication_year"),
        publication_month: s(j, "publication_month"),
        publication_day: s(j, "publication_day"),
        publisher: s(j, "publisher"),
        url: s(j, "url"),
        url_date: s(j, "url_date"),
      )
    end

    private def self.category_from_json(j : ::JSON::Any) : Category
      raise CWE::Error.new("malformed CWE document: each category must be an object") unless j.as_h?
      id = i32(j, "id") || raise CWE::Error.new("category missing id")
      status_raw = raw_s(j, "status")
      Category.new(
        id: id,
        name: raw_s(j, "name") || "",
        status: Status.parse_label(status_raw),
        summary: s(j, "summary"),
        members: parse_members(j),
        notes: objects(j, "notes").map { |x| parse_note(x) },
        taxonomy_mappings: objects(j, "taxonomy_mappings").map { |x| parse_taxonomy(x) },
        references: objects(j, "references").map { |x| parse_reference_link(x) },
        mapping_notes: object(j, "mapping_notes").try { |x| parse_mapping_notes(x) },
        content_history: object(j, "content_history").try { |x| parse_content_history(x) },
        raw_status: status_raw,
      )
    end

    private def self.view_from_json(j : ::JSON::Any) : View
      raise CWE::Error.new("malformed CWE document: each view must be an object") unless j.as_h?
      id = i32(j, "id") || raise CWE::Error.new("view missing id")
      status_raw = raw_s(j, "status")
      View.new(
        id: id,
        name: raw_s(j, "name") || "",
        type: s(j, "type"),
        status: Status.parse_label(status_raw),
        objective: s(j, "objective"),
        filter: s(j, "filter"),
        members: parse_members(j),
        audience: objects(j, "audience").map { |x| parse_stakeholder(x) },
        notes: objects(j, "notes").map { |x| parse_note(x) },
        references: objects(j, "references").map { |x| parse_reference_link(x) },
        mapping_notes: object(j, "mapping_notes").try { |x| parse_mapping_notes(x) },
        content_history: object(j, "content_history").try { |x| parse_content_history(x) },
        raw_status: status_raw,
      )
    end

    private def self.parse_reference_link(x : ::JSON::Any) : ReferenceLink
      ReferenceLink.new(
        external_reference_id: raw_s(x, "external_reference_id") || "",
        section: s(x, "section"),
      )
    end

    private def self.parse_stakeholder(x : ::JSON::Any) : Stakeholder
      Stakeholder.new(
        type: raw_s(x, "type") || "",
        description: s(x, "description"),
      )
    end

    private def self.parse_mapping_notes(j : ::JSON::Any) : MappingNotes
      raw_usage = raw_s(j, "usage")
      MappingNotes.new(
        usage: MappingUsage.parse_label(raw_usage),
        raw_usage: raw_usage,
        rationale: s(j, "rationale"),
        comments: s(j, "comments"),
        reasons: strings(j, "reasons"),
        suggestions: objects(j, "suggestions").map { |x| parse_mapping_suggestion(x) },
      )
    end

    private def self.parse_mapping_suggestion(x : ::JSON::Any) : MappingSuggestion
      MappingSuggestion.new(
        cwe_id: i32(x, "cwe_id") || 0,
        comment: s(x, "comment"),
      )
    end

    private def self.parse_content_history(j : ::JSON::Any) : ContentHistory
      ContentHistory.new(
        submission_date: s(j, "submission_date"),
        submission_name: s(j, "submission_name"),
        submission_organization: s(j, "submission_organization"),
        last_modification_date: s(j, "last_modification_date"),
        modification_count: i32(j, "modification_count") || 0,
      )
    end

    private def self.parse_demonstrative_example(j : ::JSON::Any) : DemonstrativeExample
      DemonstrativeExample.new(
        intro_text: s(j, "intro_text"),
        body_text: strings(j, "body_text"),
        example_code: objects(j, "example_code").map { |c| parse_example_code(c) },
        reference_ids: strings(j, "reference_ids"),
      )
    end

    private def self.parse_example_code(j : ::JSON::Any) : ExampleCode
      ExampleCode.new(
        code: raw_s(j, "code") || "",
        nature: s(j, "nature"),
        language: s(j, "language"),
      )
    end

    private def self.parse_members(j : ::JSON::Any) : Array(Category::Member)
      objects(j, "members").map do |m|
        Category::Member.new(
          cwe_id: i32(m, "cwe_id") || 0,
          view_id: i32(m, "view_id") || 0,
        )
      end
    end

    private def self.weakness_from_json(j : ::JSON::Any) : Weakness
      raise CWE::Error.new("malformed CWE document: each weakness must be an object") unless j.as_h?
      id = i32(j, "id") || raise CWE::Error.new("weakness missing id")
      name = raw_s(j, "name") || ""
      abs_raw = raw_s(j, "abstraction")
      status_raw = raw_s(j, "status")
      structure_raw = raw_s(j, "structure")

      Weakness.new(
        id: id,
        name: name,
        abstraction: Abstraction.parse_label(abs_raw),
        status: Status.parse_label(status_raw),
        structure: Structure.parse_label(structure_raw),
        description: raw_s(j, "description"),
        extended_description: raw_s(j, "extended_description"),
        likelihood_of_exploit: raw_s(j, "likelihood_of_exploit"),
        related_weaknesses: objects(j, "related_weaknesses").map { |x| parse_related(x) },
        ordinalities: objects(j, "ordinalities").map { |x| parse_ordinality(x) },
        applicable_platforms: objects(j, "applicable_platforms").compact_map { |x| parse_platform(x) },
        alternate_terms: objects(j, "alternate_terms").map { |x| parse_alt_term(x) },
        modes_of_introduction: objects(j, "modes_of_introduction").map { |x| parse_intro(x) },
        common_consequences: objects(j, "common_consequences").map { |x| parse_consequence(x) },
        detection_methods: objects(j, "detection_methods").map { |x| parse_detection(x) },
        potential_mitigations: objects(j, "potential_mitigations").map { |x| parse_mitigation(x) },
        observed_examples: objects(j, "observed_examples").map { |x| parse_example(x) },
        demonstrative_examples: objects(j, "demonstrative_examples").map { |x| parse_demonstrative_example(x) },
        taxonomy_mappings: objects(j, "taxonomy_mappings").map { |x| parse_taxonomy(x) },
        related_attack_patterns: int32s(j, "related_attack_patterns"),
        notes: objects(j, "notes").map { |x| parse_note(x) },
        background_details: strings(j, "background_details"),
        functional_areas: strings(j, "functional_areas"),
        affected_resources: strings(j, "affected_resources"),
        exploitation_factors: strings(j, "exploitation_factors"),
        references: objects(j, "references").map { |x| parse_reference_link(x) },
        mapping_notes: object(j, "mapping_notes").try { |x| parse_mapping_notes(x) },
        content_history: object(j, "content_history").try { |x| parse_content_history(x) },
        raw_abstraction: abs_raw,
        raw_status: status_raw,
        raw_structure: structure_raw,
      )
    end

    private def self.parse_related(x : ::JSON::Any) : Related
      Related.new(
        nature: raw_s(x, "nature") || "",
        cwe_id: i32(x, "cwe_id") || 0,
        view_id: i32(x, "view_id") || 0,
        ordinal: s(x, "ordinal"),
        chain_id: s(x, "chain_id"),
      )
    end

    private def self.parse_ordinality(x : ::JSON::Any) : Ordinality
      Ordinality.new(
        ordinality: raw_s(x, "ordinality") || "",
        description: s(x, "description"),
      )
    end

    private def self.parse_platform(x : ::JSON::Any) : ApplicablePlatform?
      hash = x.as_h? || return
      keys = hash.keys
      kind, prefix = if keys.any?(&.starts_with?("language"))
                       {"Language", "language"}
                     elsif keys.any?(&.starts_with?("technology"))
                       {"Technology", "technology"}
                     elsif keys.any?(&.starts_with?("operating_system"))
                       {"OperatingSystem", "operating_system"}
                     elsif keys.any?(&.starts_with?("architecture"))
                       {"Architecture", "architecture"}
                     elsif keys.any?(&.starts_with?("paradigm"))
                       {"Paradigm", "paradigm"}
                     else
                       {"Unknown", "unknown"}
                     end
      ApplicablePlatform.new(
        kind: kind,
        name: s(x, "#{prefix}_name"),
        class_label: s(x, "#{prefix}_class"),
        prevalence: s(x, "#{prefix}_prevalence"),
        version: s(x, "#{prefix}_version"),
      )
    end

    private def self.parse_alt_term(x : ::JSON::Any) : AlternateTerm
      AlternateTerm.new(
        term: raw_s(x, "term") || "",
        description: s(x, "description"),
      )
    end

    private def self.parse_intro(x : ::JSON::Any) : ModeOfIntroduction
      ModeOfIntroduction.new(
        phase: raw_s(x, "phase") || "",
        note: s(x, "note"),
      )
    end

    private def self.parse_consequence(x : ::JSON::Any) : Consequence
      Consequence.new(
        scope: raw_s(x, "scope") || "",
        impact: s(x, "impact"),
        likelihood: s(x, "likelihood"),
        note: s(x, "note"),
      )
    end

    private def self.parse_detection(x : ::JSON::Any) : DetectionMethod
      DetectionMethod.new(
        method: raw_s(x, "method") || "",
        method_id: s(x, "method_id"),
        description: s(x, "description"),
        effectiveness: s(x, "effectiveness"),
        effectiveness_notes: s(x, "effectiveness_notes"),
      )
    end

    private def self.parse_mitigation(x : ::JSON::Any) : Mitigation
      Mitigation.new(
        mitigation_id: s(x, "mitigation_id"),
        phase: s(x, "phase"),
        strategy: s(x, "strategy"),
        description: s(x, "description"),
        effectiveness: s(x, "effectiveness"),
        effectiveness_notes: s(x, "effectiveness_notes"),
      )
    end

    private def self.parse_example(x : ::JSON::Any) : ObservedExample
      ObservedExample.new(
        reference: raw_s(x, "reference") || "",
        description: s(x, "description"),
        link: s(x, "link"),
      )
    end

    private def self.parse_taxonomy(x : ::JSON::Any) : TaxonomyMapping
      TaxonomyMapping.new(
        taxonomy_name: raw_s(x, "taxonomy_name") || "",
        entry_id: s(x, "entry_id"),
        entry_name: s(x, "entry_name"),
        mapping_fit: s(x, "mapping_fit"),
      )
    end

    private def self.parse_note(x : ::JSON::Any) : Note
      Note.new(
        type: s(x, "type"),
        note: s(x, "note"),
      )
    end

    # ---------- Lookup ----------

    # Narrow an arbitrary `Int` to the `Int32` the catalog is keyed by.
    # Ids outside the `Int32` range (an `Int64` parsed from user input, say)
    # simply cannot be in the catalog, so they yield nil here instead of
    # raising `OverflowError` from `to_i32` — lookups keep their documented
    # "returns nil / empty on a miss" contract for every `Int` input.
    private def narrow_id(id : Int) : Int32?
      id.to_i32 if Int32::MIN <= id && id <= Int32::MAX
    end

    # Number of entries in the catalog.
    def size : Int32
      @sorted.size
    end

    # All weaknesses, sorted by numeric id.
    #
    # Returns a fresh array on each call — the catalog's own storage is never
    # handed out, so a caller is free to sort/reject/clear the result without
    # corrupting the catalog. Use `each` to iterate without the copy.
    def all : Array(Weakness)
      @sorted.dup
    end

    # Iterate over all entries in numeric-id order.
    def each(& : Weakness ->) : Nil
      @sorted.each { |w| yield w }
    end

    # Find by integer id. Returns nil if not found.
    def find(id : Int) : Weakness?
      if i = narrow_id(id)
        @by_id[i]?
      end
    end

    # Find by `"CWE-79"` / `"cwe-79"` / `"79"`. Returns nil if the string
    # does not parse as a CWE id or the id is not in the catalog.
    def find(id : String) : Weakness?
      if i = CWE.parse_id?(id)
        @by_id[i]?
      end
    end

    # Bang variants — raise `NotFoundError` on miss.
    def find!(id : Int) : Weakness
      find(id) || raise NotFoundError.new("CWE-#{id} not in catalog")
    end

    def find!(id : String) : Weakness
      i = CWE.parse_id(id) # raises ParseError on bad input
      @by_id[i]? || raise NotFoundError.new("#{id} not in catalog")
    end

    # `Catalog[X]` syntax — same as `find!`.
    def [](id : Int) : Weakness
      find!(id)
    end

    def [](id : String) : Weakness
      find!(id)
    end

    # `Catalog[X]?` syntax — same as `find`.
    def []?(id : Int) : Weakness?
      find(id)
    end

    def []?(id : String) : Weakness?
      find(id)
    end

    def includes?(id : Int) : Bool
      if i = narrow_id(id)
        @by_id.has_key?(i)
      else
        false
      end
    end

    def includes?(id : String) : Bool
      if i = CWE.parse_id?(id)
        @by_id.has_key?(i)
      else
        false
      end
    end

    # ---------- Categories ----------

    # Number of categories in the catalog (0 if the build was CSV-only).
    def category_count : Int32
      @sorted_categories.size
    end

    # All categories, sorted by numeric id. Fresh array on each call, as `all`.
    def all_categories : Array(Category)
      @sorted_categories.dup
    end

    def category(id : Int) : Category?
      if i = narrow_id(id)
        @categories_by_id[i]?
      end
    end

    def category(id : String) : Category?
      if i = CWE.parse_id?(id)
        @categories_by_id[i]?
      end
    end

    def category!(id : Int) : Category
      category(id) || raise NotFoundError.new("CWE-#{id} is not a Category in this catalog")
    end

    def category!(id : String) : Category
      i = CWE.parse_id(id)
      @categories_by_id[i]? || raise NotFoundError.new("#{id} is not a Category in this catalog")
    end

    # ---------- Views ----------

    def view_count : Int32
      @sorted_views.size
    end

    # All views, sorted by numeric id. Fresh array on each call, as `all`.
    def all_views : Array(View)
      @sorted_views.dup
    end

    def view(id : Int) : View?
      if i = narrow_id(id)
        @views_by_id[i]?
      end
    end

    def view(id : String) : View?
      if i = CWE.parse_id?(id)
        @views_by_id[i]?
      end
    end

    def view!(id : Int) : View
      view(id) || raise NotFoundError.new("CWE-#{id} is not a View in this catalog")
    end

    def view!(id : String) : View
      i = CWE.parse_id(id)
      @views_by_id[i]? || raise NotFoundError.new("#{id} is not a View in this catalog")
    end

    # ---------- External references ----------

    # All catalog-level external references (citations), sorted by their
    # `Reference_ID` (e.g. `"REF-1"`, `"REF-10"`, …).
    def external_references : Array(ExternalReference)
      @sorted_external_refs.dup
    end

    # Resolve a `Reference_ID` such as `"REF-2"` to its full citation. Returns
    # nil if the id is not in the registry.
    def external_reference(id : String) : ExternalReference?
      @external_refs_by_id[id]?
    end

    def external_reference!(id : String) : ExternalReference
      external_reference(id) || raise NotFoundError.new("external reference #{id} not in catalog")
    end

    # Number of catalog-level external references.
    def external_reference_count : Int32
      @sorted_external_refs.size
    end

    # ---------- Unified entry lookup ----------

    # Look up any entry by id — returns a `Weakness`, `Category`, or `View`
    # (in that order of preference). Useful when you don't know up front
    # which kind of CWE entity a given id refers to.
    def entry(id : Int) : Weakness | Category | View?
      find(id) || category(id) || view(id)
    end

    def entry(id : String) : Weakness | Category | View?
      find(id) || category(id) || view(id)
    end

    # Member weaknesses (resolved) of a category or view. Members that
    # reference Categories or Views (rare nesting) are skipped — use
    # `Category#members` / `View#members` for the raw edge list.
    def members_of(id : Int) : Array(Weakness)
      mem_ids = if cat = category(id)
                  cat.member_ids
                elsif v = view(id)
                  v.member_ids
                else
                  return [] of Weakness
                end
      mem_ids.compact_map { |m| find(m) }
    end

    # ---------- Filters ----------

    def with_abstraction(level : Abstraction) : Array(Weakness)
      @sorted.select { |w| w.abstraction == level }
    end

    def with_status(status : Status) : Array(Weakness)
      @sorted.select { |w| w.status == status }
    end

    # ---------- Relationships ----------

    # Direct parents of `id` per the catalog's `ChildOf` edges. When
    # `view_id` is given, only edges declared in that CWE view are returned
    # (CWE catalog records the same parent twice when it appears in multiple
    # views — view 1000 vs 1003 most commonly).
    def parents_of(id : Int, view_id : Int? = nil) : Array(Weakness)
      w = find(id) || return [] of Weakness
      rels = w.parent_relations
      if v = view_id
        vid = narrow_id(v) || return [] of Weakness
        rels = rels.select { |r| r.view_id == vid }
      end
      rels.compact_map { |r| find(r.cwe_id) }.uniq!
    end

    # Direct children of `id`. Resolved via the pre-built children index in
    # O(children); when `view_id` is given, only children whose `ChildOf`
    # edge belongs to that view are returned. The returned array is a copy of
    # the index bucket, so mutating it does not disturb the catalog.
    def children_of(id : Int, view_id : Int? = nil) : Array(Weakness)
      target = narrow_id(id) || return [] of Weakness
      kids = @children_index[target]? || return [] of Weakness
      if v = view_id
        vid = narrow_id(v) || return [] of Weakness
        return kids.select do |w|
          w.parent_relations.any? { |r| r.cwe_id == target && r.view_id == vid }
        end
      end
      kids.dup
    end

    # All ancestors (transitive closure of `ChildOf`), nearest first.
    # `max_depth` guards against pathological catalogs; the real CWE has
    # chains of length 3-4. `view_id` filters edges to a single CWE view.
    def ancestors_of(id : Int, view_id : Int? = nil, max_depth : Int = 32) : Array(Weakness)
      seen = Set(Int32).new
      result = [] of Weakness
      frontier = parents_of(id, view_id)
      depth = 0
      while !frontier.empty? && depth < max_depth
        frontier.each do |w|
          next if seen.includes?(w.id)
          seen << w.id
          result << w
        end
        frontier = frontier.flat_map { |w| parents_of(w.id, view_id) }
          .reject { |w| seen.includes?(w.id) }.uniq!
        depth += 1
      end
      result
    end

    # All descendants (transitive closure of children), nearest first.
    def descendants_of(id : Int, view_id : Int? = nil, max_depth : Int = 32) : Array(Weakness)
      seen = Set(Int32).new
      result = [] of Weakness
      frontier = children_of(id, view_id)
      depth = 0
      while !frontier.empty? && depth < max_depth
        frontier.each do |w|
          next if seen.includes?(w.id)
          seen << w.id
          result << w
        end
        frontier = frontier.flat_map { |w| children_of(w.id, view_id) }
          .reject { |w| seen.includes?(w.id) }.uniq!
        depth += 1
      end
      result
    end

    # The pillar (top-level entry) reached by walking `ChildOf` edges from
    # `id`. Returns the entry itself if it is already a `Pillar`. Returns
    # nil if `id` is not in the catalog. If the ancestor chain contains a
    # `Pillar`, that is returned; otherwise the most distant ancestor is
    # returned (some chains topple out at a `Class` rather than a `Pillar`).
    def pillar_of(id : Int) : Weakness?
      w = find(id) || return
      return w if w.abstraction == Abstraction::Pillar
      chain = ancestors_of(id)
      chain.reverse.find { |a| a.abstraction == Abstraction::Pillar } ||
        chain.last?
    end

    # ---------- Search ----------

    # Case-insensitive substring search over name + description + extended
    # description + alternate terms. Returns matches in id order.
    def search(query : String) : Array(Weakness)
      q = query.downcase.strip
      return [] of Weakness if q.empty?
      @sorted.select { |w| matches?(w, q) }
    end

    # Like `search` but returns only entries with at least one hit in the
    # `name` field. Useful when callers want strong matches only.
    def search_by_name(query : String) : Array(Weakness)
      q = query.downcase.strip
      return [] of Weakness if q.empty?
      @sorted.select(&.name.downcase.includes?(q))
    end

    private def matches?(w : Weakness, q : String) : Bool
      return true if w.name.downcase.includes?(q)
      if d = w.description
        return true if d.downcase.includes?(q)
      end
      if d = w.extended_description
        return true if d.downcase.includes?(q)
      end
      w.alternate_terms.any? do |t|
        t.term.downcase.includes?(q) ||
          (t.description.try(&.downcase.includes?(q)) || false)
      end
    end
  end
end
