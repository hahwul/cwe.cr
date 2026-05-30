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

      version = doc["catalog_version"]?.try(&.as_s) || "unknown"
      generated = doc["generated_at"]?.try(&.as_s) || ""

      weaknesses_node = doc["weaknesses"]? ||
                        raise CWE::Error.new("malformed CWE document: missing required \"weaknesses\" key")
      ws = weaknesses_node.as_a.map { |w| weakness_from_json(w) }
      cats = doc["categories"]?.try(&.as_a.map { |c| category_from_json(c) }) || [] of Category
      vws = doc["views"]?.try(&.as_a.map { |v| view_from_json(v) }) || [] of View
      ers = doc["external_references"]?.try(&.as_a.map { |r| external_reference_from_json(r) }) ||
            [] of ExternalReference
      new(version, generated, ws, cats, vws, ers)
    end

    private def self.external_reference_from_json(j : ::JSON::Any) : ExternalReference
      ExternalReference.new(
        reference_id: j["reference_id"].as_s,
        authors: (j["authors"]?.try(&.as_a.map(&.as_s)) || [] of String),
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
      id = j["id"].as_i64.to_i32
      status_raw = j["status"]?.try(&.as_s)
      Category.new(
        id: id,
        name: j["name"]?.try(&.as_s) || "",
        status: Status.parse_label(status_raw),
        summary: s(j, "summary"),
        members: parse_members(j["members"]?),
        notes: (j["notes"]?.try(&.as_a.map { |x| parse_note(x) }) || [] of Note),
        taxonomy_mappings: (j["taxonomy_mappings"]?.try(&.as_a.map { |x| parse_taxonomy(x) }) || [] of TaxonomyMapping),
        references: (j["references"]?.try(&.as_a.map { |x| parse_reference_link(x) }) || [] of ReferenceLink),
        mapping_notes: j["mapping_notes"]?.try { |x| parse_mapping_notes(x) },
        content_history: j["content_history"]?.try { |x| parse_content_history(x) },
        raw_status: status_raw,
      )
    end

    private def self.view_from_json(j : ::JSON::Any) : View
      id = j["id"].as_i64.to_i32
      status_raw = j["status"]?.try(&.as_s)
      View.new(
        id: id,
        name: j["name"]?.try(&.as_s) || "",
        type: s(j, "type"),
        status: Status.parse_label(status_raw),
        objective: s(j, "objective"),
        filter: s(j, "filter"),
        members: parse_members(j["members"]?),
        audience: (j["audience"]?.try(&.as_a.map { |x| parse_stakeholder(x) }) || [] of Stakeholder),
        notes: (j["notes"]?.try(&.as_a.map { |x| parse_note(x) }) || [] of Note),
        references: (j["references"]?.try(&.as_a.map { |x| parse_reference_link(x) }) || [] of ReferenceLink),
        mapping_notes: j["mapping_notes"]?.try { |x| parse_mapping_notes(x) },
        content_history: j["content_history"]?.try { |x| parse_content_history(x) },
        raw_status: status_raw,
      )
    end

    private def self.parse_reference_link(x : ::JSON::Any) : ReferenceLink
      ReferenceLink.new(
        external_reference_id: x["external_reference_id"]?.try(&.as_s) || "",
        section: s(x, "section"),
      )
    end

    private def self.parse_stakeholder(x : ::JSON::Any) : Stakeholder
      Stakeholder.new(
        type: x["type"]?.try(&.as_s) || "",
        description: s(x, "description"),
      )
    end

    private def self.parse_mapping_notes(j : ::JSON::Any) : MappingNotes
      raw_usage = j["usage"]?.try(&.as_s)
      reasons = (j["reasons"]?.try(&.as_a.map(&.as_s)) || [] of String)
      suggestions = (j["suggestions"]?.try(&.as_a.map { |s| parse_mapping_suggestion(s) }) || [] of MappingSuggestion)
      MappingNotes.new(
        usage: MappingUsage.parse_label(raw_usage),
        raw_usage: raw_usage,
        rationale: s(j, "rationale"),
        comments: s(j, "comments"),
        reasons: reasons,
        suggestions: suggestions,
      )
    end

    private def self.parse_mapping_suggestion(x : ::JSON::Any) : MappingSuggestion
      MappingSuggestion.new(
        cwe_id: (x["cwe_id"]?.try(&.as_i64) || 0_i64).to_i32,
        comment: s(x, "comment"),
      )
    end

    private def self.parse_content_history(j : ::JSON::Any) : ContentHistory
      ContentHistory.new(
        submission_date: s(j, "submission_date"),
        submission_name: s(j, "submission_name"),
        submission_organization: s(j, "submission_organization"),
        last_modification_date: s(j, "last_modification_date"),
        modification_count: (j["modification_count"]?.try(&.as_i64) || 0_i64).to_i32,
      )
    end

    private def self.parse_demonstrative_example(j : ::JSON::Any) : DemonstrativeExample
      codes = (j["example_code"]?.try(&.as_a.map { |c| parse_example_code(c) }) || [] of ExampleCode)
      bodies = (j["body_text"]?.try(&.as_a.map(&.as_s)) || [] of String)
      refs = (j["reference_ids"]?.try(&.as_a.map(&.as_s)) || [] of String)
      DemonstrativeExample.new(
        intro_text: s(j, "intro_text"),
        body_text: bodies,
        example_code: codes,
        reference_ids: refs,
      )
    end

    private def self.parse_example_code(j : ::JSON::Any) : ExampleCode
      ExampleCode.new(
        code: j["code"]?.try(&.as_s) || "",
        nature: s(j, "nature"),
        language: s(j, "language"),
      )
    end

    private def self.parse_members(j : ::JSON::Any?) : Array(Category::Member)
      return [] of Category::Member unless j
      j.as_a.map do |m|
        Category::Member.new(
          cwe_id: (m["cwe_id"]?.try(&.as_i64) || 0_i64).to_i32,
          view_id: (m["view_id"]?.try(&.as_i64) || 0_i64).to_i32,
        )
      end
    end

    private def self.weakness_from_json(j : ::JSON::Any) : Weakness
      id = j["id"].as_i64.to_i32
      name = j["name"].as_s
      abs_raw = j["abstraction"]?.try(&.as_s)
      status_raw = j["status"]?.try(&.as_s)
      structure_raw = j["structure"]?.try(&.as_s)

      Weakness.new(
        id: id,
        name: name,
        abstraction: Abstraction.parse_label(abs_raw),
        status: Status.parse_label(status_raw),
        structure: Structure.parse_label(structure_raw),
        description: j["description"]?.try(&.as_s),
        extended_description: j["extended_description"]?.try(&.as_s),
        likelihood_of_exploit: j["likelihood_of_exploit"]?.try(&.as_s),
        related_weaknesses: (j["related_weaknesses"]?.try(&.as_a.map { |x| parse_related(x) }) || [] of Related),
        ordinalities: (j["ordinalities"]?.try(&.as_a.map { |x| parse_ordinality(x) }) || [] of Ordinality),
        applicable_platforms: (j["applicable_platforms"]?.try(&.as_a.map { |x| parse_platform(x) }) || [] of ApplicablePlatform),
        alternate_terms: (j["alternate_terms"]?.try(&.as_a.map { |x| parse_alt_term(x) }) || [] of AlternateTerm),
        modes_of_introduction: (j["modes_of_introduction"]?.try(&.as_a.map { |x| parse_intro(x) }) || [] of ModeOfIntroduction),
        common_consequences: (j["common_consequences"]?.try(&.as_a.map { |x| parse_consequence(x) }) || [] of Consequence),
        detection_methods: (j["detection_methods"]?.try(&.as_a.map { |x| parse_detection(x) }) || [] of DetectionMethod),
        potential_mitigations: (j["potential_mitigations"]?.try(&.as_a.map { |x| parse_mitigation(x) }) || [] of Mitigation),
        observed_examples: (j["observed_examples"]?.try(&.as_a.map { |x| parse_example(x) }) || [] of ObservedExample),
        demonstrative_examples: (j["demonstrative_examples"]?.try(&.as_a.map { |x| parse_demonstrative_example(x) }) || [] of DemonstrativeExample),
        taxonomy_mappings: (j["taxonomy_mappings"]?.try(&.as_a.map { |x| parse_taxonomy(x) }) || [] of TaxonomyMapping),
        related_attack_patterns: (j["related_attack_patterns"]?.try(&.as_a.map(&.as_i64.to_i32)) || [] of Int32),
        notes: (j["notes"]?.try(&.as_a.map { |x| parse_note(x) }) || [] of Note),
        background_details: (j["background_details"]?.try(&.as_a.map(&.as_s)) || [] of String),
        functional_areas: (j["functional_areas"]?.try(&.as_a.map(&.as_s)) || [] of String),
        affected_resources: (j["affected_resources"]?.try(&.as_a.map(&.as_s)) || [] of String),
        exploitation_factors: (j["exploitation_factors"]?.try(&.as_a.map(&.as_s)) || [] of String),
        references: (j["references"]?.try(&.as_a.map { |x| parse_reference_link(x) }) || [] of ReferenceLink),
        mapping_notes: j["mapping_notes"]?.try { |x| parse_mapping_notes(x) },
        content_history: j["content_history"]?.try { |x| parse_content_history(x) },
        raw_abstraction: abs_raw,
        raw_status: status_raw,
        raw_structure: structure_raw,
      )
    end

    private def self.s(j, k) : String?
      v = j[k]?
      return unless v
      str = v.as_s?
      str.try(&.empty?) ? nil : str
    end

    private def self.parse_related(x) : Related
      Related.new(
        nature: x["nature"]?.try(&.as_s) || "",
        cwe_id: (x["cwe_id"]?.try(&.as_i64) || 0_i64).to_i32,
        view_id: (x["view_id"]?.try(&.as_i64) || 0_i64).to_i32,
        ordinal: s(x, "ordinal"),
        chain_id: s(x, "chain_id"),
      )
    end

    private def self.parse_ordinality(x) : Ordinality
      Ordinality.new(
        ordinality: x["ordinality"]?.try(&.as_s) || "",
        description: s(x, "description"),
      )
    end

    private def self.parse_platform(x) : ApplicablePlatform
      keys = x.as_h.keys
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

    private def self.parse_alt_term(x) : AlternateTerm
      AlternateTerm.new(
        term: x["term"]?.try(&.as_s) || "",
        description: s(x, "description"),
      )
    end

    private def self.parse_intro(x) : ModeOfIntroduction
      ModeOfIntroduction.new(
        phase: x["phase"]?.try(&.as_s) || "",
        note: s(x, "note"),
      )
    end

    private def self.parse_consequence(x) : Consequence
      Consequence.new(
        scope: x["scope"]?.try(&.as_s) || "",
        impact: s(x, "impact"),
        likelihood: s(x, "likelihood"),
        note: s(x, "note"),
      )
    end

    private def self.parse_detection(x) : DetectionMethod
      DetectionMethod.new(
        method: x["method"]?.try(&.as_s) || "",
        method_id: s(x, "method_id"),
        description: s(x, "description"),
        effectiveness: s(x, "effectiveness"),
        effectiveness_notes: s(x, "effectiveness_notes"),
      )
    end

    private def self.parse_mitigation(x) : Mitigation
      Mitigation.new(
        mitigation_id: s(x, "mitigation_id"),
        phase: s(x, "phase"),
        strategy: s(x, "strategy"),
        description: s(x, "description"),
        effectiveness: s(x, "effectiveness"),
        effectiveness_notes: s(x, "effectiveness_notes"),
      )
    end

    private def self.parse_example(x) : ObservedExample
      ObservedExample.new(
        reference: x["reference"]?.try(&.as_s) || "",
        description: s(x, "description"),
        link: s(x, "link"),
      )
    end

    private def self.parse_taxonomy(x) : TaxonomyMapping
      TaxonomyMapping.new(
        taxonomy_name: x["taxonomy_name"]?.try(&.as_s) || "",
        entry_id: s(x, "entry_id"),
        entry_name: s(x, "entry_name"),
        mapping_fit: s(x, "mapping_fit"),
      )
    end

    private def self.parse_note(x) : Note
      Note.new(
        type: s(x, "type"),
        note: s(x, "note"),
      )
    end

    # ---------- Lookup ----------

    # Number of entries in the catalog.
    def size : Int32
      @sorted.size
    end

    # All weaknesses, sorted by numeric id.
    def all : Array(Weakness)
      @sorted
    end

    # Iterate over all entries in numeric-id order.
    def each(& : Weakness ->) : Nil
      @sorted.each { |w| yield w }
    end

    # Find by integer id. Returns nil if not found.
    def find(id : Int) : Weakness?
      @by_id[id.to_i32]?
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
      @by_id.has_key?(id.to_i32)
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

    def all_categories : Array(Category)
      @sorted_categories
    end

    def category(id : Int) : Category?
      @categories_by_id[id.to_i32]?
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

    def all_views : Array(View)
      @sorted_views
    end

    def view(id : Int) : View?
      @views_by_id[id.to_i32]?
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
      @sorted_external_refs
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
        rels = rels.select { |r| r.view_id == v.to_i32 }
      end
      rels.compact_map { |r| find(r.cwe_id) }.uniq!
    end

    # Direct children of `id`. Resolved via the pre-built children index in
    # O(children); when `view_id` is given, only children whose `ChildOf`
    # edge belongs to that view are returned.
    def children_of(id : Int, view_id : Int? = nil) : Array(Weakness)
      target = id.to_i32
      kids = @children_index[target]? || ([] of Weakness)
      if v = view_id
        kids = kids.select do |w|
          w.parent_relations.any? { |r| r.cwe_id == target && r.view_id == v.to_i32 }
        end
      end
      kids
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
