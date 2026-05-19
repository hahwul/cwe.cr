require "json"
require "./types"
require "./weakness"
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

    # The catalog backed by the embedded MITRE data. Built on first access.
    def self.default : Catalog
      @@default ||= from_json(EMBEDDED_JSON)
    end

    # The MITRE catalog version string, e.g. `"4.20"`, or `"unknown"` if the
    # build script was not given a sibling XML to read it from.
    getter catalog_version : String
    # ISO-8601 UTC timestamp at which the embedded blob was generated.
    getter generated_at : String

    @by_id : Hash(Int32, Weakness)
    @sorted : Array(Weakness)

    def initialize(@catalog_version : String, @generated_at : String,
                   weaknesses : Array(Weakness))
      @by_id = {} of Int32 => Weakness
      weaknesses.each { |w| @by_id[w.id] = w }
      @sorted = weaknesses.sort
    end

    # Build a `Catalog` from a JSON document with the schema produced by
    # `data/build_data.cr`. Useful for testing and for callers that ship
    # their own subset.
    def self.from_json(input : String | IO) : Catalog
      doc = ::JSON.parse(input)

      version = doc["catalog_version"]?.try(&.as_s) || "unknown"
      generated = doc["generated_at"]?.try(&.as_s) || ""

      ws = doc["weaknesses"].as_a.map { |w| weakness_from_json(w) }
      new(version, generated, ws)
    end

    private def self.weakness_from_json(j : ::JSON::Any) : Weakness
      id = j["id"].as_i64.to_i32
      name = j["name"].as_s
      abs_raw = j["abstraction"]?.try(&.as_s)
      status_raw = j["status"]?.try(&.as_s)

      Weakness.new(
        id: id,
        name: name,
        abstraction: Abstraction.parse_label(abs_raw),
        status: Status.parse_label(status_raw),
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
        taxonomy_mappings: (j["taxonomy_mappings"]?.try(&.as_a.map { |x| parse_taxonomy(x) }) || [] of TaxonomyMapping),
        related_attack_patterns: (j["related_attack_patterns"]?.try(&.as_a.map(&.as_i64.to_i32)) || [] of Int32),
        notes: (j["notes"]?.try(&.as_a.map { |x| parse_note(x) }) || [] of Note),
        raw_abstraction: abs_raw,
        raw_status: status_raw,
      )
    end

    private def self.s(j, k) : String?
      v = j[k]?
      return nil unless v
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
      kind = if keys.any? { |k| k.starts_with?("language") }
               "Language"
             elsif keys.any? { |k| k.starts_with?("technology") }
               "Technology"
             elsif keys.any? { |k| k.starts_with?("operating_system") }
               "Operating_System"
             elsif keys.any? { |k| k.starts_with?("architecture") }
               "Architecture"
             elsif keys.any? { |k| k.starts_with?("paradigm") }
               "Paradigm"
             else
               "Unknown"
             end
      prefix = kind.downcase
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

    # ---------- Filters ----------

    def with_abstraction(level : Abstraction) : Array(Weakness)
      @sorted.select { |w| w.abstraction == level }
    end

    def with_status(status : Status) : Array(Weakness)
      @sorted.select { |w| w.status == status }
    end

    # ---------- Relationships ----------

    # Direct parents of `id` per the catalog's `ChildOf` edges.
    def parents_of(id : Int) : Array(Weakness)
      w = find(id) || return [] of Weakness
      w.parent_relations.compact_map { |r| find(r.cwe_id) }.uniq
    end

    # Direct children of `id`. Computed by scanning the catalog for entries
    # with a `ChildOf` edge pointing at `id`.
    def children_of(id : Int) : Array(Weakness)
      target = id.to_i32
      @sorted.select do |w|
        w.parent_relations.any? { |r| r.cwe_id == target }
      end
    end

    # All ancestors (transitive closure of `ChildOf`), nearest first.
    def ancestors_of(id : Int, max_depth : Int = 32) : Array(Weakness)
      seen = Set(Int32).new
      result = [] of Weakness
      frontier = parents_of(id)
      depth = 0
      while !frontier.empty? && depth < max_depth
        frontier.each do |w|
          next if seen.includes?(w.id)
          seen << w.id
          result << w
        end
        frontier = frontier.flat_map { |w| parents_of(w.id) }.reject { |w| seen.includes?(w.id) }.uniq
        depth += 1
      end
      result
    end

    # All descendants (transitive closure of children), nearest first.
    def descendants_of(id : Int, max_depth : Int = 32) : Array(Weakness)
      seen = Set(Int32).new
      result = [] of Weakness
      frontier = children_of(id)
      depth = 0
      while !frontier.empty? && depth < max_depth
        frontier.each do |w|
          next if seen.includes?(w.id)
          seen << w.id
          result << w
        end
        frontier = frontier.flat_map { |w| children_of(w.id) }.reject { |w| seen.includes?(w.id) }.uniq
        depth += 1
      end
      result
    end

    # The pillar (top-level entry) reached by walking `ChildOf` edges from
    # `id`. Returns nil if the entry has no ancestors or its ancestor chain
    # never reaches a `Pillar`.
    def pillar_of(id : Int) : Weakness?
      chain = ancestors_of(id)
      chain.reverse.find { |w| w.abstraction == Abstraction::Pillar } ||
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
      @sorted.select { |w| w.name.downcase.includes?(q) }
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
