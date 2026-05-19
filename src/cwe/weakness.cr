require "json"
require "./types"

module CWE
  # A single CWE entry.
  #
  # Instances are constructed once when the embedded catalog is loaded
  # (`CWE::Catalog`) and are then immutable. All accessors are pure reads
  # over the parsed data — no I/O happens after the initial load.
  #
  # ```
  # w = CWE.find!("CWE-79")
  # w.name        # => "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
  # w.abstraction # => CWE::Abstraction::Base
  # w.parents.map(&.cwe_id) # => [74]
  # ```
  class Weakness
    include Comparable(Weakness)

    getter id : Int32
    getter name : String
    getter abstraction : Abstraction
    getter status : Status
    getter description : String?
    getter extended_description : String?
    getter likelihood_of_exploit : String?

    getter related_weaknesses : Array(Related)
    getter ordinalities : Array(Ordinality)
    getter applicable_platforms : Array(ApplicablePlatform)
    getter alternate_terms : Array(AlternateTerm)
    getter modes_of_introduction : Array(ModeOfIntroduction)
    getter common_consequences : Array(Consequence)
    getter detection_methods : Array(DetectionMethod)
    getter potential_mitigations : Array(Mitigation)
    getter observed_examples : Array(ObservedExample)
    getter taxonomy_mappings : Array(TaxonomyMapping)
    getter related_attack_patterns : Array(Int32)
    getter notes : Array(Note)
    getter background_details : Array(String)
    getter functional_areas : Array(String)
    getter affected_resources : Array(String)
    getter exploitation_factors : Array(String)

    # Raw fields kept for the catalog's internal use; not part of the public
    # surface but exposed for callers that want to introspect the underlying
    # representation.
    getter raw_abstraction : String?
    getter raw_status : String?

    def initialize(
      @id : Int32,
      @name : String,
      @abstraction : Abstraction = Abstraction::Other,
      @status : Status = Status::Other,
      @description : String? = nil,
      @extended_description : String? = nil,
      @likelihood_of_exploit : String? = nil,
      @related_weaknesses : Array(Related) = [] of Related,
      @ordinalities : Array(Ordinality) = [] of Ordinality,
      @applicable_platforms : Array(ApplicablePlatform) = [] of ApplicablePlatform,
      @alternate_terms : Array(AlternateTerm) = [] of AlternateTerm,
      @modes_of_introduction : Array(ModeOfIntroduction) = [] of ModeOfIntroduction,
      @common_consequences : Array(Consequence) = [] of Consequence,
      @detection_methods : Array(DetectionMethod) = [] of DetectionMethod,
      @potential_mitigations : Array(Mitigation) = [] of Mitigation,
      @observed_examples : Array(ObservedExample) = [] of ObservedExample,
      @taxonomy_mappings : Array(TaxonomyMapping) = [] of TaxonomyMapping,
      @related_attack_patterns : Array(Int32) = [] of Int32,
      @notes : Array(Note) = [] of Note,
      @background_details : Array(String) = [] of String,
      @functional_areas : Array(String) = [] of String,
      @affected_resources : Array(String) = [] of String,
      @exploitation_factors : Array(String) = [] of String,
      @raw_abstraction : String? = nil,
      @raw_status : String? = nil
    )
    end

    # Canonical identifier with the `CWE-` prefix, e.g. `"CWE-79"`.
    def cwe_id : String
      "CWE-#{@id}"
    end

    # URL on cwe.mitre.org for this entry.
    def url : String
      "https://cwe.mitre.org/data/definitions/#{@id}.html"
    end

    # Subset of `related_weaknesses` with the given nature.
    def related_with(nature : String) : Array(Related)
      @related_weaknesses.select { |r| r.nature == nature }
    end

    # Edges of the form `ChildOf` — i.e. the catalog parents of this entry.
    def parent_relations : Array(Related)
      related_with("ChildOf")
    end

    # Edges of the form `ParentOf` — children that point back at this entry.
    # Note that the MITRE CSV usually expresses the relationship from the
    # child's side, so use `Catalog#children_of` for a complete answer.
    def child_relations : Array(Related)
      related_with("ParentOf")
    end

    def peer_relations : Array(Related)
      related_with("PeerOf")
    end

    def can_precede_relations : Array(Related)
      related_with("CanPrecede")
    end

    def can_follow_relations : Array(Related)
      related_with("CanFollow")
    end

    # OWASP entries in `taxonomy_mappings`.
    def owasp_mappings : Array(TaxonomyMapping)
      @taxonomy_mappings.select { |t| t.taxonomy_name.starts_with?("OWASP") }
    end

    # CAPEC IDs this weakness is mapped to (Common Attack Pattern Enumeration).
    def capec_ids : Array(Int32)
      @related_attack_patterns
    end

    # True if the catalog marks this entry deprecated.
    def deprecated? : Bool
      @status == Status::Deprecated || @name.starts_with?("DEPRECATED:")
    end

    # Single-line summary suitable for log lines / CLI output:
    # `"CWE-79: Improper Neutralization of Input ... (Base, Stable)"`.
    def summary : String
      String.build do |io|
        io << cwe_id << ": " << @name
        io << " (" << @abstraction
        io << ", " << @status
        io << ')'
      end
    end

    # Order by numeric id — useful for stable sort of result sets.
    def <=>(other : Weakness) : Int32
      @id <=> other.id
    end

    def ==(other : Weakness) : Bool
      @id == other.id
    end

    def hash(hasher)
      @id.hash(hasher)
    end

    def to_s(io : IO) : Nil
      io << cwe_id
    end

    def inspect(io : IO) : Nil
      io << "#<CWE::Weakness " << cwe_id << ' ' << @name.inspect << '>'
    end
  end
end
