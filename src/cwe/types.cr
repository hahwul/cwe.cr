require "json"

module CWE
  # CWE catalog defines a small fixed set of abstraction levels. We expose
  # them as an enum so callers can pattern-match against them; unknown values
  # (catalog drift, future MITRE releases) map to `Other`.
  enum Abstraction
    Pillar
    Class
    Base
    Variant
    Compound
    Other

    def self.parse_label(s : String?) : Abstraction
      case s.try(&.strip).try(&.downcase)
      when "pillar"   then Pillar
      when "class"    then Class
      when "base"     then Base
      when "variant"  then Variant
      when "compound" then Compound
      else                 Other
      end
    end

    def to_s : String
      case self
      in Pillar   then "Pillar"
      in Class    then "Class"
      in Base     then "Base"
      in Variant  then "Variant"
      in Compound then "Compound"
      in Other    then "Other"
      end
    end

    def to_s(io : IO) : Nil
      io << to_s
    end
  end

  # Lifecycle status assigned by the CWE editorial board.
  enum Status
    Stable
    Draft
    Incomplete
    Deprecated
    Obsolete
    Usable
    Other

    def self.parse_label(s : String?) : Status
      case s.try(&.strip).try(&.downcase)
      when "stable"     then Stable
      when "draft"      then Draft
      when "incomplete" then Incomplete
      when "deprecated" then Deprecated
      when "obsolete"   then Obsolete
      when "usable"     then Usable
      else                   Other
      end
    end

    def to_s : String
      case self
      in Stable     then "Stable"
      in Draft      then "Draft"
      in Incomplete then "Incomplete"
      in Deprecated then "Deprecated"
      in Obsolete   then "Obsolete"
      in Usable     then "Usable"
      in Other      then "Other"
      end
    end

    def to_s(io : IO) : Nil
      io << to_s
    end
  end

  # A directed edge in the CWE hierarchy.
  #
  # `nature` is the relationship label as defined by the catalog
  # (`"ChildOf"`, `"ParentOf"`, `"PeerOf"`, `"CanPrecede"`, `"CanFollow"`,
  # `"CanAlsoBe"`, `"StartsWith"`, `"Requires"`). The string is preserved
  # verbatim so callers can match it against future natures without a library
  # upgrade.
  struct Related
    include JSON::Serializable

    getter nature : String

    @[JSON::Field(key: "cweId")]
    getter cwe_id : Int32

    @[JSON::Field(key: "viewId")]
    getter view_id : Int32

    getter ordinal : String?

    @[JSON::Field(key: "chainId")]
    getter chain_id : String?

    def initialize(@nature, @cwe_id, @view_id, @ordinal = nil, @chain_id = nil)
    end

    def primary? : Bool
      ordinal == "Primary"
    end
  end

  struct Consequence
    include JSON::Serializable

    getter scope : String
    getter impact : String?
    getter likelihood : String?
    getter note : String?

    def initialize(@scope, @impact = nil, @likelihood = nil, @note = nil)
    end
  end

  struct Mitigation
    include JSON::Serializable

    @[JSON::Field(key: "mitigationId")]
    getter mitigation_id : String?

    getter phase : String?
    getter strategy : String?
    getter description : String?
    getter effectiveness : String?

    @[JSON::Field(key: "effectivenessNotes")]
    getter effectiveness_notes : String?

    def initialize(@mitigation_id = nil, @phase = nil, @strategy = nil,
                   @description = nil, @effectiveness = nil, @effectiveness_notes = nil)
    end
  end

  struct DetectionMethod
    include JSON::Serializable

    getter method : String

    @[JSON::Field(key: "methodId")]
    getter method_id : String?

    getter description : String?
    getter effectiveness : String?

    @[JSON::Field(key: "effectivenessNotes")]
    getter effectiveness_notes : String?

    def initialize(@method, @method_id = nil, @description = nil,
                   @effectiveness = nil, @effectiveness_notes = nil)
    end
  end

  struct ObservedExample
    include JSON::Serializable

    getter reference : String
    getter description : String?
    getter link : String?

    def initialize(@reference, @description = nil, @link = nil)
    end
  end

  struct AlternateTerm
    include JSON::Serializable

    getter term : String
    getter description : String?

    def initialize(@term, @description = nil)
    end
  end

  struct ModeOfIntroduction
    include JSON::Serializable

    getter phase : String
    getter note : String?

    def initialize(@phase, @note = nil)
    end
  end

  struct ApplicablePlatform
    include JSON::Serializable

    # One of `"Language"`, `"Technology"`, `"OperatingSystem"`,
    # `"Architecture"`, `"Paradigm"` — derived from which set of keys is
    # populated in the source row.
    getter kind : String
    getter name : String?

    @[JSON::Field(key: "class")]
    getter class_label : String?

    getter prevalence : String?
    getter version : String?

    def initialize(@kind, @name = nil, @class_label = nil, @prevalence = nil, @version = nil)
    end
  end

  struct TaxonomyMapping
    include JSON::Serializable

    @[JSON::Field(key: "taxonomyName")]
    getter taxonomy_name : String

    @[JSON::Field(key: "entryId")]
    getter entry_id : String?

    @[JSON::Field(key: "entryName")]
    getter entry_name : String?

    @[JSON::Field(key: "mappingFit")]
    getter mapping_fit : String?

    def initialize(@taxonomy_name, @entry_id = nil, @entry_name = nil, @mapping_fit = nil)
    end
  end

  struct Ordinality
    include JSON::Serializable

    getter ordinality : String
    getter description : String?

    def initialize(@ordinality, @description = nil)
    end
  end

  struct Note
    include JSON::Serializable

    getter type : String?
    getter note : String?

    def initialize(@type = nil, @note = nil)
    end
  end
end
