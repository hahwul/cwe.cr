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
    Other

    def self.parse_label(s : String?) : Abstraction
      case s.try(&.strip).try(&.downcase)
      when "pillar"  then Pillar
      when "class"   then Class
      when "base"    then Base
      when "variant" then Variant
      else                Other
      end
    end

    def to_s : String
      case self
      in Pillar  then "Pillar"
      in Class   then "Class"
      in Base    then "Base"
      in Variant then "Variant"
      in Other   then "Other"
      end
    end

    def to_s(io : IO) : Nil
      io << to_s
    end
  end

  # Internal structure of a Weakness. MITRE encodes this as the
  # `Structure` attribute on `<Weakness>` and uses it to mark Compound
  # entries (`Chain`, `Composite`) vs the standard `Simple` form.
  enum Structure
    Simple
    Composite
    Chain
    Other

    def self.parse_label(s : String?) : Structure
      case s.try(&.strip).try(&.downcase)
      when "simple"    then Simple
      when "composite" then Composite
      when "chain"     then Chain
      else                  Other
      end
    end

    def to_s : String
      case self
      in Simple    then "Simple"
      in Composite then "Composite"
      in Chain     then "Chain"
      in Other     then "Other"
      end
    end

    def to_s(io : IO) : Nil
      io << to_s
    end
  end

  # Mapping policy as assigned by MITRE in CWE 4.x. Determines whether the
  # entry is an acceptable target when mapping a CVE / finding to a CWE.
  # Categories and Views are always `Prohibited`; Weaknesses may be
  # `Allowed`, `Allowed-with-Review`, `Discouraged`, or `Prohibited`.
  enum MappingUsage
    Allowed
    AllowedWithReview
    Discouraged
    Prohibited
    Other

    def self.parse_label(s : String?) : MappingUsage
      case s.try(&.strip).try(&.downcase).try(&.gsub('_', '-'))
      when "allowed"             then Allowed
      when "allowed-with-review" then AllowedWithReview
      when "discouraged"         then Discouraged
      when "prohibited"          then Prohibited
      else                            Other
      end
    end

    def to_s : String
      case self
      in Allowed           then "Allowed"
      in AllowedWithReview then "Allowed-with-Review"
      in Discouraged       then "Discouraged"
      in Prohibited        then "Prohibited"
      in Other             then "Other"
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

  # A code/intro example shipped with a CWE entry. Captures the prose
  # (`intro_text`, `body_text`) and one or more code snippets, each tagged
  # with the language and the nature of the snippet (`Bad`, `Good`,
  # `Attack`, `Result`, `Informative`).
  struct DemonstrativeExample
    include JSON::Serializable

    @[JSON::Field(key: "introText")]
    getter intro_text : String?

    @[JSON::Field(key: "bodyText")]
    getter body_text : Array(String)

    @[JSON::Field(key: "exampleCode")]
    getter example_code : Array(ExampleCode)

    @[JSON::Field(key: "referenceIds")]
    getter reference_ids : Array(String)

    def initialize(@intro_text = nil,
                   @body_text = [] of String,
                   @example_code = [] of ExampleCode,
                   @reference_ids = [] of String)
    end
  end

  struct ExampleCode
    include JSON::Serializable

    getter nature : String?
    getter language : String?
    getter code : String

    def initialize(@code, @nature = nil, @language = nil)
    end
  end

  # An entry in `Weakness#references` / `Category#references` / `View#references`.
  # Points at a row in the catalog-level `external_references` registry by
  # `external_reference_id` (e.g. `"REF-2"`). Use `Catalog#external_reference`
  # to resolve.
  struct ReferenceLink
    include JSON::Serializable

    @[JSON::Field(key: "externalReferenceId")]
    getter external_reference_id : String

    getter section : String?

    def initialize(@external_reference_id, @section = nil)
    end
  end

  # A catalog-level citation. CWE stores all references once in a global
  # registry; individual entries link to them by id.
  struct ExternalReference
    include JSON::Serializable

    @[JSON::Field(key: "referenceId")]
    getter reference_id : String

    getter authors : Array(String)
    getter title : String?
    getter edition : String?
    getter publication : String?

    @[JSON::Field(key: "publicationYear")]
    getter publication_year : String?

    @[JSON::Field(key: "publicationMonth")]
    getter publication_month : String?

    @[JSON::Field(key: "publicationDay")]
    getter publication_day : String?

    getter publisher : String?
    getter url : String?

    @[JSON::Field(key: "urlDate")]
    getter url_date : String?

    def initialize(@reference_id,
                   @authors = [] of String,
                   @title = nil,
                   @edition = nil,
                   @publication = nil,
                   @publication_year = nil,
                   @publication_month = nil,
                   @publication_day = nil,
                   @publisher = nil,
                   @url = nil,
                   @url_date = nil)
    end
  end

  # CWE 4.x `Mapping_Notes` block. The `usage` field is what tooling cares
  # about most — it determines whether the entry is an acceptable mapping
  # target for a CVE / finding. The raw label is preserved on
  # `raw_usage` for forward compatibility.
  struct MappingNotes
    include JSON::Serializable

    getter usage : MappingUsage

    @[JSON::Field(key: "rawUsage")]
    getter raw_usage : String?

    getter rationale : String?
    getter comments : String?

    # `Mapping_Notes/Reasons/Reason/@Type` values such as `"Frequent-Misuse"`,
    # `"Acceptable-Use"`, `"Prohibited"`, `"Abstraction"`, etc.
    getter reasons : Array(String)

    # `Mapping_Notes/Suggestions/Suggestion` — a list of related CWEs that
    # MITRE recommends as alternative mapping targets.
    getter suggestions : Array(MappingSuggestion)

    def initialize(@usage = MappingUsage::Other,
                   @raw_usage = nil,
                   @rationale = nil,
                   @comments = nil,
                   @reasons = [] of String,
                   @suggestions = [] of MappingSuggestion)
    end
  end

  struct MappingSuggestion
    include JSON::Serializable

    @[JSON::Field(key: "cweId")]
    getter cwe_id : Int32

    getter comment : String?

    def initialize(@cwe_id, @comment = nil)
    end
  end

  # Compact view of an entry's revision history. The full XML record
  # contains a verbose list of modifications; we expose only the most
  # commonly queried fields (first submission, latest modification).
  struct ContentHistory
    include JSON::Serializable

    @[JSON::Field(key: "submissionDate")]
    getter submission_date : String?

    @[JSON::Field(key: "submissionName")]
    getter submission_name : String?

    @[JSON::Field(key: "submissionOrganization")]
    getter submission_organization : String?

    @[JSON::Field(key: "lastModificationDate")]
    getter last_modification_date : String?

    @[JSON::Field(key: "modificationCount")]
    getter modification_count : Int32

    def initialize(@submission_date = nil,
                   @submission_name = nil,
                   @submission_organization = nil,
                   @last_modification_date = nil,
                   @modification_count = 0)
    end
  end

  # A stakeholder description from a CWE `View`'s `Audience` block.
  struct Stakeholder
    include JSON::Serializable

    getter type : String
    getter description : String?

    def initialize(@type, @description = nil)
    end
  end
end
