require "./spec_helper"

# Helper: wrap a list of (possibly malformed) weakness hashes in an otherwise
# well-formed top-level Catalog document for the hardening specs below.
private def malformed_catalog_doc(weaknesses)
  {
    "catalog_version" => "1.0",
    "generated_at"    => "2026-01-01T00:00:00Z",
    "weaknesses"      => weaknesses,
  }
end

describe CWE do
  it "exposes a version constant" do
    CWE::VERSION.should be_a(String)
  end

  it "embeds the MITRE catalog at compile time" do
    CWE.catalog_version.should match(/\d+\.\d+/)
    CWE.size.should be > 900
  end

  describe ".parse_id?" do
    it "parses canonical CWE strings" do
      CWE.parse_id?("CWE-79").should eq(79)
      CWE.parse_id?("cwe-79").should eq(79)
      CWE.parse_id?("CWE_79").should eq(79)
      CWE.parse_id?("CWE:79").should eq(79)
      CWE.parse_id?(" CWE-79 ").should eq(79)
      CWE.parse_id?("79").should eq(79)
    end

    it "returns nil on malformed input" do
      CWE.parse_id?("").should be_nil
      CWE.parse_id?("CWE-").should be_nil
      CWE.parse_id?("garbage").should be_nil
      CWE.parse_id?("CWE-abc").should be_nil
      CWE.parse_id?("CWE-12a").should be_nil
    end

    it "rejects the non-canonical separator-less form" do
      # "CWE79" (no separator between the prefix and the number) is not a
      # canonical CWE id and must not be accepted.
      CWE.parse_id?("CWE79").should be_nil
      CWE.parse_id?("cwe79").should be_nil
    end

    it "accepts a single space as the separator" do
      CWE.parse_id?("CWE 79").should eq(79)
    end

    it "rejects embedded whitespace and repeated separators" do
      # Bug: the separator class was `[-_:\s]+`, so newlines, tabs and runs
      # of mixed separators all parsed as a canonical id.
      CWE.parse_id?("CWE-\n79").should be_nil
      CWE.parse_id?("CWE-\t79").should be_nil
      CWE.parse_id?("CWE- 79").should be_nil
      CWE.parse_id?("CWE--79").should be_nil
      CWE.parse_id?("CWE-_:79").should be_nil
      CWE.parse_id?("CWE  79").should be_nil
      CWE.parse_id?("7 9").should be_nil
    end
  end

  describe ".parse_id" do
    it "raises ParseError on malformed input" do
      expect_raises(CWE::ParseError, /not a CWE id/) do
        CWE.parse_id("garbage")
      end
    end
  end

  describe ".find / .find!" do
    it "finds CWE-79 with its expected name" do
      w = CWE.find!("CWE-79")
      w.name.should eq(
        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
      )
      w.id.should eq(79)
      w.cwe_id.should eq("CWE-79")
      w.abstraction.should eq(CWE::Abstraction::Base)
      w.status.should eq(CWE::Status::Stable)
      w.url.should eq("https://cwe.mitre.org/data/definitions/79.html")
    end

    it "accepts integer ids, prefixed strings, and bare numbers" do
      [79, "79", "CWE-79", "cwe-79", "CWE_79"].each do |key|
        case key
        when Int
          CWE.find!(key).id.should eq(79)
        when String
          CWE.find!(key).id.should eq(79)
        end
      end
    end

    it "returns nil for unknown ids" do
      CWE.find(999_999).should be_nil
      CWE.find("CWE-999999").should be_nil
    end

    it "raises NotFoundError for unknown ids" do
      expect_raises(CWE::NotFoundError) { CWE.find!("CWE-999999") }
      expect_raises(CWE::NotFoundError) { CWE.find!(999_999) }
    end

    it "raises ParseError for unparseable strings" do
      expect_raises(CWE::ParseError) { CWE.find!("not-a-cwe") }
    end

    it "supports [] and []? indexing" do
      CWE[79].id.should eq(79)
      CWE["CWE-79"].id.should eq(79)
      CWE[999_999]?.should be_nil
      CWE["bogus"]?.should be_nil
    end

    it "includes? answers without raising" do
      CWE.includes?(79).should be_true
      CWE.includes?(999_999).should be_false
      CWE.includes?("CWE-79").should be_true
      CWE.includes?("bogus").should be_false
    end
  end

  describe "Weakness data — CWE-79 round-trip" do
    it "has common consequences with Confidentiality scope" do
      w = CWE.find!(79)
      w.common_consequences.should_not be_empty
      w.common_consequences.any? { |c| c.scope == "Confidentiality" }.should be_true
    end

    it "exposes potential mitigations" do
      w = CWE.find!(79)
      w.potential_mitigations.should_not be_empty
      w.potential_mitigations.any? { |m| m.description.try(&.includes?("encod")) }.should be_true
    end

    it "exposes detection methods" do
      CWE.find!(79).detection_methods.should_not be_empty
    end

    it "exposes alternate terms (XSS, HTML Injection, …)" do
      terms = CWE.find!(79).alternate_terms.map(&.term)
      terms.should contain("XSS")
    end

    it "exposes parent relationships via ChildOf edges" do
      parents = CWE.find!(79).parent_relations.map(&.cwe_id).uniq!
      parents.should contain(74)
    end
  end

  describe "Relationships" do
    it "traverses parents_of / children_of" do
      CWE.parents_of(79).map(&.id).should contain(74)
      CWE.children_of(79).should_not be_empty
    end

    it "walks to the pillar via ancestors_of" do
      pillar = CWE.pillar_of(79)
      pillar.should_not be_nil
      pillar.not_nil!.abstraction.should eq(CWE::Abstraction::Pillar)
    end

    it "ancestors_of returns nearest first" do
      ancestors = CWE.ancestors_of(79)
      ancestors.should_not be_empty
      ancestors.first.id.should eq(74)
    end

    it "descendants_of returns the full subtree" do
      descendants = CWE.descendants_of(79)
      descendants.size.should be >= CWE.children_of(79).size
    end
  end

  describe "Search" do
    it "finds by name substring" do
      results = CWE.search_by_name("cross-site scripting")
      results.map(&.id).should contain(79)
    end

    it "finds by full-text including description" do
      results = CWE.search("HttpOnly")
      results.map(&.id).should contain(1004)
    end

    it "is case-insensitive" do
      CWE.search("XSS").map(&.id).should contain(79)
      CWE.search("xss").map(&.id).should contain(79)
    end

    it "returns an empty list for an empty query" do
      CWE.search("").should be_empty
      CWE.search("   ").should be_empty
    end
  end

  describe "Filters" do
    it "filters by abstraction" do
      pillars = CWE.with_abstraction(CWE::Abstraction::Pillar)
      pillars.should_not be_empty
      pillars.all? { |w| w.abstraction == CWE::Abstraction::Pillar }.should be_true
    end

    it "filters by status" do
      stable = CWE.with_status(CWE::Status::Stable)
      stable.should_not be_empty
      stable.all? { |w| w.status == CWE::Status::Stable }.should be_true
    end
  end

  describe "Comparable / equality" do
    it "sorts weaknesses by numeric id" do
      a = CWE.find!(20)
      b = CWE.find!(79)
      (a < b).should be_true
      [b, a].sort.first.should eq(a)
    end

    it "equality is by id" do
      CWE.find!(79).should eq(CWE.find!("CWE-79"))
    end

    it "is usable as Hash / Set key" do
      set = Set(CWE::Weakness).new
      set << CWE.find!(79)
      set << CWE.find!("CWE-79")
      set.size.should eq(1)
    end
  end

  describe "JSON serialization" do
    it "emits an object with id, cweId, name, url" do
      json = JSON.parse(CWE.find!(79).to_json)
      json["id"].as_i.should eq(79)
      json["cweId"].as_s.should eq("CWE-79")
      json["name"].as_s.should contain("Cross-site Scripting")
      json["url"].as_s.should eq("https://cwe.mitre.org/data/definitions/79.html")
      json["abstraction"].as_s.should eq("Base")
      json["status"].as_s.should eq("Stable")
    end

    it "includes commonConsequences when present" do
      json = JSON.parse(CWE.find!(79).to_json)
      json["commonConsequences"]?.should_not be_nil
      json["commonConsequences"].as_a.size.should be > 0
    end

    it "omits empty arrays" do
      # Pick any entry; the assertion is that empty arrays aren't serialised.
      w = CWE.all.first
      serialised = JSON.parse(w.to_json).as_h
      serialised.values.all? do |v|
        !(v.as_a?.try(&.empty?) == true)
      end.should be_true
    end
  end

  describe "Abstraction / Status enums" do
    it "parses known labels" do
      CWE::Abstraction.parse_label("Base").should eq(CWE::Abstraction::Base)
      CWE::Abstraction.parse_label("pillar").should eq(CWE::Abstraction::Pillar)
      CWE::Abstraction.parse_label("nonsense").should eq(CWE::Abstraction::Other)
      CWE::Abstraction.parse_label(nil).should eq(CWE::Abstraction::Other)

      CWE::Status.parse_label("Stable").should eq(CWE::Status::Stable)
      CWE::Status.parse_label("incomplete").should eq(CWE::Status::Incomplete)
      CWE::Status.parse_label(nil).should eq(CWE::Status::Other)
    end

    it "round-trips labels via to_s" do
      CWE::Abstraction::Base.to_s.should eq("Base")
      CWE::Status::Stable.to_s.should eq("Stable")
    end
  end

  describe "Catalog from_json" do
    it "builds an isolated catalog from a JSON document" do
      doc = {
        "catalog_version" => "1.0",
        "generated_at"    => "2026-01-01T00:00:00Z",
        "weaknesses"      => [
          {
            "id"          => 79,
            "name"        => "Test entry",
            "abstraction" => "Base",
            "status"      => "Stable",
          },
        ],
      }.to_json
      cat = CWE::Catalog.from_json(doc)
      cat.size.should eq(1)
      cat.find!(79).name.should eq("Test entry")
    end

    it "raises a CWE::Error (not a raw KeyError) when 'weaknesses' is missing" do
      doc = {
        "catalog_version" => "1.0",
        "generated_at"    => "2026-01-01T00:00:00Z",
      }.to_json
      expect_raises(CWE::Error, /missing required "weaknesses"/) do
        CWE::Catalog.from_json(doc)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Regressions discovered during audit
  # ---------------------------------------------------------------------------

  describe "Data integrity (audit regressions)" do
    it "populates CAPEC IDs for entries that have them" do
      # Bug: the CAPEC column is encoded as a bare ::N::N:: list, not a
      # ::CAPEC ID:N:: keyed pair. The build script must parse the list form.
      CWE.find!(79).capec_ids.should_not be_empty
      CWE.find!(79).capec_ids.should contain(85)
      CWE.find!(89).capec_ids.should_not be_empty
    end

    it "parses Operating System applicable platforms" do
      # Bug: MITRE's CSV uses 'OPERATING SYSTEM …' with a space, not the
      # underscored form. Confirm the rebuild picks them up.
      os = CWE.all.flat_map(&.applicable_platforms).select { |p| p.kind == "OperatingSystem" }
      os.should_not be_empty
    end

    it "parses Architecture applicable platforms" do
      arch = CWE.all.flat_map(&.applicable_platforms).select { |p| p.kind == "Architecture" }
      arch.should_not be_empty
    end

    it "exposes background_details, functional_areas, affected_resources" do
      CWE.find!(22).functional_areas.should contain("File Processing")
      CWE.find!(22).affected_resources.should_not be_empty
      CWE.all.count { |w| !w.background_details.empty? }.should be > 0
    end

    it "keeps Compound as a first-class Abstraction" do
      # Bug: `Compound` had been dropped from the enum on the theory that it
      # duplicated `Structure`. It does not — MITRE's AbstractionEnumeration
      # lists it, and the seven affected entries carry both attributes. With
      # it missing they degraded into `Other`, the unknown-label bucket.
      CWE::Abstraction.parse_label("Compound").should eq(CWE::Abstraction::Compound)
      CWE::Abstraction::Compound.to_s.should eq("Compound")

      compounds = CWE.with_abstraction(CWE::Abstraction::Compound)
      compounds.map(&.id).should eq([61, 352, 384, 680, 689, 690, 692])
      compounds.all?(&.compound?).should be_true
      compounds.map(&.structure).to_set.should eq(
        Set{CWE::Structure::Composite, CWE::Structure::Chain}
      )

      # `Other` is reserved for labels the library does not know about.
      CWE.with_abstraction(CWE::Abstraction::Other).should be_empty
    end

    it "rejects integer-overflow CWE ids without crashing" do
      CWE.parse_id?("99999999999").should be_nil
      CWE.parse_id?("CWE-99999999999").should be_nil
    end

    it "accepts a stripped, leading-zero, mixed-case id" do
      CWE.parse_id?("0079").should eq(79)
      CWE.parse_id?("  Cwe-79  ").should eq(79)
    end
  end

  describe "collection accessors return copies" do
    # Bug: `children_of` handed back the pre-built index bucket itself, so a
    # caller mutating the result silently corrupted the catalog for the rest
    # of the process. Same for all/all_categories/all_views/external_references.
    it "does not let a caller mutate the children index" do
      before = CWE.children_of(79).size
      before.should be > 0
      CWE.children_of(79).clear
      CWE.children_of(79).size.should eq(before)
    end

    it "hands out a fresh array from all/categories/views/external_references" do
      CWE.all.same?(CWE.all).should be_false
      CWE.categories.same?(CWE.categories).should be_false
      CWE.views.same?(CWE.views).should be_false
      CWE.external_references.same?(CWE.external_references).should be_false

      size = CWE.size
      CWE.all.clear
      CWE.size.should eq(size)
      CWE.all.size.should eq(size)
    end
  end

  describe "out-of-range integer ids" do
    # Bug: every `Int`-keyed lookup narrowed with `to_i32`, so an id outside
    # the Int32 range raised OverflowError instead of reporting a miss.
    big = 3_000_000_000_i64

    it "reports a miss instead of raising OverflowError" do
      CWE.find(big).should be_nil
      CWE[big]?.should be_nil
      CWE.includes?(big).should be_false
      CWE.category(big).should be_nil
      CWE.view(big).should be_nil
      CWE.entry(big).should be_nil
      CWE.pillar_of(big).should be_nil
    end

    it "returns empty relationship sets instead of raising" do
      CWE.parents_of(big).should be_empty
      CWE.children_of(big).should be_empty
      CWE.ancestors_of(big).should be_empty
      CWE.descendants_of(big).should be_empty
      CWE.members_of(big).should be_empty
    end

    it "treats an out-of-range view_id as matching no edge" do
      CWE.parents_of(79, view_id: big).should be_empty
      CWE.children_of(79, view_id: big).should be_empty
    end

    it "still raises NotFoundError (not OverflowError) from bang lookups" do
      expect_raises(CWE::NotFoundError) { CWE.find!(big) }
      expect_raises(CWE::NotFoundError) { CWE.category!(big) }
      expect_raises(CWE::NotFoundError) { CWE.view!(big) }
    end
  end

  describe "Catalog perf invariants" do
    it "children_of uses the pre-built index (constant-time lookup)" do
      # Sanity: 1000 calls should be effectively instant.
      start = Time.instant
      1000.times { CWE.children_of(79) }
      elapsed = Time.instant - start
      elapsed.total_milliseconds.should be < 200
    end
  end

  describe "View-filtered relationship API" do
    it "filters parents_of by view id" do
      # CWE-79 has ChildOf -> CWE-74 in both view 1000 and view 1003.
      CWE.parents_of(79, view_id: 1000).map(&.id).should eq([74])
      CWE.parents_of(79, view_id: 1003).map(&.id).should eq([74])
      CWE.parents_of(79, view_id: 9999).should be_empty
    end

    it "filters children_of by view id" do
      kids_all = CWE.children_of(79).map(&.id).sort!
      kids_1000 = CWE.children_of(79, view_id: 1000).map(&.id).sort!
      kids_1000.should eq(kids_all) # children all live in view 1000 too
      CWE.children_of(79, view_id: 9999).should be_empty
    end
  end

  describe "pillar_of edge cases" do
    it "returns the entry itself when it is already a Pillar" do
      CWE.pillar_of(284).try(&.id).should eq(284)
    end

    it "returns nil for an id not in the catalog" do
      CWE.pillar_of(999_999).should be_nil
    end
  end

  describe "JSON output is camelCase throughout" do
    it "emits camelCase keys on nested objects too" do
      j = JSON.parse(CWE.find!(79).to_json).as_h
      # Top-level
      j["cweId"].as_s.should eq("CWE-79")
      # relatedWeaknesses entries use cweId/viewId, not cwe_id/view_id
      first_rel = j["relatedWeaknesses"].as_a.first.as_h
      first_rel.has_key?("cweId").should be_true
      first_rel.has_key?("cwe_id").should be_false
      # potentialMitigations: mitigationId/effectivenessNotes
      JSON.parse(CWE.find!(79).potential_mitigations.first.to_json).as_h.keys.none?(&.includes?("_")).should be_true
      # taxonomyMappings uses taxonomyName
      first_tax = j["taxonomyMappings"].as_a.first.as_h
      first_tax.has_key?("taxonomyName").should be_true
      first_tax.has_key?("taxonomy_name").should be_false
    end

    it "emits relatedAttackPatterns as an int array" do
      j = JSON.parse(CWE.find!(79).to_json).as_h
      j["relatedAttackPatterns"].as_a.all?(&.as_i?).should be_true
    end
  end

  # ---------------------------------------------------------------------------
  # Categories & Views (sourced from the XML supplement)
  # ---------------------------------------------------------------------------

  describe "Categories" do
    it "loads MITRE Categories alongside Weaknesses" do
      CWE.categories.size.should be > 100
    end

    it "looks up CWE-227 (7PK - API Abuse) as a Category" do
      cat = CWE.category!(227)
      cat.name.should eq("7PK - API Abuse")
      cat.member_ids.should_not be_empty
    end

    it "returns nil for a Weakness id via .category" do
      CWE.category(79).should be_nil
    end

    it "raises NotFoundError for an unknown category id" do
      expect_raises(CWE::NotFoundError) { CWE.category!(999_999) }
    end
  end

  describe "Views" do
    it "loads MITRE Views" do
      CWE.views.size.should be > 30
    end

    it "looks up CWE-1000 (Research Concepts) as a View" do
      v = CWE.view!(1000)
      v.name.should eq("Research Concepts")
      v.type.should eq("Graph")
      v.member_ids.should_not be_empty
    end

    it "members_of resolves member CWE ids to Weakness objects" do
      members = CWE.members_of(1000)
      members.should_not be_empty
      members.all?(CWE::Weakness).should be_true
    end
  end

  # ---------------------------------------------------------------------------
  # CWE 4.x XML-only fields: Demonstrative_Examples, References,
  # Mapping_Notes, Content_History, Structure, Audience
  # ---------------------------------------------------------------------------

  describe "Structure attribute" do
    it "parses Weakness#structure on standard entries" do
      CWE.find!(79).structure.should eq(CWE::Structure::Simple)
    end

    it "exposes chain?/composite? predicates" do
      w = CWE.find!(79)
      w.chain?.should be_false
      w.composite?.should be_false
      w.compound?.should be_false
    end

    it "marks at least one compound entry across the catalog" do
      compounds = CWE.all.select(&.compound?)
      compounds.should_not be_empty
    end
  end

  describe "Mapping_Notes" do
    it "parses Mapping_Notes on a Stable Base weakness" do
      w = CWE.find!(79)
      mn = w.mapping_notes
      mn.should_not be_nil
      mn.not_nil!.usage.should eq(CWE::MappingUsage::Allowed)
    end

    it "exposes mapping_usage / mappable? helpers" do
      CWE.find!(79).mapping_usage.should eq(CWE::MappingUsage::Allowed)
      CWE.find!(79).mappable?.should be_true
    end

    it "marks Categories as Prohibited" do
      cat = CWE.category!(227)
      cat.mapping_usage.should eq(CWE::MappingUsage::Prohibited)
      cat.mappable?.should be_false
    end

    it "marks Views as Prohibited" do
      v = CWE.view!(1000)
      v.mapping_usage.should eq(CWE::MappingUsage::Prohibited)
      v.mappable?.should be_false
    end

    it "parses Allowed-with-Review / Discouraged usages somewhere in the catalog" do
      usages = CWE.all.compact_map(&.mapping_notes).map(&.usage).to_set
      usages.should contain(CWE::MappingUsage::Discouraged)
    end
  end

  describe "Demonstrative_Examples" do
    it "populates intro/body/code on CWE-79" do
      examples = CWE.find!(79).demonstrative_examples
      examples.should_not be_empty
      examples.first.example_code.should_not be_empty
      examples.first.example_code.first.code.should_not be_empty
    end

    it "tags example code with language and nature where present" do
      examples = CWE.find!(89).demonstrative_examples
      examples.should_not be_empty
      natures = examples.flat_map(&.example_code).compact_map(&.nature).to_set
      # SQL injection has both 'Bad' and 'Good' code samples.
      natures.should contain("Bad")
    end
  end

  describe "External_References registry" do
    it "loads the catalog-level citation list" do
      CWE.external_references.should_not be_empty
      CWE.external_references.size.should be > 1000
    end

    it "resolves REF-* ids referenced by Weakness#references" do
      w = CWE.find!(79)
      w.references.should_not be_empty
      first = w.references.first
      ref = CWE.external_reference(first.external_reference_id)
      ref.should_not be_nil
      ref.not_nil!.reference_id.should eq(first.external_reference_id)
    end

    it "raises on unknown reference id via the bang variant" do
      expect_raises(CWE::NotFoundError) { CWE.external_reference!("REF-not-real") }
    end
  end

  describe "Content_History" do
    it "exposes submission_date and modification_count on CWE-79" do
      ch = CWE.find!(79).content_history
      ch.should_not be_nil
      ch.not_nil!.submission_date.should_not be_nil
      ch.not_nil!.modification_count.should be > 0
    end
  end

  describe "View Audience" do
    it "exposes stakeholders on CWE-1000 (Research Concepts)" do
      v = CWE.view!(1000)
      v.audience.should_not be_empty
      v.audience.first.type.should_not be_empty
    end
  end

  describe "Category XML extras" do
    it "exposes taxonomy_mappings and references on CWE-227" do
      cat = CWE.category!(227)
      cat.taxonomy_mappings.should_not be_empty
      cat.references.should_not be_empty
    end
  end

  describe "JSON serialization of new fields" do
    it "emits structure, mappingNotes, demonstrativeExamples, references" do
      j = JSON.parse(CWE.find!(79).to_json).as_h
      j["structure"].as_s.should eq("Simple")
      j["mappingNotes"].as_h["usage"].as_s.should eq("Allowed")
      j["demonstrativeExamples"].as_a.should_not be_empty
      j["references"].as_a.should_not be_empty
      j["contentHistory"].as_h.has_key?("submissionDate").should be_true
    end

    it "emits a Category with the new fields" do
      j = JSON.parse(CWE.category!(227).to_json).as_h
      j["mappingNotes"].as_h["usage"].as_s.should eq("Prohibited")
      j["taxonomyMappings"].as_a.should_not be_empty
    end

    it "emits a View with audience" do
      j = JSON.parse(CWE.view!(1000).to_json).as_h
      j["audience"].as_a.should_not be_empty
    end
  end

  describe "Unified entry lookup" do
    it "returns a Weakness for a weakness id" do
      CWE.entry(79).should be_a(CWE::Weakness)
    end

    it "returns a Category for a category id" do
      CWE.entry(227).should be_a(CWE::Category)
    end

    it "returns a View for a view id" do
      CWE.entry(1000).should be_a(CWE::View)
    end

    it "returns nil for an unknown id" do
      CWE.entry(999_999).should be_nil
    end
  end

  # ---------------------------------------------------------------------------
  # Malformed-input hardening (stability regressions)
  #
  # Every malformed Catalog.from_json document below used to surface a bare
  # KeyError or TypeCastError. Required fields must now raise a wrapped
  # CWE::Error; optional/repeated fields must parse gracefully (skipping the
  # offending element) instead of crashing.
  # ---------------------------------------------------------------------------
  describe "Catalog.from_json malformed-input hardening" do
    it "raises CWE::Error when 'weaknesses' is not an array" do
      doc = {
        "catalog_version" => "1.0",
        "generated_at"    => "2026-01-01T00:00:00Z",
        "weaknesses"      => "nope",
      }.to_json
      expect_raises(CWE::Error, /"weaknesses" must be an array/) do
        CWE::Catalog.from_json(doc)
      end
    end

    it "raises CWE::Error (not KeyError) when a weakness is missing its id" do
      doc = malformed_catalog_doc([{"name" => "No id here"}]).to_json
      expect_raises(CWE::Error, /weakness missing id/) do
        CWE::Catalog.from_json(doc)
      end
    end

    it "raises CWE::Error (not TypeCastError) when a weakness id is non-integer" do
      doc = malformed_catalog_doc([{"id" => "seventy-nine", "name" => "Bad id"}]).to_json
      expect_raises(CWE::Error, /weakness missing id/) do
        CWE::Catalog.from_json(doc)
      end
    end

    it "defaults a missing/null weakness name to \"\" instead of raising" do
      doc = malformed_catalog_doc([{"id" => 79}]).to_json
      cat = CWE::Catalog.from_json(doc)
      cat.find!(79).name.should eq("")

      doc_null = malformed_catalog_doc([{"id" => 80, "name" => nil}]).to_json
      cat_null = CWE::Catalog.from_json(doc_null)
      cat_null.find!(80).name.should eq("")
    end

    it "raises CWE::Error (not KeyError) when a category is missing its id" do
      doc = {
        "catalog_version" => "1.0",
        "generated_at"    => "2026-01-01T00:00:00Z",
        "weaknesses"      => [] of JSON::Any,
        "categories"      => [{"name" => "No id"}],
      }.to_json
      expect_raises(CWE::Error, /category missing id/) do
        CWE::Catalog.from_json(doc)
      end
    end

    it "raises CWE::Error (not KeyError) when a view is missing its id" do
      doc = {
        "catalog_version" => "1.0",
        "generated_at"    => "2026-01-01T00:00:00Z",
        "weaknesses"      => [] of JSON::Any,
        "views"           => [{"name" => "No id"}],
      }.to_json
      expect_raises(CWE::Error, /view missing id/) do
        CWE::Catalog.from_json(doc)
      end
    end

    it "raises CWE::Error (not KeyError) when an external reference lacks reference_id" do
      doc = {
        "catalog_version"     => "1.0",
        "generated_at"        => "2026-01-01T00:00:00Z",
        "weaknesses"          => [] of JSON::Any,
        "external_references" => [{"title" => "Citation with no id"}],
      }.to_json
      expect_raises(CWE::Error, /external reference missing reference_id/) do
        CWE::Catalog.from_json(doc)
      end
    end

    it "skips a non-object applicable_platforms element instead of crashing" do
      doc = malformed_catalog_doc([{
        "id"                   => 79,
        "name"                 => "Platform test",
        "applicable_platforms" => ["not-an-object", {"language_name" => "PHP"}],
      }]).to_json
      cat = CWE::Catalog.from_json(doc)
      platforms = cat.find!(79).applicable_platforms
      platforms.size.should eq(1)
      platforms.first.name.should eq("PHP")
    end

    it "skips string elements in related_attack_patterns instead of crashing" do
      doc = malformed_catalog_doc([{
        "id"                      => 79,
        "name"                    => "CAPEC test",
        "related_attack_patterns" => [85, "not-an-int", 588],
      }]).to_json
      cat = CWE::Catalog.from_json(doc)
      cat.find!(79).related_attack_patterns.should eq([85, 588])
    end

    it "treats a non-array related_attack_patterns as empty instead of crashing" do
      doc = malformed_catalog_doc([{
        "id"                      => 79,
        "name"                    => "CAPEC test",
        "related_attack_patterns" => "85",
      }]).to_json
      cat = CWE::Catalog.from_json(doc)
      cat.find!(79).related_attack_patterns.should be_empty
    end

    it "raises CWE::Error when the top level is not an object" do
      expect_raises(CWE::Error, /top level must be an object/) do
        CWE::Catalog.from_json("[]")
      end
    end

    it "raises CWE::Error when categories/views/external_references are not arrays" do
      {"categories", "views", "external_references"}.each do |key|
        doc = {"weaknesses" => [] of JSON::Any, key => "nope"}.to_json
        expect_raises(CWE::Error, /"#{key}" must be an array/) do
          CWE::Catalog.from_json(doc)
        end
      end
    end

    it "raises CWE::Error (not a bare Exception) for non-object entries" do
      expect_raises(CWE::Error, /each weakness must be an object/) do
        CWE::Catalog.from_json(malformed_catalog_doc([1, 2, 3]).to_json)
      end
      expect_raises(CWE::Error, /each category must be an object/) do
        CWE::Catalog.from_json({"weaknesses" => [] of JSON::Any, "categories" => ["x"]}.to_json)
      end
      expect_raises(CWE::Error, /each view must be an object/) do
        CWE::Catalog.from_json({"weaknesses" => [] of JSON::Any, "views" => ["x"]}.to_json)
      end
    end

    it "treats an out-of-range weakness id as a missing id" do
      doc = malformed_catalog_doc([{"id" => 3_000_000_000_i64}]).to_json
      expect_raises(CWE::Error, /weakness missing id/) do
        CWE::Catalog.from_json(doc)
      end
    end

    it "treats a non-array repeated field as empty instead of crashing" do
      doc = malformed_catalog_doc([{
        "id"                 => 79,
        "related_weaknesses" => "nope",
        "notes"              => 5,
        "observed_examples"  => {"a" => "b"},
      }]).to_json
      w = CWE::Catalog.from_json(doc).find!(79)
      w.related_weaknesses.should be_empty
      w.notes.should be_empty
      w.observed_examples.should be_empty
    end

    it "skips non-object elements of repeated object fields" do
      doc = malformed_catalog_doc([{
        "id"    => 79,
        "notes" => ["a string", {"type" => "Other", "note" => "kept"}],
      }]).to_json
      notes = CWE::Catalog.from_json(doc).find!(79).notes
      notes.size.should eq(1)
      notes.first.note.should eq("kept")
    end

    it "skips non-string elements of repeated string fields" do
      doc = malformed_catalog_doc([{
        "id"                 => 79,
        "functional_areas"   => ["File Processing", 5, nil],
        "background_details" => "not-an-array",
      }]).to_json
      w = CWE::Catalog.from_json(doc).find!(79)
      w.functional_areas.should eq(["File Processing"])
      w.background_details.should be_empty
    end

    it "ignores a non-object mapping_notes / content_history block" do
      doc = malformed_catalog_doc([{
        "id"              => 79,
        "mapping_notes"   => "Allowed",
        "content_history" => ["2006-07-19"],
      }]).to_json
      w = CWE::Catalog.from_json(doc).find!(79)
      w.mapping_notes.should be_nil
      w.content_history.should be_nil
    end

    it "treats a non-array members list as empty instead of crashing" do
      doc = {
        "weaknesses" => [] of JSON::Any,
        "categories" => [{"id" => 227, "members" => "nope"}],
      }.to_json
      CWE::Catalog.from_json(doc).category!(227).members.should be_empty
    end

    it "falls back to defaults when catalog_version is not a string" do
      doc = {"catalog_version" => 4.2, "weaknesses" => [] of JSON::Any}.to_json
      CWE::Catalog.from_json(doc).catalog_version.should eq("unknown")
    end

    it "skips a non-object mapping suggestion instead of crashing" do
      doc = malformed_catalog_doc([{
        "id"            => 79,
        "name"          => "Mapping test",
        "mapping_notes" => {
          "usage"       => "Allowed",
          "suggestions" => ["not-an-object", {"cwe_id" => 89, "comment" => "ok"}],
        },
      }]).to_json
      cat = CWE::Catalog.from_json(doc)
      notes = cat.find!(79).mapping_notes.not_nil!
      notes.suggestions.size.should eq(1)
      notes.suggestions.first.cwe_id.should eq(89)
    end
  end
end
