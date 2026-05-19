require "./spec_helper"

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
      parents = CWE.find!(79).parent_relations.map(&.cwe_id).uniq
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
  end
end
