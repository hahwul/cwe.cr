require "../spec_helper"

describe CWE::Weakness do
  describe "relationship accessors" do
    # Gap: `child_relations` and `can_follow_relations` had accessors even
    # though MITRE records neither nature (both are the inverse side of an
    # edge it stores once), while `CanAlsoBe`, `Requires` and `StartsWith` —
    # which the catalog really does use — had none.
    it "exposes CanAlsoBe edges" do
      CWE.find!(78).can_also_be_relations.map(&.cwe_id).should eq([88])
      CWE.all.count { |w| !w.can_also_be_relations.empty? }.should be > 0
    end

    it "exposes the Requires edges of a Composite entry" do
      w = CWE.find!(61)
      w.structure.should eq(CWE::Structure::Composite)
      w.requires_relations.map(&.cwe_id).should eq([362, 340, 386, 732])
    end

    it "exposes the StartsWith edge of a Chain entry" do
      w = CWE.find!(680)
      w.structure.should eq(CWE::Structure::Chain)
      w.starts_with_relations.map(&.cwe_id).should eq([190])
    end

    it "exposes PeerOf and CanPrecede edges" do
      CWE.find!(79).peer_relations.map(&.cwe_id).should eq([352])
      CWE.find!(20).can_precede_relations.map(&.cwe_id).should contain(22)
    end

    it "returns an empty list for a nature the entry does not use" do
      CWE.find!(79).related_with("NotARealNature").should be_empty
      # MITRE 4.20 stores no ParentOf/CanFollow edge anywhere.
      CWE.all.flat_map(&.child_relations).should be_empty
      CWE.all.flat_map(&.can_follow_relations).should be_empty
    end

    it "covers every nature the embedded catalog actually uses" do
      natures = CWE.all.flat_map(&.related_weaknesses).map(&.nature).to_set
      natures.should eq(Set{"ChildOf", "PeerOf", "CanPrecede", "CanAlsoBe", "Requires", "StartsWith"})
    end
  end

  describe "structure predicates" do
    it "classifies the seven Compound entries" do
      structures = [61, 352, 384, 680, 689, 690, 692].map { |i| {i, CWE.find!(i).structure} }
      structures.should eq([
        {61, CWE::Structure::Composite},
        {352, CWE::Structure::Composite},
        {384, CWE::Structure::Composite},
        {680, CWE::Structure::Chain},
        {689, CWE::Structure::Composite},
        {690, CWE::Structure::Chain},
        {692, CWE::Structure::Chain},
      ])
      CWE.find!(61).composite?.should be_true
      CWE.find!(61).chain?.should be_false
      CWE.find!(680).chain?.should be_true
      CWE.find!(680).composite?.should be_false
    end
  end

  describe "#deprecated?" do
    it "is false for every entry in the Research view" do
      # The embedded set is view 1000, which MITRE builds without deprecated
      # weaknesses — so the predicate has to be exercised on a document.
      CWE.all.count(&.deprecated?).should eq(0)
    end

    it "detects both the status and the DEPRECATED: name prefix" do
      by_status = CWE::Weakness.new(id: 1, name: "Anything", status: CWE::Status::Deprecated)
      by_status.deprecated?.should be_true

      by_name = CWE::Weakness.new(id: 2, name: "DEPRECATED: Location", status: CWE::Status::Draft)
      by_name.deprecated?.should be_true

      CWE::Weakness.new(id: 3, name: "Fine", status: CWE::Status::Stable).deprecated?.should be_false
    end
  end

  describe "mapping policy" do
    it "reports Discouraged Class-level entries as not mappable" do
      CWE.find!(20).mapping_usage.should eq(CWE::MappingUsage::Discouraged)
      CWE.find!(20).mappable?.should be_false
    end

    it "reports Allowed-with-Review entries as mappable" do
      w = CWE.all.find(&.mapping_usage.allowed_with_review?).should_not be_nil
      w.mappable?.should be_true
    end

    it "falls back to Other when an entry carries no Mapping_Notes block" do
      bare = CWE::Weakness.new(id: 1, name: "No mapping notes")
      bare.mapping_usage.should eq(CWE::MappingUsage::Other)
      bare.mappable?.should be_false
    end

    it "carries MITRE's alternative-mapping suggestions" do
      suggestions = CWE.find!(20).mapping_notes.should_not be_nil
      suggestions.suggestions.map(&.cwe_id).should contain(1284)
      suggestions.suggestions.each { |s| CWE.includes?(s.cwe_id).should be_true }
    end
  end

  describe "taxonomy helpers" do
    it "selects the OWASP rows out of taxonomy_mappings" do
      owasp = CWE.find!(79).owasp_mappings
      owasp.should_not be_empty
      owasp.map(&.taxonomy_name).to_set.should eq(Set{"OWASP Top Ten 2004", "OWASP Top Ten 2007"})
      owasp.all?(&.taxonomy_name.starts_with?("OWASP")).should be_true
    end

    it "aliases capec_ids to related_attack_patterns" do
      w = CWE.find!(79)
      w.capec_ids.should eq(w.related_attack_patterns)
      w.capec_ids.should contain(85)
    end
  end

  describe "string forms" do
    it "renders a one-line summary" do
      CWE.find!(79).summary.should eq(
        "CWE-79: Improper Neutralization of Input During Web Page Generation " \
        "('Cross-site Scripting') (Base, Stable)"
      )
    end

    it "prints the canonical id from to_s and the name from inspect" do
      w = CWE.find!(79)
      w.to_s.should eq("CWE-79")
      "#{w}".should eq("CWE-79")
      w.inspect.should eq(%(#<CWE::Weakness CWE-79 "#{w.name}">))
    end

    it "builds cwe_id and url from the numeric id" do
      w = CWE.find!(1004)
      w.cwe_id.should eq("CWE-1004")
      w.url.should eq("https://cwe.mitre.org/data/definitions/1004.html")
    end
  end
end
