require "../spec_helper"

describe "CWE JSON serialization" do
  describe CWE::MappingNotes do
    # Bug: `to_json` never wrote `rawUsage`, but `from_json` reads it — so the
    # one thing the field exists for (a MITRE label newer than the enum, which
    # parses to `Other`) was dropped the moment the entry was serialized.
    it "round-trips a usage label the enum does not know" do
      notes = CWE::MappingNotes.new(
        usage: CWE::MappingUsage::Other,
        raw_usage: "Allowed-with-Supervision",
        rationale: "hypothetical future label",
      )
      restored = CWE::MappingNotes.from_json(notes.to_json)
      restored.usage.should eq(CWE::MappingUsage::Other)
      restored.raw_usage.should eq("Allowed-with-Supervision")
      restored.rationale.should eq("hypothetical future label")
    end

    it "does not repeat a raw label that already matches the canonical one" do
      # Every entry in the current catalog is in this shape, so the emitted
      # document stays as compact as it was.
      notes = CWE.find!(79).mapping_notes.should_not be_nil
      notes.raw_usage.should eq("Allowed")
      JSON.parse(notes.to_json).as_h.has_key?("rawUsage").should be_false
      CWE.all.compact_map(&.mapping_notes)
        .count(&.to_json.includes?("rawUsage")).should eq(0)
    end

    it "round-trips the reasons and suggestions lists" do
      notes = CWE.find!(20).mapping_notes.should_not be_nil
      restored = CWE::MappingNotes.from_json(notes.to_json)
      restored.usage.should eq(CWE::MappingUsage::Discouraged)
      restored.reasons.should eq(notes.reasons)
      restored.suggestions.map(&.cwe_id).should eq(notes.suggestions.map(&.cwe_id))
    end
  end

  describe CWE::Weakness do
    it "omits absent scalars rather than emitting null" do
      w = CWE::Weakness.new(id: 1, name: "Bare")
      JSON.parse(w.to_json).as_h.keys.should eq(
        %w[id cweId name url abstraction status structure]
      )
    end

    it "emits every populated block of a fully-detailed entry" do
      keys = JSON.parse(CWE.find!(79).to_json).as_h.keys
      %w[
        description extendedDescription relatedWeaknesses ordinalities
        applicablePlatforms alternateTerms modesOfIntroduction
        commonConsequences detectionMethods potentialMitigations
        observedExamples taxonomyMappings relatedAttackPatterns
        demonstrativeExamples references mappingNotes contentHistory
      ].each { |key| keys.should contain(key) }
    end

    it "emits the string-list blocks when they are populated" do
      j = JSON.parse(CWE.find!(22).to_json).as_h
      j["functionalAreas"].as_a.map(&.as_s).should contain("File Processing")
      j["affectedResources"].as_a.should_not be_empty

      background = CWE.all.find { |w| !w.background_details.empty? }.should_not be_nil
      JSON.parse(background.to_json).as_h["backgroundDetails"].as_a.should_not be_empty
    end

    it "nests observed examples with their CVE reference" do
      first = JSON.parse(CWE.find!(79).to_json)["observedExamples"].as_a.first.as_h
      first["reference"].as_s.should start_with("CVE-")
      first.keys.none?(&.includes?("_")).should be_true
    end
  end

  describe CWE::Category do
    it "serializes members and the Prohibited mapping policy" do
      j = JSON.parse(CWE.category!(227).to_json).as_h
      j["cweId"].as_s.should eq("CWE-227")
      j["url"].as_s.should eq("https://cwe.mitre.org/data/definitions/227.html")
      j["status"].as_s.should eq(CWE.category!(227).status.to_s)
      j["summary"].as_s.should_not be_empty
      j["mappingNotes"].as_h["usage"].as_s.should eq("Prohibited")
      member = j["members"].as_a.first.as_h
      member.keys.should eq(%w[cweId viewId])
    end

    it "omits blocks a category does not carry" do
      bare = CWE::Category.new(9999, "Nothing")
      JSON.parse(bare.to_json).as_h.keys.should eq(%w[id cweId name url status])
    end
  end

  describe CWE::View do
    it "serializes type, objective, audience and members" do
      j = JSON.parse(CWE.view!(1000).to_json).as_h
      j["type"].as_s.should eq("Graph")
      j["objective"].as_s.should_not be_empty
      j["audience"].as_a.first.as_h.has_key?("type").should be_true
      j["members"].as_a.size.should eq(CWE.view!(1000).members.size)
    end

    it "emits the filter of a filtered view" do
      filtered = CWE.views.find { |v| !v.filter.nil? }.should_not be_nil
      JSON.parse(filtered.to_json).as_h["filter"].as_s.should_not be_empty
    end
  end
end
