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
      # MITRE stores no ParentOf/CanFollow edge anywhere (as of CWE 5.0).
      CWE.all.flat_map(&.child_relations).should be_empty
      CWE.all.flat_map(&.can_follow_relations).should be_empty
    end

    it "covers every nature the embedded catalog actually uses" do
      natures = CWE.all.flat_map(&.related_weaknesses).map(&.nature).to_set
      natures.should eq(Set{"ChildOf", "PeerOf", "CanPrecede", "CanAlsoBe", "Requires", "StartsWith", "Overlaps"})
    end

    it "selects the Overlaps edges CWE 5.0 introduced" do
      CWE.find!(788).overlaps_relations.map(&.cwe_id).should eq([126, 787])
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
    # Gap: the catalog came from MITRE's view-1000 CSV export, which leaves
    # deprecated weaknesses out, so looking one up by id missed.
    it "finds deprecated weaknesses, which the catalog now includes" do
      w = CWE.find!(71)
      w.status.should eq(CWE::Status::Deprecated)
      w.deprecated?.should be_true
      w.name.should eq("DEPRECATED: Apple '.DS_Store'")
      CWE.with_status(CWE::Status::Deprecated).size.should eq(28)
      CWE.all.count(&.deprecated?).should eq(28)
    end

    it "leaves deprecated entries out of the hierarchy MITRE does not put them in" do
      CWE.find!(71).related_weaknesses.should be_empty
      CWE.all.flat_map(&.related_weaknesses).map(&.cwe_id).should_not contain(71)
      CWE.pillar_of(71).should be_nil
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
      owasp.map(&.taxonomy_name).to_set.should eq(Set{"OWASP Top Ten 2004", "OWASP Top Ten 2007", "OWASP Golang Secure Coding Practices Guide"})
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
        "CWE-79: Improper Neutralization of Input During Web Page Generation (Base, Stable)"
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

  describe "structured CSV columns" do
    # Bug: the build kept one value per key, so a Consequence listing several
    # `Scope`s / `Impact`s (cwe_schema_v7.3: both maxOccurs="unbounded") kept
    # only the last of each.
    it "keeps every Scope and Impact of a consequence, in order" do
      c = CWE.find!(79).common_consequences.first
      c.scopes.should eq(["Access Control", "Confidentiality"])
      c.impacts.should eq(["Bypass Protection Mechanism", "Read Application Data"])
      c.scope.should eq("Access Control")
      c.impact.should eq("Bypass Protection Mechanism")
    end

    it "reads a document that carries a single scope / impact" do
      doc = {"weaknesses" => [{"id" => 1, "common_consequences" => [
        {"scope" => "Integrity", "impact" => "Modify Memory"},
      ]}]}.to_json
      c = CWE::Catalog.from_json(doc).find!(1).common_consequences.first
      c.scopes.should eq(["Integrity"])
      c.impacts.should eq(["Modify Memory"])

      legacy = CWE::Consequence.from_json(%({"scope":"Integrity","impact":"Modify Memory"}))
      legacy.scopes.should eq(["Integrity"])
      legacy.impacts.should eq(["Modify Memory"])
    end

    # Bug: a value containing `::` was split as if it were the entry
    # separator, leaving a truncated entry plus a bogus one.
    it "keeps a value that contains the entry separator" do
      CWE.find!(69).taxonomy_mappings.map(&.entry_name)
        .should eq(["Windows ::DATA alternate data stream"])
      ex = CWE.find!(428).observed_examples.find!(&.reference.==("CVE-2005-2938"))
      ex.description.should eq(%(CreateProcess() and CreateProcessAsUser() can be misused by applications to allow "program.exe" style attacks in C:))
      ex.link.should eq("https://www.cve.org/CVERecord?id=CVE-2005-2938")
      CWE.all.flat_map(&.observed_examples).none?(&.reference.empty?).should be_true

      CWE.find!(401).potential_mitigations
        .any?(&.description.try(&.includes?("std::auto_ptr"))).should be_true
    end

    # Bug: an empty value (`::PHASE::DESCRIPTION:...`) read as an entry break.
    it "keeps a mitigation whose phase is empty in one piece" do
      m = CWE.find!(122).potential_mitigations.first
      m.phase.should be_nil
      m.description.should eq("Pre-design: Use a language or compiler that performs automatic bounds checking.")
      CWE.all.flat_map(&.potential_mitigations).none?(&.description.nil?).should be_true
    end
  end

  describe "XML-derived text" do
    # Bug: the build copied the XML's pretty-printing whitespace into the
    # text and ignored the xhtml layout, so code lost the line breaks and
    # indentation MITRE encodes with `<xhtml:br/>` and nested
    # `<xhtml:div style="margin-left:1em;">`, and gained the source tabs
    # instead — this Python example was not valid Python.
    it "lays out example code from its xhtml markup" do
      code = CWE.find!(203).demonstrative_examples.flat_map(&.example_code)
        .find!(&.code.starts_with?("def validate_password")).code
      code.should eq(<<-PY)
        def validate_password(actual_pw, typed_pw):
            if len(actual_pw) <> len(typed_pw):
                return 0

            for i in len(actual_pw):
                if actual_pw[i] <> typed_pw[i]:
                    return 0

            return 1
        PY
    end

    it "keeps the spacing inside a line of code" do
      CWE.find!(1243).demonstrative_examples.flat_map(&.example_code)
        .flat_map(&.code.lines).should contain("assign key_big0    = debug_mode_i ? 192'b0 : {key0[0],")
    end

    it "collapses layout whitespace in prose, as MITRE's CSV export does" do
      layout = /[\t\n]|  /
      CWE.all.each do |w|
        w.demonstrative_examples.each do |e|
          e.intro_text.try(&.should_not match(layout))
          e.body_text.each(&.should_not match(layout))
        end
        w.references.each { |r| r.section.try(&.should_not match(layout)) }
      end
      notes = CWE.categories.flat_map(&.notes) + CWE.views.flat_map(&.notes)
      notes.each { |n| n.note.try(&.should_not match(layout)) }
      (CWE.all + CWE.categories + CWE.views).each do |e|
        e.mapping_notes.try do |m|
          m.rationale.try(&.should_not match(layout))
          m.comments.try(&.should_not match(layout))
        end
      end
      CWE.categories.each { |c| c.summary.try(&.should_not match(layout)) }
      CWE.views.each { |v| v.objective.try(&.should_not match(layout)) }
      CWE.external_references.each { |r| r.title.try(&.should_not match(layout)) }
      CWE.find!(862).references.find!(&.section.try(&.includes?("Determining")))
        .section.should eq(%(Chapter 4, "Authorization" Page 114; Chapter 6, "Determining Appropriate Access Control" Page 171))
    end
  end

  # The catalog used to come from MITRE's CSV export, which loses or mangles
  # data the XML carries. Each example below read differently (or not at
  # all) when the embedded data was built from the CSV.
  describe "XML-sourced fields the CSV export lost" do
    it "reads Likelihood_Of_Exploit, which the CSV left blank on every entry" do
      CWE.find!(79).likelihood_of_exploit.should eq("High")
      CWE.all.count(&.likelihood_of_exploit).should be > 150
      CWE.all.compact_map(&.likelihood_of_exploit).to_set.should eq(Set{"High", "Medium", "Low"})
    end

    it "keeps Mitigation_ID and Detection_Method_ID" do
      CWE.find!(79).potential_mitigations.map(&.mitigation_id).first(4)
        .should eq(["MIT-4", nil, "MIT-6", "MIT-15"])
      CWE.find!(78).detection_methods.map(&.method_id).first(3).should eq(["DM-1", "DM-2", "DM-10"])
      CWE.all.flat_map(&.detection_methods).count(&.method_id).should be > 500
    end

    it "keeps effectiveness notes" do
      CWE.find!(78).detection_methods.first.effectiveness_notes
        .should eq("This is not a perfect solution, since 100% accuracy and coverage are not feasible.")
    end

    it "lists every phase of a mitigation instead of joining them with a space" do
      m = CWE.find!(79).potential_mitigations[1]
      m.phases.should eq(["Implementation", "Architecture and Design"])
      m.phase.should eq("Implementation") # was "Implementation Architecture and Design"
      CWE.all.flat_map(&.potential_mitigations).none?(&.phase.try(&.includes?(" Architecture and Design"))).should be_true
    end

    it "lists every phase of a mode of introduction, Custom_Phase included" do
      intro = CWE.find!(7).modes_of_introduction.first
      intro.phases.should eq(["Implementation", "System Configuration", "Operation"])
      intro.phase.should eq("Implementation")
      CWE.find!(1427).modes_of_introduction.map(&.phases).should contain(["Implementation", "Training"])
      CWE.find!(1461).modes_of_introduction.first.phase.should eq("Implementation & Physical Design")
    end

    it "reads a document that carries a single phase" do
      doc = {"weaknesses" => [{"id" => 1,
                               "potential_mitigations" => [{"phase" => "Implementation"}],
                               "modes_of_introduction" => [{"phase" => "Operation"}]}]}.to_json
      w = CWE::Catalog.from_json(doc).find!(1)
      w.potential_mitigations.first.phases.should eq(["Implementation"])
      w.modes_of_introduction.first.phases.should eq(["Operation"])

      CWE::Mitigation.from_json(%({"phase":"Testing"})).phases.should eq(["Testing"])
      CWE::Mitigation.from_json(%({"phases":["Testing","Operation"]})).phase.should eq("Testing")
      CWE::Mitigation.new.phases.should be_empty
      CWE::ModeOfIntroduction.new("Operation").phases.should eq(["Operation"])
    end

    it "round-trips phases through JSON" do
      m = CWE.find!(79).potential_mitigations[1]
      back = CWE::Mitigation.from_json(m.to_json)
      back.phases.should eq(m.phases)
      back.phase.should eq(m.phase)
    end

    it "keeps the quotes and backslashes in names and text" do
      CWE.find!(28).name.should eq(%(Path Traversal: '..\\filedir'))
      CWE.find!(29).name.should eq(%(Path Traversal: '\\..\\filename'))
      CWE.find!(30).name.should eq(%(Path Traversal: '\\dir\\..\\filename'))
      CWE.find!(31).name.should eq(%(Path Traversal: 'dir\\..\\..\\filename'))
      CWE.find!(8).potential_mitigations.first.description.to_s.should contain(%(Declare Java beans "local"))
    end

    it "keeps a platform's Name and Class apart" do
      tech = CWE.find!(1259).applicable_platforms.select(&.kind.==("Technology"))
      tech.map { |p| {p.name, p.class_label} }
        .should eq([{"Processor Hardware", "Not Technology-Specific"}, {nil, "System on Chip"}])
    end

    it "exposes Technical_Nuance, where CWE 5.0 moved extended descriptions" do
      w = CWE.find!(79)
      w.technical_nuance.to_s.should start_with("There are many variants of cross-site scripting")
      CWE.search("different attack topologies").map(&.id).should contain(79)
      JSON.parse(w.to_json)["technicalNuance"].as_s.should eq(w.technical_nuance)
    end
  end
end
