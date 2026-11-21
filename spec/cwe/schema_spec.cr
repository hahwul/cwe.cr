require "../spec_helper"
require "../../data/catalog_xml"

describe "CWE XML schema" do
  it "evaluates implicit filters against a prefixed catalog without changing XPath syntax" do
    xml = <<-XML
      <c:Weakness_Catalog xmlns:c="http://cwe.mitre.org/cwe-8" Version="5.0">
        <c:Weaknesses>
          <c:Weakness ID="1" Name="A or B" Status="Draft"/>
          <c:Weakness ID="2" Name="Second" Status="Deprecated"/>
        </c:Weaknesses>
        <c:Views>
          <c:View ID="3" Name="Filtered" Type="Implicit">
            <c:Filter>/Weakness_Catalog/*[not(self::External_References)]/c:Weakness[attribute::Name='A or B' or @Status='Deprecated']</c:Filter>
          </c:View>
        </c:Views>
      </c:Weakness_Catalog>
      XML
    catalog = CWE::Catalog.from_json(CWE::CatalogXML.parse(xml).to_json)
    catalog.members_of(3).map(&.id).should eq([1, 2])
  end

  it "preserves image-only prose and preformatted example code" do
    xml = <<-XML
      <Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" xmlns:xhtml="http://www.w3.org/1999/xhtml" Version="5.0">
        <Weaknesses><Weakness ID="1"><Demonstrative_Examples><Demonstrative_Example>
          <Body_Text><xhtml:img alt="Diagram" src="/example.png"/></Body_Text>
          <Example_Code Nature="Informative"><xhtml:pre>def label():
          return 1</xhtml:pre></Example_Code>
        </Demonstrative_Example></Demonstrative_Examples></Weakness></Weaknesses>
      </Weakness_Catalog>
      XML
    catalog = CWE::Catalog.from_json(CWE::CatalogXML.parse(xml).to_json)
    example = catalog.find!(1).demonstrative_examples.first
    example.entries.first.should eq("Diagram (/example.png)")
    example.example_code.first.code.should eq("def label():\n    return 1")
    CWE.find!(1476).demonstrative_examples.first.entries.size.should eq(15)
  end

  it "retains the position and domain of a custom phase with the same name as a standard phase" do
    xml = <<-XML
      <Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" Version="5.0">
        <Weaknesses><Weakness ID="1"><Potential_Mitigations>
          <Mitigation><Phase>Testing</Phase><Custom_Phase Domain="AI">Testing</Custom_Phase></Mitigation>
          <Mitigation><Custom_Phase Domain="AI">Testing</Custom_Phase><Phase>Testing</Phase></Mitigation>
        </Potential_Mitigations></Weakness></Weaknesses>
      </Weakness_Catalog>
      XML
    catalog = CWE::Catalog.from_json(CWE::CatalogXML.parse(xml).to_json)
    first, second = catalog.find!(1).potential_mitigations
    custom = CWE::CustomPhase.new("AI", "Testing")
    first.phase_entries.should eq(["Testing", custom])
    second.phase_entries.should eq([custom, "Testing"])
    first.phases.should eq(["Testing", "Testing"])
    CWE::Mitigation.from_json(second.to_json).phase_entries.should eq(second.phase_entries)
  end

  it "rejects invalid and duplicate entry IDs before generating a catalog" do
    expect_raises(ArgumentError, /invalid ID/) do
      CWE::CatalogXML.parse(%(<Weakness_Catalog><Weaknesses><Weakness ID="1"/><Weakness ID="typo"/></Weaknesses></Weakness_Catalog>))
    end
    expect_raises(ArgumentError, /duplicate weakness ID 1/) do
      CWE::CatalogXML.parse(%(<Weakness_Catalog><Weaknesses><Weakness ID="1"/><Weakness ID="1"/></Weaknesses></Weakness_Catalog>))
    end
  end

  it "round-trips structured metadata from schema 8.0 through the catalog" do
    xml = <<-XML
      <Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" Name="CWE" Version="5.0" Date="2026-10-28">
        <Weaknesses>
          <Weakness ID="1" Name="Example weakness" Abstraction="Base" Structure="Simple" Status="Draft" Diagram="/example.png">
            <Description>Example description</Description>
            <Dimensions><Dimension Type="Behavior-Type">Comparison</Dimension></Dimensions>
            <Related_Weaknesses>
              <Related_Weakness Nature="ChildOf" CWE_ID="2" View_ID="3">
                <Dimensions><Dimension Type="Resource-Type">Page</Dimension></Dimensions>
              </Related_Weakness>
            </Related_Weaknesses>
            <Applicable_Platforms>
              <Operating_System Name="Linux" Version="6" CPE_ID="cpe:example" Prevalence="Undetermined">
                <Note>Platform context</Note>
              </Operating_System>
            </Applicable_Platforms>
            <Alternate_Terms>
              <Alternate_Term><Term>EC</Term><Role>Acronym</Role><Role>Common-Name</Role></Alternate_Term>
            </Alternate_Terms>
            <Modes_Of_Introduction>
              <Introduction><Custom_Phase Domain="AI">Training</Custom_Phase><Phase>Implementation</Phase></Introduction>
            </Modes_Of_Introduction>
            <Common_Consequences><Consequence Consequence_ID="CC-1"><Scope>Availability</Scope></Consequence></Common_Consequences>
            <Detection_Methods>
              <Detection_Method>
                <Method>Manual Analysis</Method><Custom_Phase Domain="Hardware">Hardware Architecture</Custom_Phase>
                <Description>Detection information</Description>
              </Detection_Method>
            </Detection_Methods>
            <Potential_Mitigations>
              <Mitigation><Custom_Phase Domain="AI">Testing</Custom_Phase><Description>Mitigation information</Description></Mitigation>
            </Potential_Mitigations>
            <Demonstrative_Examples>
              <Demonstrative_Example Demonstrative_Example_ID="DX-1">
                <Title_Text>Example title</Title_Text><Intro_Text>Example introduction</Intro_Text>
                <Body_Text>Before</Body_Text><Example_Code Nature="Informative" Language="Python">print(message)</Example_Code>
                <Body_Text>After</Body_Text>
              </Demonstrative_Example>
            </Demonstrative_Examples>
            <Observed_Examples>
              <Observed_Example>
                <Reference>CVE-2000-0001</Reference><Description>Case description</Description>
                <Link>https://example.com/case</Link><Rationale>Chain</Rationale>
              </Observed_Example>
            </Observed_Examples>
            <Mapping_Notes><Usage>Allowed</Usage><Rationale>Mapping guidance</Rationale></Mapping_Notes>
            <Notes><Note Type="Maintenance" Version="5.0" ReleaseDate="2026-10-28">A note</Note></Notes>
            <Content_History>
              <Submission>
                <Submission_Name>Ada</Submission_Name><Submission_Name>Grace</Submission_Name>
                <Submission_Date>2025-01-01</Submission_Date><Submission_Version>5.0</Submission_Version>
                <Submission_ReleaseDate>2026-10-28</Submission_ReleaseDate>
              </Submission>
              <Modification>
                <Modification_Date>2026-01-01</Modification_Date><Modification_Version>5.0</Modification_Version>
                <Modification_ReleaseDate>2026-10-28</Modification_ReleaseDate>
                <Modification_Importance>Critical</Modification_Importance><Modification_Comment>Updated</Modification_Comment>
              </Modification>
              <Contribution Type="Content">
                <Contribution_Name>Alex</Contribution_Name><Contribution_Name>Sam</Contribution_Name>
                <Contribution_Date>2026-01-01</Contribution_Date><Contribution_Version>5.0</Contribution_Version>
                <Contribution_ReleaseDate>2026-10-28</Contribution_ReleaseDate>
              </Contribution>
              <Previous_Entry_Name Date="2026-10-28" Version="5.0">Old name</Previous_Entry_Name>
            </Content_History>
          </Weakness>
        </Weaknesses>
        <Groupings>
          <Grouping ID="2" Name="Example grouping" Status="Draft">
            <Summary>Grouping summary</Summary>
            <Relationships>
              <Member_Of CWE_ID="3" View_ID="3"/>
              <Has_Member CWE_ID="1" View_ID="3">
                <Dimensions><Dimension Type="Behavior-Type">Comparison</Dimension></Dimensions>
              </Has_Member>
            </Relationships>
            <Mapping_Notes><Usage>Prohibited</Usage><Rationale>Grouping</Rationale></Mapping_Notes>
            <Content_History/>
          </Grouping>
        </Groupings>
        <External_References>
          <External_Reference Reference_ID="REF-1">
            <Title>Example source</Title><Alt_URL>https://example.com/archive</Alt_URL><Alt_URL_Date>2026-01-01</Alt_URL_Date>
          </External_Reference>
        </External_References>
      </Weakness_Catalog>
      XML
    catalog = CWE::Catalog.from_json(CWE::CatalogXML.parse(xml).to_json)
    catalog.catalog_name.should eq("CWE")
    catalog.catalog_date.should eq("2026-10-28")

    weakness = catalog.find!(1)
    weakness.diagram.should eq("/example.png")
    weakness.dimensions.should eq([CWE::Dimension.new("Behavior-Type", "Comparison")])
    weakness.related_weaknesses.first.dimensions.first.value.should eq("Page")
    weakness.applicable_platforms.first.note.should eq("Platform context")
    weakness.applicable_platforms.first.cpe_id.should eq("cpe:example")
    weakness.alternate_terms.first.roles.should eq(["Acronym", "Common-Name"])
    weakness.notes.first.release_date.should eq("2026-10-28")
    weakness.common_consequences.first.consequence_id.should eq("CC-1")
    weakness.observed_examples.first.rationales.should eq(["Chain"])

    intro = weakness.modes_of_introduction.first
    intro.phase.should eq("Training")
    intro.phases.should eq(["Training", "Implementation"])
    intro.custom_phases.should eq([CWE::CustomPhase.new("AI", "Training")])
    weakness.detection_methods.first.custom_phases.first.domain.should eq("Hardware")
    weakness.potential_mitigations.first.custom_phases.first.value.should eq("Testing")

    example = weakness.demonstrative_examples.first
    example.example_id.should eq("DX-1")
    example.title_text.should eq("Example title")
    example.entries.should eq(["Before", example.example_code.first, "After"])
    example.body_text.should eq(["Before", "After"])
    CWE::DemonstrativeExample.from_json(example.to_json).should eq(example)

    history = weakness.content_history.not_nil!
    history.submission_name.should eq("Ada")
    history.submissions.first.names.should eq(["Ada", "Grace"])
    history.contributions.first.names.should eq(["Alex", "Sam"])
    history.modifications.first.importance.should eq("Critical")
    history.last_modification_date.should eq("2026-01-01")
    history.modification_count.should eq(1)
    history.previous_entry_names.first.name.should eq("Old name")
    CWE::ContentHistory.from_json(history.to_json).should eq(history)

    grouping = catalog.category!(2)
    grouping.members.first.dimensions.first.type.should eq("Behavior-Type")
    grouping.member_of.first.cwe_id.should eq(3)
    JSON.parse(grouping.to_json)["memberOf"][0]["cweId"].as_i.should eq(3)
    catalog.external_reference!("REF-1").alt_url_date.should eq("2026-01-01")
    JSON.parse(weakness.to_json)["dimensions"][0]["value"].as_s.should eq("Comparison")
  end

  it "loads existing schema 7.x category names and single phases" do
    xml = <<-XML
      <Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.20" Date="2026-04-30">
        <Weaknesses>
          <Weakness ID="1" Name="Older weakness">
            <Modes_Of_Introduction><Introduction><Phase>Implementation</Phase></Introduction></Modes_Of_Introduction>
          </Weakness>
        </Weaknesses>
        <Categories>
          <Category ID="2" Name="Older category">
            <Relationships><Has_Member CWE_ID="1" View_ID="3"/></Relationships>
          </Category>
        </Categories>
      </Weakness_Catalog>
      XML
    catalog = CWE::Catalog.from_json(CWE::CatalogXML.parse(xml).to_json)
    catalog.catalog_version.should eq("4.20")
    catalog.members_of(2).map(&.id).should eq([1])
    intro = catalog.find!(1).modes_of_introduction.first
    intro.phase.should eq("Implementation")
    intro.custom_phases.should be_empty
  end

  it "includes the new metadata in the embedded CWE 5.0 catalog" do
    catalog = CWE.catalog
    catalog.catalog_date.should eq("2026-10-28")
    catalog.find!(79).parent_relations.first.dimensions.map(&.value).should contain("Web")
    catalog.find!(79).alternate_terms.find!(&.term.== "XSS").roles.should eq(["Acronym"])
    hardware = catalog.find!(1461)
    hardware.modes_of_introduction.first.custom_phases.first.domain.should eq("Hardware")
    hardware.content_history.not_nil!.contributions.map(&.names).should contain(["CWE Ad Hoc RTL WG"])
    catalog.find!(1342).content_history.not_nil!.submissions.first.names.size.should eq(2)
    catalog.find!(1114).observed_examples.flat_map(&.rationales).should contain("Chain")
    catalog.external_references.count { |r| r.alt_url }.should eq(6)
  end
end
