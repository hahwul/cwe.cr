require "../spec_helper"

describe "CWE label enums" do
  describe CWE::Abstraction do
    it "parses every member of MITRE's AbstractionEnumeration" do
      {"Pillar"   => CWE::Abstraction::Pillar,
       "Class"    => CWE::Abstraction::Class,
       "Base"     => CWE::Abstraction::Base,
       "Variant"  => CWE::Abstraction::Variant,
       "Compound" => CWE::Abstraction::Compound}.each do |label, member|
        CWE::Abstraction.parse_label(label).should eq(member)
        CWE::Abstraction.parse_label(label.downcase).should eq(member)
        CWE::Abstraction.parse_label("  #{label}  ").should eq(member)
        member.to_s.should eq(label)
      end
    end

    it "keeps every abstraction level populated in the embedded catalog" do
      counts = CWE::Abstraction.values.to_h do |level|
        {level, CWE.with_abstraction(level).size}
      end
      counts[CWE::Abstraction::Other].should eq(0)
      CWE::Abstraction.values.reject(&.other?).each do |level|
        counts[level].should be > 0
      end
      counts.values.sum.should eq(CWE.size)
    end
  end

  describe CWE::Structure do
    it "treats an absent or blank label as Simple, per the schema default" do
      CWE::Structure.parse_label(nil).should eq(CWE::Structure::Simple)
      CWE::Structure.parse_label("").should eq(CWE::Structure::Simple)
      CWE::Structure.parse_label("  ").should eq(CWE::Structure::Simple)
    end

    it "parses the compound labels and buckets anything else as Other" do
      CWE::Structure.parse_label("Composite").should eq(CWE::Structure::Composite)
      CWE::Structure.parse_label("chain").should eq(CWE::Structure::Chain)
      CWE::Structure.parse_label("Chain of Trust").should eq(CWE::Structure::Other)
      CWE::Structure::Other.to_s.should eq("Other")
    end
  end

  describe CWE::MappingUsage do
    it "normalises the underscored spelling of Allowed-with-Review" do
      CWE::MappingUsage.parse_label("Allowed_with_Review")
        .should eq(CWE::MappingUsage::AllowedWithReview)
      CWE::MappingUsage.parse_label("allowed-with-review")
        .should eq(CWE::MappingUsage::AllowedWithReview)
      CWE::MappingUsage::AllowedWithReview.to_s.should eq("Allowed-with-Review")
    end

    it "covers the four usages MITRE assigns" do
      seen = CWE.all.map(&.mapping_usage).to_set
      seen.should eq(Set{
        CWE::MappingUsage::Allowed,
        CWE::MappingUsage::AllowedWithReview,
        CWE::MappingUsage::Discouraged,
        CWE::MappingUsage::Prohibited,
      })
    end
  end

  describe CWE::Status do
    it "parses every member of MITRE's StatusEnumeration" do
      {"Stable"     => CWE::Status::Stable,
       "Draft"      => CWE::Status::Draft,
       "Incomplete" => CWE::Status::Incomplete,
       "Deprecated" => CWE::Status::Deprecated,
       "Obsolete"   => CWE::Status::Obsolete,
       "Usable"     => CWE::Status::Usable}.each do |label, member|
        CWE::Status.parse_label(label).should eq(member)
        member.to_s.should eq(label)
      end
      CWE::Status.parse_label("Retired").should eq(CWE::Status::Other)
    end

    it "keeps the raw label available when it parsed to Other" do
      doc = {"weaknesses" => [{"id" => 79, "status" => "Provisional"}]}.to_json
      w = CWE::Catalog.from_json(doc).find!(79)
      w.status.should eq(CWE::Status::Other)
      w.raw_status.should eq("Provisional")
    end
  end
end

describe CWE::Related do
  it "reports the Primary ordinal" do
    rel = CWE.find!(79).parent_relations.find(&.primary?).should_not be_nil
    rel.cwe_id.should eq(74)
    rel.ordinal.should eq("Primary")
    CWE::Related.new("ChildOf", 74, 1000).primary?.should be_false
  end

  it "carries the chain id where MITRE assigns one" do
    chained = CWE.all.flat_map(&.related_weaknesses).select { |r| !r.chain_id.nil? }
    chained.should_not be_empty
  end
end

describe CWE::ApplicablePlatform do
  it "derives the kind from the populated key group" do
    kinds = CWE.all.flat_map(&.applicable_platforms).map(&.kind).to_set
    kinds.should eq(Set{"Language", "Technology", "OperatingSystem", "Architecture"})
    kinds.should_not contain("Unknown")
  end

  it "keeps class-only rows (no name) rather than dropping them" do
    class_only = CWE.all.flat_map(&.applicable_platforms)
      .select { |p| p.name.nil? && !p.class_label.nil? }
    class_only.should_not be_empty
    class_only.all? { |p| !p.prevalence.nil? }.should be_true
  end
end
