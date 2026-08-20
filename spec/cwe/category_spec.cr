require "../spec_helper"

describe CWE::Category do
  describe "#deprecated?" do
    # Gap: `Weakness#deprecated?` existed, but MITRE retires far more
    # Categories and Views than Weaknesses (35 and 4 in CWE 4.20) and neither
    # class could answer the question.
    it "detects the Deprecated status" do
      cat = CWE.category!(1)
      cat.name.should eq("DEPRECATED: Location")
      cat.status.should eq(CWE::Status::Deprecated)
      cat.deprecated?.should be_true
      CWE.categories.count(&.deprecated?).should eq(35)
    end

    it "does not treat Obsolete as Deprecated" do
      # CWE-16 "Configuration" is Obsolete: superseded, but not withdrawn.
      obsolete = CWE.category!(16)
      obsolete.status.should eq(CWE::Status::Obsolete)
      obsolete.deprecated?.should be_false
    end

    it "detects the DEPRECATED: name prefix on a document without the status" do
      CWE::Category.new(1, "DEPRECATED: Location", CWE::Status::Draft).deprecated?.should be_true
      CWE::Category.new(2, "Live one", CWE::Status::Draft).deprecated?.should be_false
    end
  end

  describe "identity and ordering" do
    it "builds cwe_id / url / to_s / inspect from the numeric id" do
      cat = CWE.category!(227)
      cat.cwe_id.should eq("CWE-227")
      cat.url.should eq("https://cwe.mitre.org/data/definitions/227.html")
      cat.to_s.should eq("CWE-227")
      cat.inspect.should eq(%(#<CWE::Category CWE-227 "7PK - API Abuse">))
    end

    it "orders and de-duplicates by numeric id" do
      a = CWE.category!(16)
      b = CWE.category!(227)
      (a < b).should be_true
      [b, a].sort.map(&.id).should eq([16, 227])
      Set{CWE.category!(227), CWE.category!("CWE-227")}.size.should eq(1)
    end

    it "is always Mapping_Prohibited" do
      CWE.categories.each do |cat|
        cat.mappable?.should be_false
      end
      CWE.category!(227).mapping_usage.should eq(CWE::MappingUsage::Prohibited)
    end
  end

  describe "#member_ids" do
    it "de-duplicates the raw Has_Member edges" do
      cat = CWE.category!(227)
      cat.member_ids.size.should eq(cat.member_ids.uniq.size)
      cat.members.first.view_id.should be > 0
      cat.member_ids.should eq(cat.members.map(&.cwe_id).uniq!)
    end

    it "resolves through Catalog#members_of, dropping unresolvable edges" do
      # Categories are drawn from the whole catalog, so some members are
      # weaknesses the Research view leaves out (CWE-251 is deprecated).
      ids = CWE.category!(227).member_ids
      resolved = CWE.members_of(227).map(&.id)
      resolved.should eq(ids.select { |m| CWE.includes?(m) })
      (ids - resolved).should eq([251])
    end
  end
end

describe CWE::View do
  it "reports type values from MITRE's ViewTypeEnumeration" do
    # The doc comment used to claim "Slice" / "Explicit Slice" / "Implicit
    # Slice"; MITRE's schema and the embedded catalog use these three.
    CWE.views.compact_map(&.type).to_set.should eq(Set{"Graph", "Explicit", "Implicit"})
    CWE.view!(1000).type.should eq("Graph")
  end

  it "detects deprecated views" do
    CWE.view!(630).deprecated?.should be_true
    CWE.view!(1000).deprecated?.should be_false
    CWE.views.count(&.deprecated?).should eq(4)
  end

  it "builds cwe_id / url / to_s / inspect from the numeric id" do
    v = CWE.view!(1000)
    v.cwe_id.should eq("CWE-1000")
    v.url.should eq("https://cwe.mitre.org/data/definitions/1000.html")
    v.to_s.should eq("CWE-1000")
    v.inspect.should eq(%(#<CWE::View CWE-1000 "Research Concepts">))
  end

  it "orders by numeric id and is always Mapping_Prohibited" do
    [CWE.view!(1000), CWE.view!(699)].sort.map(&.id).should eq([699, 1000])
    CWE.views.each(&.mappable?.should(be_false))
  end

  it "exposes the objective and, on a filtered view, its XPath filter" do
    CWE.view!(1000).objective.should_not be_nil
    filtered = CWE.views.find { |v| !v.filter.nil? }.should_not be_nil
    filtered.type.should eq("Implicit")
  end

  it "accepts string ids like every other lookup" do
    CWE.view("CWE-1000").should eq(CWE.view(1000))
    CWE.category("cwe-227").should eq(CWE.category(227))
    CWE.view("nonsense").should be_nil
    CWE.category("nonsense").should be_nil
  end
end
