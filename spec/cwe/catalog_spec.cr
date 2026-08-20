require "../spec_helper"

# Wrap a list of weakness hashes in an otherwise well-formed Catalog document,
# so the graph specs below can be asserted against a hierarchy small enough to
# reason about.
private def catalog_doc(weaknesses, **rest)
  {
    "catalog_version" => "1.0",
    "generated_at"    => "2026-01-01T00:00:00Z",
    "weaknesses"      => weaknesses,
  }.merge(rest.to_h.transform_keys(&.to_s)).to_json
end

private def child_of(id, view = 1000, ordinal = nil)
  {"nature" => "ChildOf", "cwe_id" => id, "view_id" => view, "ordinal" => ordinal}
end

describe CWE::Catalog do
  describe "#pillar_of" do
    # Bug: the walk merged the `ChildOf` edges of *every* view and then picked
    # whichever Pillar happened to sit last in the BFS result. MITRE places the
    # Pillar tier only in the Research view (1000) and marks one parent per
    # entry `Primary`, so the merged walk answered with a pillar from a
    # different hierarchy for 188 of the 944 embedded entries.
    it "ignores edges borrowed from a non-Research view" do
      # CWE-15 is ChildOf CWE-642 in view 1000 and ChildOf CWE-20 in view 700
      # (7 Pernicious Kingdoms). Following the 7PK edge landed on CWE-707.
      CWE.find!(15).parent_relations.map { |r| {r.cwe_id, r.view_id} }
        .should eq([{642, 1000}, {610, 1000}, {20, 700}])
      CWE.pillar_of(15).try(&.id).should eq(664)
    end

    it "follows the Primary ordinal when Research-view parents disagree" do
      # CWE-13 -> 260 -> 522, and CWE-522 is ChildOf CWE-1390 (Primary) and
      # CWE-668 (secondary) in the same view; the two reach different pillars.
      CWE.find!(522).parent_relations
        .select { |r| r.view_id == 1000 }
        .map { |r| {r.cwe_id, r.primary?} }
        .should eq([{1390, true}, {668, false}])
      CWE.pillar_of(522).try(&.id).should eq(284)
      CWE.pillar_of(13).try(&.id).should eq(284)
    end

    it "matches MITRE's Research view on entries with a single chain" do
      CWE.pillar_of(79).try(&.id).should eq(707) # -> 74 -> 707
      CWE.pillar_of(41).try(&.id).should eq(664) # -> 706 -> 664
      CWE.pillar_of(14).try(&.id).should eq(435) # -> 733 -> 1038 -> 435
    end

    it "resolves a genuine Pillar for every entry in the catalog" do
      unresolved = CWE.all.reject do |w|
        CWE.pillar_of(w.id).try(&.abstraction) == CWE::Abstraction::Pillar
      end
      unresolved.map(&.id).should be_empty
    end

    it "returns the entry itself when it is already a Pillar" do
      CWE.with_abstraction(CWE::Abstraction::Pillar).each do |p|
        CWE.pillar_of(p.id).should be(p)
      end
    end

    it "falls back to the most distant ancestor when no Pillar is reachable" do
      cat = CWE::Catalog.from_json(catalog_doc([
        {"id" => 1, "name" => "Leaf", "abstraction" => "Variant",
         "related_weaknesses" => [child_of(2, ordinal: "Primary")]},
        {"id" => 2, "name" => "Top", "abstraction" => "Class"},
      ]))
      cat.pillar_of(1).try(&.id).should eq(2)
    end

    it "terminates on a cycle instead of recursing forever" do
      cat = CWE::Catalog.from_json(catalog_doc([
        {"id" => 1, "name" => "A", "abstraction" => "Base",
         "related_weaknesses" => [child_of(2, ordinal: "Primary")]},
        {"id" => 2, "name" => "B", "abstraction" => "Class",
         "related_weaknesses" => [child_of(1, ordinal: "Primary")]},
      ]))
      cat.pillar_of(1).try(&.id).should eq(2)
      cat.pillar_of(2).try(&.id).should eq(1)
      cat.ancestors_of(1).map(&.id).should eq([2, 1])
    end

    it "still finds a Pillar that only a secondary branch reaches" do
      # The Primary chain tops out at a Class; the walk must fall through to
      # the secondary edge rather than give up on the first branch.
      cat = CWE::Catalog.from_json(catalog_doc([
        {"id" => 1, "name" => "Leaf", "abstraction" => "Variant",
         "related_weaknesses" => [child_of(2, ordinal: "Primary"), child_of(3)]},
        {"id" => 2, "name" => "Dead end", "abstraction" => "Class"},
        {"id" => 3, "name" => "Root", "abstraction" => "Pillar"},
      ]))
      cat.pillar_of(1).try(&.id).should eq(3)
    end
  end

  describe "#children_of" do
    # Bug: the children index is keyed by `ChildOf` target, and `children_of`
    # read it without checking the target exists — so a dangling edge resolved
    # in one direction (`children_of`) but not the other (`parents_of`).
    it "reports a miss for an id that is not in the catalog" do
      cat = CWE::Catalog.from_json(catalog_doc([
        {"id" => 79, "name" => "Orphan", "related_weaknesses" => [child_of(999)]},
      ]))
      cat.find(999).should be_nil
      cat.parents_of(79).should be_empty
      cat.children_of(999).should be_empty
      cat.descendants_of(999).should be_empty
    end

    it "still resolves children for ids that are in the catalog" do
      CWE.children_of(79).map(&.id).should eq([80, 81, 83, 84, 85, 86, 87])
    end
  end

  describe ".from_json" do
    it "wraps a JSON syntax error in CWE::Error" do
      # Every other failure mode is already a CWE::Error; a caller should only
      # have to rescue the one type.
      ex = expect_raises(CWE::Error, /malformed CWE document/) do
        CWE::Catalog.from_json("{oops")
      end
      ex.cause.should be_a(JSON::ParseException)

      expect_raises(CWE::Error, /malformed CWE document/) do
        CWE::Catalog.from_json("")
      end
    end

    it "accepts an IO as well as a String" do
      io = IO::Memory.new(catalog_doc([{"id" => 79, "name" => "From IO"}]))
      CWE::Catalog.from_json(io).find!(79).name.should eq("From IO")
    end
  end

  describe "instance API" do
    it "memoises the embedded catalog" do
      CWE::Catalog.default.should be(CWE::Catalog.default)
      CWE.catalog.should be(CWE::Catalog.default)
    end

    it "reports a count for each entity kind" do
      cat = CWE::Catalog.default
      cat.size.should eq(CWE.all.size)
      cat.category_count.should eq(CWE.categories.size)
      cat.view_count.should eq(CWE.views.size)
      cat.external_reference_count.should eq(CWE.external_references.size)
    end

    it "iterates every entry in numeric id order" do
      ids = [] of Int32
      CWE.each { |w| ids << w.id }
      ids.size.should eq(CWE.size)
      ids.should eq(ids.sort)
    end

    it "supports [] / []? on the catalog object" do
      cat = CWE::Catalog.default
      cat[79].id.should eq(79)
      cat["CWE-79"].id.should eq(79)
      cat[79]?.try(&.id).should eq(79)
      cat[999_999]?.should be_nil
      cat["nope"]?.should be_nil
      expect_raises(CWE::NotFoundError) { cat[999_999] }
      expect_raises(CWE::ParseError) { cat["nope"] }
    end

    it "exposes the generated_at stamp of the embedded blob" do
      CWE::Catalog.default.generated_at.should match(/\A\d{4}-\d{2}-\d{2}T/)
    end
  end

  describe "#members_of" do
    it "resolves only Weakness members, skipping nested Categories" do
      # View 699 (Software Development) is assembled entirely out of
      # Categories, so there is nothing for members_of to resolve — the raw
      # edges are still reachable through View#members.
      view = CWE.view!(699)
      view.member_ids.should_not be_empty
      view.member_ids.all? { |m| !CWE.category(m).nil? }.should be_true
      CWE.members_of(699).should be_empty
    end

    it "returns an empty list for an id that is neither Category nor View" do
      CWE.members_of(79).should be_empty
    end
  end

  describe "#search" do
    it "matches the extended description, not just name and description" do
      cat = CWE::Catalog.from_json(catalog_doc([
        {"id" => 1, "name" => "Nothing here", "extended_description" => "a zibbleflux hazard"},
      ]))
      cat.search("zibbleflux").map(&.id).should eq([1])
      cat.search_by_name("zibbleflux").should be_empty
    end

    it "matches alternate terms and their descriptions" do
      cat = CWE::Catalog.from_json(catalog_doc([
        {"id" => 1, "name" => "Nothing here", "alternate_terms" => [
          {"term" => "Zibbleflux", "description" => "also called quaxing"},
        ]},
      ]))
      cat.search("zibbleflux").map(&.id).should eq([1])
      cat.search("QUAXING").map(&.id).should eq([1])
    end

    it "returns matches in numeric id order" do
      ids = CWE.search("injection").map(&.id)
      ids.should_not be_empty
      ids.should eq(ids.sort)
    end
  end

  describe "#external_reference" do
    it "exposes the full citation record" do
      ref = CWE.external_reference!("REF-1")
      ref.reference_id.should eq("REF-1")
      ref.title.should_not be_nil
      ref.url.should_not be_nil
      ref.authors.should_not be_empty
    end

    it "returns nil rather than raising for an unparseable id" do
      CWE.external_reference("").should be_nil
      CWE.external_reference("not a reference").should be_nil
    end
  end
end
