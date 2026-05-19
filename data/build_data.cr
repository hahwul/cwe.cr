# Build script: parses MITRE CWE CSV export into the compact JSON file
# that the library embeds at compile time.
#
# Usage:
#   crystal run data/build_data.cr
#
# Inputs:
#   data/cwec.csv  — MITRE export (view 1000, full Research view)
#
# Outputs:
#   src/cwe/data/weaknesses.json
#
# The MITRE CSV uses a "::FIELD:value:FIELD2:value2::FIELD:value3:..::"
# encoding for structured columns. We split on "::" to find entries, then
# tokenise each entry on ":" and walk through keyed by the known field names
# for that column. Values that contain literal ":" are reassembled by joining
# tokens that don't match a known field name.
require "csv"
require "json"
require "xml"
require "file_utils"

ROOT     = File.expand_path("..", __DIR__)
CSV_PATH = File.join(ROOT, "data", "cwec.csv")
OUT_DIR  = File.join(ROOT, "src", "cwe", "data")
OUT_PATH = File.join(OUT_DIR, "weaknesses.json")

# Optional: when this XML file is present, Categories and Views are
# extracted from it too. The CSV export only contains weaknesses, so the
# XML is the only source for these auxiliary entities.
XML_PATH_CANDIDATES = [
  File.join(ROOT, "data", "cwec.xml"),
] + Dir.glob(File.join(ROOT, "data", "cwec_v*.xml"))

# Known field names per structured column. Tokens that exactly equal one of
# these are treated as keys; everything in between is the value.
RELATED_FIELDS    = Set{"NATURE", "CWE ID", "VIEW ID", "ORDINAL", "CHAIN ID"}
ORDINALITY_FIELDS = Set{"ORDINALITY", "DESCRIPTION"}
PLATFORM_FIELDS   = Set{
  "LANGUAGE NAME", "LANGUAGE CLASS", "LANGUAGE PREVALENCE",
  "TECHNOLOGY NAME", "TECHNOLOGY CLASS", "TECHNOLOGY PREVALENCE",
  # MITRE's CSV uses "OPERATING SYSTEM …" with a space, not "OPERATING_SYSTEM …".
  "OPERATING SYSTEM NAME", "OPERATING SYSTEM CLASS", "OPERATING SYSTEM PREVALENCE", "OPERATING SYSTEM VERSION",
  "ARCHITECTURE NAME", "ARCHITECTURE CLASS", "ARCHITECTURE PREVALENCE",
  "PARADIGM NAME", "PARADIGM CLASS", "PARADIGM PREVALENCE",
}
ALT_TERM_FIELDS    = Set{"TERM", "DESCRIPTION"}
INTRO_FIELDS       = Set{"PHASE", "NOTE"}
CONSEQUENCE_FIELDS = Set{"SCOPE", "IMPACT", "NOTE", "LIKELIHOOD"}
DETECTION_FIELDS   = Set{"METHOD", "METHOD ID", "DESCRIPTION", "EFFECTIVENESS", "EFFECTIVENESS NOTES"}
MITIGATION_FIELDS  = Set{"MITIGATION ID", "PHASE", "STRATEGY", "DESCRIPTION", "EFFECTIVENESS", "EFFECTIVENESS NOTES"}
EXAMPLE_FIELDS     = Set{"REFERENCE", "DESCRIPTION", "LINK"}
TAXONOMY_FIELDS    = Set{"TAXONOMY NAME", "ENTRY ID", "ENTRY NAME", "MAPPING FIT"}
NOTE_FIELDS        = Set{"TYPE", "NOTE"}

# Some columns are encoded as a bare list of values (no field names), e.g.
# `::209::588::591::592::63::`. `parse_bare_list` splits on `::` and returns
# the non-empty trimmed values.
def parse_bare_list(raw : String) : Array(String)
  result = [] of String
  return result if raw.strip.empty?
  raw.split("::").each do |chunk|
    next if chunk.empty?
    trimmed = chunk.strip
    result << trimmed unless trimmed.empty?
  end
  result
end

def parse_structured(raw : String, known : Set(String)) : Array(Hash(String, String))
  result = [] of Hash(String, String)
  return result if raw.strip.empty?

  raw.split("::").each do |entry|
    next if entry.strip.empty?

    h = {} of String => String
    tokens = entry.split(":")
    i = 0
    while i < tokens.size
      tok = tokens[i]
      if known.includes?(tok)
        j = i + 1
        parts = [] of String
        while j < tokens.size && !known.includes?(tokens[j])
          parts << tokens[j]
          j += 1
        end
        h[tok] = parts.join(":").strip
        i = j
      else
        i += 1
      end
    end
    result << h unless h.empty?
  end
  result
end

def take_first(rows : Array(Hash(String, String)), field : String) : String?
  rows.each do |r|
    if v = r[field]?
      return v unless v.empty?
    end
  end
  nil
end

def emit_related(rows : Array(Hash(String, String))) : Array(Hash(String, JSON::Any))
  rows.map do |r|
    h = {} of String => JSON::Any
    h["nature"] = JSON::Any.new(r["NATURE"]? || "")
    if cwe_id = r["CWE ID"]?
      h["cwe_id"] = JSON::Any.new(cwe_id.to_i64?.try { |i| JSON::Any.new(i) } || JSON::Any.new(cwe_id))
    end
    h["view_id"] = JSON::Any.new(r["VIEW ID"]? || "")
    h["ordinal"] = JSON::Any.new(r["ORDINAL"]? || "")
    h["chain_id"] = JSON::Any.new(r["CHAIN ID"]? || "")
    h
  end
end

# -----------------------------------------------------------------------------

abort "missing CSV: #{CSV_PATH}" unless File.exists?(CSV_PATH)
FileUtils.mkdir_p(OUT_DIR)

raw = File.read(CSV_PATH)
csv = CSV.new(raw, headers: true)

weaknesses = [] of Hash(String, JSON::Any)
meta_version = "unknown"

while csv.next
  id_str = csv["CWE-ID"].strip
  next if id_str.empty?
  id = id_str.to_i? || next

  name = csv["Name"]
  abstraction = csv["Weakness Abstraction"]
  structure = nil # Not in CSV; will stay null
  status = csv["Status"]
  description = csv["Description"]
  ext_desc = csv["Extended Description"]
  likelihood = csv["Likelihood of Exploit"]

  related = parse_structured(csv["Related Weaknesses"], RELATED_FIELDS)
  ordinalities = parse_structured(csv["Weakness Ordinalities"], ORDINALITY_FIELDS)
  platforms = parse_structured(csv["Applicable Platforms"], PLATFORM_FIELDS)
  alt_terms = parse_structured(csv["Alternate Terms"], ALT_TERM_FIELDS)
  intros = parse_structured(csv["Modes Of Introduction"], INTRO_FIELDS)
  consequences = parse_structured(csv["Common Consequences"], CONSEQUENCE_FIELDS)
  detections = parse_structured(csv["Detection Methods"], DETECTION_FIELDS)
  mitigations = parse_structured(csv["Potential Mitigations"], MITIGATION_FIELDS)
  examples = parse_structured(csv["Observed Examples"], EXAMPLE_FIELDS)
  taxonomies = parse_structured(csv["Taxonomy Mappings"], TAXONOMY_FIELDS)
  # CAPEC IDs are encoded as a bare `::N::N::` list, not key/value pairs.
  capecs = parse_bare_list(csv["Related Attack Patterns"])
  notes = parse_structured(csv["Notes"], NOTE_FIELDS)

  background_details = parse_bare_list(csv["Background Details"])
  functional_areas = parse_bare_list(csv["Functional Areas"])
  affected_resources = parse_bare_list(csv["Affected Resources"])
  exploitation_factors = parse_bare_list(csv["Exploitation Factors"])

  h = {} of String => JSON::Any
  h["id"] = JSON::Any.new(id.to_i64)
  h["name"] = JSON::Any.new(name)
  h["abstraction"] = JSON::Any.new(abstraction) unless abstraction.empty?
  h["status"] = JSON::Any.new(status) unless status.empty?
  h["description"] = JSON::Any.new(description) unless description.empty?
  h["extended_description"] = JSON::Any.new(ext_desc) unless ext_desc.empty?
  h["likelihood_of_exploit"] = JSON::Any.new(likelihood) unless likelihood.empty?

  unless related.empty?
    arr = related.map do |r|
      inner = {} of String => JSON::Any
      inner["nature"] = JSON::Any.new(r["NATURE"]? || "")
      if cwe_id = r["CWE ID"]?
        inner["cwe_id"] = JSON::Any.new(cwe_id.to_i64? || 0_i64)
      end
      inner["view_id"] = JSON::Any.new((r["VIEW ID"]? || "").to_i64? || 0_i64)
      inner["ordinal"] = JSON::Any.new(r["ORDINAL"]? || "") if r["ORDINAL"]?
      inner["chain_id"] = JSON::Any.new(r["CHAIN ID"]? || "") if r["CHAIN ID"]?
      JSON::Any.new(inner)
    end
    h["related_weaknesses"] = JSON::Any.new(arr)
  end

  unless ordinalities.empty?
    arr = ordinalities.map do |r|
      inner = {} of String => JSON::Any
      inner["ordinality"] = JSON::Any.new(r["ORDINALITY"]? || "")
      inner["description"] = JSON::Any.new(r["DESCRIPTION"]? || "") if r["DESCRIPTION"]?
      JSON::Any.new(inner)
    end
    h["ordinalities"] = JSON::Any.new(arr)
  end

  unless platforms.empty?
    arr = platforms.map do |r|
      inner = {} of String => JSON::Any
      r.each { |k, v| inner[k.downcase.tr(" ", "_")] = JSON::Any.new(v) }
      JSON::Any.new(inner)
    end
    h["applicable_platforms"] = JSON::Any.new(arr)
  end

  unless alt_terms.empty?
    arr = alt_terms.map do |r|
      inner = {} of String => JSON::Any
      inner["term"] = JSON::Any.new(r["TERM"]? || "")
      inner["description"] = JSON::Any.new(r["DESCRIPTION"]? || "") if r["DESCRIPTION"]?
      JSON::Any.new(inner)
    end
    h["alternate_terms"] = JSON::Any.new(arr)
  end

  unless intros.empty?
    arr = intros.map do |r|
      inner = {} of String => JSON::Any
      inner["phase"] = JSON::Any.new(r["PHASE"]? || "")
      inner["note"] = JSON::Any.new(r["NOTE"]? || "") if r["NOTE"]?
      JSON::Any.new(inner)
    end
    h["modes_of_introduction"] = JSON::Any.new(arr)
  end

  unless consequences.empty?
    arr = consequences.map do |r|
      inner = {} of String => JSON::Any
      inner["scope"] = JSON::Any.new(r["SCOPE"]? || "")
      inner["impact"] = JSON::Any.new(r["IMPACT"]? || "") if r["IMPACT"]?
      inner["likelihood"] = JSON::Any.new(r["LIKELIHOOD"]? || "") if r["LIKELIHOOD"]?
      inner["note"] = JSON::Any.new(r["NOTE"]? || "") if r["NOTE"]?
      JSON::Any.new(inner)
    end
    h["common_consequences"] = JSON::Any.new(arr)
  end

  unless detections.empty?
    arr = detections.map do |r|
      inner = {} of String => JSON::Any
      inner["method"] = JSON::Any.new(r["METHOD"]? || "")
      inner["method_id"] = JSON::Any.new(r["METHOD ID"]? || "") if r["METHOD ID"]?
      inner["description"] = JSON::Any.new(r["DESCRIPTION"]? || "") if r["DESCRIPTION"]?
      inner["effectiveness"] = JSON::Any.new(r["EFFECTIVENESS"]? || "") if r["EFFECTIVENESS"]?
      inner["effectiveness_notes"] = JSON::Any.new(r["EFFECTIVENESS NOTES"]? || "") if r["EFFECTIVENESS NOTES"]?
      JSON::Any.new(inner)
    end
    h["detection_methods"] = JSON::Any.new(arr)
  end

  unless mitigations.empty?
    arr = mitigations.map do |r|
      inner = {} of String => JSON::Any
      inner["mitigation_id"] = JSON::Any.new(r["MITIGATION ID"]? || "") if r["MITIGATION ID"]?
      inner["phase"] = JSON::Any.new(r["PHASE"]? || "") if r["PHASE"]?
      inner["strategy"] = JSON::Any.new(r["STRATEGY"]? || "") if r["STRATEGY"]?
      inner["description"] = JSON::Any.new(r["DESCRIPTION"]? || "") if r["DESCRIPTION"]?
      inner["effectiveness"] = JSON::Any.new(r["EFFECTIVENESS"]? || "") if r["EFFECTIVENESS"]?
      inner["effectiveness_notes"] = JSON::Any.new(r["EFFECTIVENESS NOTES"]? || "") if r["EFFECTIVENESS NOTES"]?
      JSON::Any.new(inner)
    end
    h["potential_mitigations"] = JSON::Any.new(arr)
  end

  unless examples.empty?
    arr = examples.map do |r|
      inner = {} of String => JSON::Any
      inner["reference"] = JSON::Any.new(r["REFERENCE"]? || "")
      inner["description"] = JSON::Any.new(r["DESCRIPTION"]? || "") if r["DESCRIPTION"]?
      inner["link"] = JSON::Any.new(r["LINK"]? || "") if r["LINK"]?
      JSON::Any.new(inner)
    end
    h["observed_examples"] = JSON::Any.new(arr)
  end

  unless taxonomies.empty?
    arr = taxonomies.map do |r|
      inner = {} of String => JSON::Any
      inner["taxonomy_name"] = JSON::Any.new(r["TAXONOMY NAME"]? || "")
      inner["entry_id"] = JSON::Any.new(r["ENTRY ID"]? || "") if r["ENTRY ID"]?
      inner["entry_name"] = JSON::Any.new(r["ENTRY NAME"]? || "") if r["ENTRY NAME"]?
      inner["mapping_fit"] = JSON::Any.new(r["MAPPING FIT"]? || "") if r["MAPPING FIT"]?
      JSON::Any.new(inner)
    end
    h["taxonomy_mappings"] = JSON::Any.new(arr)
  end

  unless capecs.empty?
    arr = capecs.compact_map { |s| s.to_i64?.try { |i| JSON::Any.new(i) } }
    h["related_attack_patterns"] = JSON::Any.new(arr) unless arr.empty?
  end

  unless background_details.empty?
    h["background_details"] = JSON::Any.new(background_details.map { |s| JSON::Any.new(s) })
  end
  unless functional_areas.empty?
    h["functional_areas"] = JSON::Any.new(functional_areas.map { |s| JSON::Any.new(s) })
  end
  unless affected_resources.empty?
    h["affected_resources"] = JSON::Any.new(affected_resources.map { |s| JSON::Any.new(s) })
  end
  unless exploitation_factors.empty?
    h["exploitation_factors"] = JSON::Any.new(exploitation_factors.map { |s| JSON::Any.new(s) })
  end

  unless notes.empty?
    arr = notes.map do |r|
      inner = {} of String => JSON::Any
      inner["type"] = JSON::Any.new(r["TYPE"]? || "") if r["TYPE"]?
      inner["note"] = JSON::Any.new(r["NOTE"]? || "") if r["NOTE"]?
      JSON::Any.new(inner)
    end
    h["notes"] = JSON::Any.new(arr)
  end

  weaknesses << h
end

# Sort by ID for stable diffs
weaknesses.sort_by! { |h| h["id"].as_i64 }

# Catalog version is detected from, in order:
#   1. $CWE_CATALOG_VERSION env var
#   2. a sibling `cwec_vX.Y.xml` file (MITRE ships this alongside the CSV)
#   3. a `data/VERSION` text file
if v = ENV["CWE_CATALOG_VERSION"]?
  meta_version = v.strip
end
if meta_version == "unknown"
  Dir.glob(File.join(ROOT, "data", "cwec_v*.xml")).each do |f|
    if md = f.match(/cwec_v([\d.]+)\.xml/)
      meta_version = md[1]
    end
  end
end
if meta_version == "unknown"
  vfile = File.join(ROOT, "data", "VERSION")
  meta_version = File.read(vfile).strip if File.exists?(vfile)
end

# --- Extract Weakness-level XML-only fields ---------------------------------
#
# The CSV omits these blocks entirely; they only exist in the XML. We index
# them by CWE id and merge them into the JSON output below.
xml_extras = {} of Int32 => Hash(String, JSON::Any)
external_refs = [] of Hash(String, JSON::Any)
# Categories and Views accumulate the same xml-derived blocks (notes,
# taxonomy_mappings, references, mapping_notes, content_history, audience).
category_extras = {} of Int32 => Hash(String, JSON::Any)
view_extras = {} of Int32 => Hash(String, JSON::Any)

# Collapse the xhtml content of a `<xhtml:div>` (used inside Example_Code)
# into a plain string. `<xhtml:br/>` becomes a newline; other tags are
# stripped but their text content is preserved.
def render_xhtml(node : XML::Node) : String
  io = String::Builder.new
  walk = uninitialized XML::Node -> Nil
  walk = ->(n : XML::Node) do
    n.children.each do |c|
      if c.element?
        case c.name
        when "br"
          io << '\n'
        else
          walk.call(c)
        end
      else
        io << c.content
      end
    end
  end
  walk.call(node)
  io.to_s.strip
end

def child_named(parent : XML::Node, local : String) : XML::Node?
  parent.children.find { |c| c.element? && c.name == local }
end

def children_named(parent : XML::Node, local : String) : Array(XML::Node)
  parent.children.select { |c| c.element? && c.name == local }.map(&.as(XML::Node))
end

def text_of_child(parent : XML::Node, local : String) : String?
  if c = child_named(parent, local)
    s = c.content.strip
    s.empty? ? nil : s
  end
end

# Parses `<Mapping_Notes>` into the JSON shape consumed by Catalog.from_json.
def parse_mapping_notes(node : XML::Node) : Hash(String, JSON::Any)
  h = {} of String => JSON::Any
  usage = text_of_child(node, "Usage")
  h["usage"] = JSON::Any.new(usage) if usage
  if r = text_of_child(node, "Rationale")
    h["rationale"] = JSON::Any.new(r)
  end
  if c = text_of_child(node, "Comments")
    h["comments"] = JSON::Any.new(c)
  end
  if reasons_node = child_named(node, "Reasons")
    rs = [] of JSON::Any
    children_named(reasons_node, "Reason").each do |r|
      if t = r["Type"]?
        rs << JSON::Any.new(t)
      end
    end
    h["reasons"] = JSON::Any.new(rs) unless rs.empty?
  end
  if suggestions_node = child_named(node, "Suggestions")
    ss = [] of JSON::Any
    children_named(suggestions_node, "Suggestion").each do |s|
      cid = s["CWE_ID"]?.try(&.to_i64?)
      next unless cid
      inner = {} of String => JSON::Any
      inner["cwe_id"] = JSON::Any.new(cid)
      if c = s["Comment"]?
        inner["comment"] = JSON::Any.new(c)
      end
      ss << JSON::Any.new(inner)
    end
    h["suggestions"] = JSON::Any.new(ss) unless ss.empty?
  end
  h
end

# Parses `<Content_History>` into a compact summary record.
def parse_content_history(node : XML::Node) : Hash(String, JSON::Any)
  h = {} of String => JSON::Any
  if sub = child_named(node, "Submission")
    if d = text_of_child(sub, "Submission_Date")
      h["submission_date"] = JSON::Any.new(d)
    end
    if n = text_of_child(sub, "Submission_Name")
      h["submission_name"] = JSON::Any.new(n)
    end
    if o = text_of_child(sub, "Submission_Organization")
      h["submission_organization"] = JSON::Any.new(o)
    end
  end
  mods = children_named(node, "Modification")
  h["modification_count"] = JSON::Any.new(mods.size.to_i64)
  if last = mods.last?
    if d = text_of_child(last, "Modification_Date")
      h["last_modification_date"] = JSON::Any.new(d)
    end
  end
  h
end

def parse_references(node : XML::Node) : Array(JSON::Any)
  arr = [] of JSON::Any
  children_named(node, "Reference").each do |r|
    next unless rid = r["External_Reference_ID"]?
    inner = {} of String => JSON::Any
    inner["external_reference_id"] = JSON::Any.new(rid)
    if sec = r["Section"]?
      inner["section"] = JSON::Any.new(sec)
    end
    arr << JSON::Any.new(inner)
  end
  arr
end

def parse_notes(node : XML::Node) : Array(JSON::Any)
  arr = [] of JSON::Any
  children_named(node, "Note").each do |n|
    inner = {} of String => JSON::Any
    inner["type"] = JSON::Any.new(n["Type"]? || "")
    text = n.content.strip
    inner["note"] = JSON::Any.new(text) unless text.empty?
    arr << JSON::Any.new(inner)
  end
  arr
end

def parse_taxonomy_mappings(node : XML::Node) : Array(JSON::Any)
  arr = [] of JSON::Any
  children_named(node, "Taxonomy_Mapping").each do |t|
    inner = {} of String => JSON::Any
    inner["taxonomy_name"] = JSON::Any.new(t["Taxonomy_Name"]? || "")
    if eid = text_of_child(t, "Entry_ID")
      inner["entry_id"] = JSON::Any.new(eid)
    end
    if en = text_of_child(t, "Entry_Name")
      inner["entry_name"] = JSON::Any.new(en)
    end
    if mf = text_of_child(t, "Mapping_Fit")
      inner["mapping_fit"] = JSON::Any.new(mf)
    end
    arr << JSON::Any.new(inner)
  end
  arr
end

def parse_audience(node : XML::Node) : Array(JSON::Any)
  arr = [] of JSON::Any
  children_named(node, "Stakeholder").each do |s|
    inner = {} of String => JSON::Any
    inner["type"] = JSON::Any.new(text_of_child(s, "Type") || "")
    if d = text_of_child(s, "Description")
      inner["description"] = JSON::Any.new(d)
    end
    arr << JSON::Any.new(inner)
  end
  arr
end

def parse_demonstrative_examples(node : XML::Node) : Array(JSON::Any)
  arr = [] of JSON::Any
  children_named(node, "Demonstrative_Example").each do |de|
    inner = {} of String => JSON::Any
    intro = nil
    bodies = [] of JSON::Any
    codes = [] of JSON::Any
    ref_ids = [] of JSON::Any

    de.children.each do |c|
      next unless c.element?
      case c.name
      when "Intro_Text"
        s = c.content.strip
        intro = s unless s.empty?
      when "Body_Text"
        s = c.content.strip
        bodies << JSON::Any.new(s) unless s.empty?
      when "Example_Code"
        rendered = render_xhtml(c)
        next if rendered.empty?
        ch = {} of String => JSON::Any
        ch["code"] = JSON::Any.new(rendered)
        if nat = c["Nature"]?
          ch["nature"] = JSON::Any.new(nat)
        end
        if lang = c["Language"]?
          ch["language"] = JSON::Any.new(lang)
        end
        codes << JSON::Any.new(ch)
      when "References"
        children_named(c, "Reference").each do |r|
          if rid = r["External_Reference_ID"]?
            ref_ids << JSON::Any.new(rid)
          end
        end
      end
    end

    inner["intro_text"] = JSON::Any.new(intro) if intro
    inner["body_text"] = JSON::Any.new(bodies) unless bodies.empty?
    inner["example_code"] = JSON::Any.new(codes) unless codes.empty?
    inner["reference_ids"] = JSON::Any.new(ref_ids) unless ref_ids.empty?
    arr << JSON::Any.new(inner) unless inner.empty?
  end
  arr
end

# --- Extract Categories and Views from the XML (optional) -------------------
#
# The XML uses the `http://cwe.mitre.org/cwe-7` default namespace. Crystal's
# `XML.parse` keeps that namespace inline, so we navigate by local-name via
# `XPath.string`-style matching. We use ad-hoc traversal — the structure is
# shallow and stable enough that introducing a full XPath dependency isn't
# worth the cost.
categories = [] of Hash(String, JSON::Any)
views = [] of Hash(String, JSON::Any)

xml_path = XML_PATH_CANDIDATES.find { |p| File.exists?(p) }
if xml_path
  doc = XML.parse(File.read(xml_path))

  # Direct text content of the first child element with the given local name.
  text_of = ->(parent : XML::Node, local : String) do
    parent.children.find { |c| c.element? && c.name == local }.try(&.content)
  end

  collect_members = ->(parent : XML::Node) do
    mlist = [] of Hash(String, JSON::Any)
    parent.children.each do |child|
      next unless child.element? && child.name == "Has_Member"
      cid = child["CWE_ID"]?.try(&.to_i64?) || next
      vid = child["View_ID"]?.try(&.to_i64?) || 0_i64
      mlist << {
        "cwe_id"  => JSON::Any.new(cid),
        "view_id" => JSON::Any.new(vid),
      } of String => JSON::Any
    end
    mlist
  end

  doc.root.try &.children.each do |group|
    next unless group.element?
    case group.name
    when "Weaknesses"
      group.children.each do |wn|
        next unless wn.element? && wn.name == "Weakness"
        id = wn["ID"]?.try(&.to_i?) || next

        extras = {} of String => JSON::Any
        if struct_attr = wn["Structure"]?
          extras["structure"] = JSON::Any.new(struct_attr)
        end

        wn.children.each do |child|
          next unless child.element?
          case child.name
          when "Demonstrative_Examples"
            des = parse_demonstrative_examples(child)
            extras["demonstrative_examples"] = JSON::Any.new(des) unless des.empty?
          when "References"
            refs = parse_references(child)
            extras["references"] = JSON::Any.new(refs) unless refs.empty?
          when "Mapping_Notes"
            mn = parse_mapping_notes(child)
            extras["mapping_notes"] = JSON::Any.new(mn) unless mn.empty?
          when "Content_History"
            ch = parse_content_history(child)
            extras["content_history"] = JSON::Any.new(ch) unless ch.empty?
          end
        end

        xml_extras[id] = extras unless extras.empty?
      end
    when "External_References"
      group.children.each do |er|
        next unless er.element? && er.name == "External_Reference"
        rid = er["Reference_ID"]? || next
        entry = {} of String => JSON::Any
        entry["reference_id"] = JSON::Any.new(rid)
        authors = [] of JSON::Any
        er.children.each do |c|
          next unless c.element?
          case c.name
          when "Author"           then authors << JSON::Any.new(c.content.strip)
          when "Title"            then entry["title"] = JSON::Any.new(c.content.strip)
          when "Edition"          then entry["edition"] = JSON::Any.new(c.content.strip)
          when "Publication"      then entry["publication"] = JSON::Any.new(c.content.strip)
          when "Publication_Year" then entry["publication_year"] = JSON::Any.new(c.content.strip)
          when "Publication_Month"
            entry["publication_month"] = JSON::Any.new(c.content.strip)
          when "Publication_Day" then entry["publication_day"] = JSON::Any.new(c.content.strip)
          when "Publisher"       then entry["publisher"] = JSON::Any.new(c.content.strip)
          when "URL"             then entry["url"] = JSON::Any.new(c.content.strip)
          when "URL_Date"        then entry["url_date"] = JSON::Any.new(c.content.strip)
          end
        end
        entry["authors"] = JSON::Any.new(authors) unless authors.empty?
        external_refs << entry
      end
    when "Categories"
      group.children.each do |cat|
        next unless cat.element? && cat.name == "Category"
        id = cat["ID"]?.try(&.to_i?) || next
        members = [] of Hash(String, JSON::Any)
        summary = ""
        notes = [] of JSON::Any
        taxonomy = [] of JSON::Any
        references = [] of JSON::Any
        mapping_notes = {} of String => JSON::Any
        content_history = {} of String => JSON::Any
        cat.children.each do |child|
          next unless child.element?
          case child.name
          when "Summary"           then summary = child.content.strip
          when "Relationships"     then members = collect_members.call(child)
          when "Notes"             then notes = parse_notes(child)
          when "Taxonomy_Mappings" then taxonomy = parse_taxonomy_mappings(child)
          when "References"        then references = parse_references(child)
          when "Mapping_Notes"     then mapping_notes = parse_mapping_notes(child)
          when "Content_History"   then content_history = parse_content_history(child)
          end
        end
        entry = {} of String => JSON::Any
        entry["id"] = JSON::Any.new(id.to_i64)
        entry["name"] = JSON::Any.new(cat["Name"]? || "")
        entry["status"] = JSON::Any.new(cat["Status"]? || "")
        entry["summary"] = JSON::Any.new(summary) unless summary.empty?
        unless members.empty?
          entry["members"] = JSON::Any.new(members.map { |m| JSON::Any.new(m) })
        end
        entry["notes"] = JSON::Any.new(notes) unless notes.empty?
        entry["taxonomy_mappings"] = JSON::Any.new(taxonomy) unless taxonomy.empty?
        entry["references"] = JSON::Any.new(references) unless references.empty?
        entry["mapping_notes"] = JSON::Any.new(mapping_notes) unless mapping_notes.empty?
        entry["content_history"] = JSON::Any.new(content_history) unless content_history.empty?
        categories << entry
      end
    when "Views"
      group.children.each do |view|
        next unless view.element? && view.name == "View"
        id = view["ID"]?.try(&.to_i?) || next
        members = [] of Hash(String, JSON::Any)
        objective = ""
        filter = ""
        audience = [] of JSON::Any
        notes = [] of JSON::Any
        references = [] of JSON::Any
        mapping_notes = {} of String => JSON::Any
        content_history = {} of String => JSON::Any
        view.children.each do |child|
          next unless child.element?
          case child.name
          when "Objective"       then objective = child.content.strip
          when "Filter"          then filter = child.content.strip
          when "Members"         then members = collect_members.call(child)
          when "Audience"        then audience = parse_audience(child)
          when "Notes"           then notes = parse_notes(child)
          when "References"      then references = parse_references(child)
          when "Mapping_Notes"   then mapping_notes = parse_mapping_notes(child)
          when "Content_History" then content_history = parse_content_history(child)
          end
        end
        entry = {} of String => JSON::Any
        entry["id"] = JSON::Any.new(id.to_i64)
        entry["name"] = JSON::Any.new(view["Name"]? || "")
        entry["type"] = JSON::Any.new(view["Type"]? || "")
        entry["status"] = JSON::Any.new(view["Status"]? || "")
        entry["objective"] = JSON::Any.new(objective) unless objective.empty?
        entry["filter"] = JSON::Any.new(filter) unless filter.empty?
        unless members.empty?
          entry["members"] = JSON::Any.new(members.map { |m| JSON::Any.new(m) })
        end
        entry["audience"] = JSON::Any.new(audience) unless audience.empty?
        entry["notes"] = JSON::Any.new(notes) unless notes.empty?
        entry["references"] = JSON::Any.new(references) unless references.empty?
        entry["mapping_notes"] = JSON::Any.new(mapping_notes) unless mapping_notes.empty?
        entry["content_history"] = JSON::Any.new(content_history) unless content_history.empty?
        views << entry
      end
    end
  end
end

# Merge the XML-only weakness fields back into the CSV-derived rows.
weaknesses.each do |w|
  wid = w["id"].as_i64.to_i32
  next unless extras = xml_extras[wid]?
  extras.each { |k, v| w[k] = v }
end

categories.sort_by! { |h| h["id"].as_i64 }
views.sort_by! { |h| h["id"].as_i64 }

top = {} of String => JSON::Any
top["catalog_version"] = JSON::Any.new(meta_version)
top["generated_at"] = JSON::Any.new(Time.utc.to_rfc3339)
top["weakness_count"] = JSON::Any.new(weaknesses.size.to_i64)
top["category_count"] = JSON::Any.new(categories.size.to_i64)
top["view_count"] = JSON::Any.new(views.size.to_i64)
top["external_reference_count"] = JSON::Any.new(external_refs.size.to_i64)
top["weaknesses"] = JSON::Any.new(weaknesses.map { |h| JSON::Any.new(h) })
top["categories"] = JSON::Any.new(categories.map { |h| JSON::Any.new(h) })
top["views"] = JSON::Any.new(views.map { |h| JSON::Any.new(h) })
top["external_references"] = JSON::Any.new(external_refs.map { |h| JSON::Any.new(h) })

File.write(OUT_PATH, JSON::Any.new(top).to_json)

puts "wrote #{weaknesses.size} weaknesses, #{categories.size} categories, #{views.size} views, #{external_refs.size} refs to #{OUT_PATH}"
puts "size: #{File.size(OUT_PATH).humanize_bytes}"
