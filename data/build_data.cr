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

  name        = csv["Name"]
  abstraction = csv["Weakness Abstraction"]
  structure   = nil # Not in CSV; will stay null
  status      = csv["Status"]
  description = csv["Description"]
  ext_desc    = csv["Extended Description"]
  likelihood  = csv["Likelihood of Exploit"]

  related     = parse_structured(csv["Related Weaknesses"], RELATED_FIELDS)
  ordinalities = parse_structured(csv["Weakness Ordinalities"], ORDINALITY_FIELDS)
  platforms   = parse_structured(csv["Applicable Platforms"], PLATFORM_FIELDS)
  alt_terms   = parse_structured(csv["Alternate Terms"], ALT_TERM_FIELDS)
  intros      = parse_structured(csv["Modes Of Introduction"], INTRO_FIELDS)
  consequences = parse_structured(csv["Common Consequences"], CONSEQUENCE_FIELDS)
  detections  = parse_structured(csv["Detection Methods"], DETECTION_FIELDS)
  mitigations = parse_structured(csv["Potential Mitigations"], MITIGATION_FIELDS)
  examples    = parse_structured(csv["Observed Examples"], EXAMPLE_FIELDS)
  taxonomies  = parse_structured(csv["Taxonomy Mappings"], TAXONOMY_FIELDS)
  # CAPEC IDs are encoded as a bare `::N::N::` list, not key/value pairs.
  capecs      = parse_bare_list(csv["Related Attack Patterns"])
  notes       = parse_structured(csv["Notes"], NOTE_FIELDS)

  background_details  = parse_bare_list(csv["Background Details"])
  functional_areas    = parse_bare_list(csv["Functional Areas"])
  affected_resources  = parse_bare_list(csv["Affected Resources"])
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
    when "Categories"
      group.children.each do |cat|
        next unless cat.element? && cat.name == "Category"
        id = cat["ID"]?.try(&.to_i?) || next
        members = [] of Hash(String, JSON::Any)
        summary = ""
        cat.children.each do |child|
          next unless child.element?
          case child.name
          when "Summary"       then summary = child.content.strip
          when "Relationships" then members = collect_members.call(child)
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
        categories << entry
      end
    when "Views"
      group.children.each do |view|
        next unless view.element? && view.name == "View"
        id = view["ID"]?.try(&.to_i?) || next
        members = [] of Hash(String, JSON::Any)
        objective = ""
        filter = ""
        view.children.each do |child|
          next unless child.element?
          case child.name
          when "Objective" then objective = child.content.strip
          when "Filter"    then filter = child.content.strip
          when "Members"   then members = collect_members.call(child)
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
        views << entry
      end
    end
  end
end

categories.sort_by! { |h| h["id"].as_i64 }
views.sort_by! { |h| h["id"].as_i64 }

top = {} of String => JSON::Any
top["catalog_version"] = JSON::Any.new(meta_version)
top["generated_at"] = JSON::Any.new(Time.utc.to_rfc3339)
top["weakness_count"] = JSON::Any.new(weaknesses.size.to_i64)
top["category_count"] = JSON::Any.new(categories.size.to_i64)
top["view_count"] = JSON::Any.new(views.size.to_i64)
top["weaknesses"] = JSON::Any.new(weaknesses.map { |h| JSON::Any.new(h) })
top["categories"] = JSON::Any.new(categories.map { |h| JSON::Any.new(h) })
top["views"] = JSON::Any.new(views.map { |h| JSON::Any.new(h) })

File.write(OUT_PATH, JSON::Any.new(top).to_json)

puts "wrote #{weaknesses.size} weaknesses, #{categories.size} categories, #{views.size} views to #{OUT_PATH}"
puts "size: #{File.size(OUT_PATH).humanize_bytes}"
