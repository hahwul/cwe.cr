require "json"
require "xml"

module CWE::CatalogXML
  extend self

  # MITRE writes Example_Code, Intro_Text, Body_Text, Notes, … as xhtml and
  # pretty-prints the XML around it, so the newlines and tabs in their text
  # nodes that span a source line break are layout, not content. Both renderers
  # below let only the markup decide where a line or paragraph ends.
  XHTML_ASCII_WS = /[ \t\r\n]+/
  XHTML_BLOCKS   = Set{"div", "p", "li", "ul", "ol", "table", "thead", "tbody", "tr"}

  # An `<Example_Code>` as lines of code. `<xhtml:br/>` ends a line (an empty
  # one too), a block element starts and ends one, and each
  # `<xhtml:div style="margin-left:1em;">` indents its lines one level — the
  # only way MITRE encodes code indentation, so Python stays valid.
  class CodeRenderer
    INDENT = "    "

    @lines = [] of String
    @line = ""
    @depth = 0
    @line_depth = 0

    def self.render(node : XML::Node) : String
      r = new
      r.walk(node)
      r.result
    end

    def result : String
      end_line(false)
      @lines.join('\n').strip('\n')
    end

    def walk(node : XML::Node) : Nil
      node.children.each do |c|
        if c.element?
          name = c.name
          if name == "br"
            end_line(true)
          elsif XHTML_BLOCKS.includes?(name)
            indented = name == "div" && c["style"]?.try(&.includes?("margin-left"))
            end_line(false)
            @depth += 1 if indented
            walk(c)
            end_line(false)
            @depth -= 1 if indented
          else
            walk(c)
            text(" ") if name.in?("td", "th")
          end
        elsif c.text? || c.cdata?
          text(c.content)
        end
      end
    end

    # Only a run that spans a source line break is pretty-printing; spaces
    # inside a line (column alignment, `"a  b"` literals) are the author's.
    private def text(s : String) : Nil
      s = s.gsub(/[ \t]*[\r\n][ \t\r\n]*/, " ")
      s = s.lstrip if @line.empty?
      return if s.empty?
      @line_depth = @depth if @line.empty?
      @line += s
    end

    # A hard break (`br`) always ends a line; a block boundary only ends one
    # that has content, as in HTML.
    private def end_line(hard : Bool) : Nil
      line = @line.rstrip(' ')
      @lines << (line.empty? ? "" : INDENT * @line_depth + line) if hard || !line.empty?
      @line = ""
    end
  end

  # Running text as one line, the way MITRE's own CSV export flattens the same
  # xhtml: block boundaries and `br` become a space and whitespace collapses.
  # Unlike the CSV, `sup` / `sub` keep their meaning as `^` / `_` (CWE-1241's
  # `x<sup>6</sup>` is `x^6`, not `x6`), parenthesised unless a single word
  # not followed by one. Example_Code is left alone: `^` / `_` mean other things
  # in code, and no CWE 5.0 code uses either tag.
  def render_prose(node : XML::Node) : String
    io = String::Builder.new
    walk = uninitialized XML::Node -> Nil
    walk = ->(n : XML::Node) do
      n.children.each do |c|
        if c.element? && c.name.in?("sup", "sub")
          inner = render_prose(c)
          next if inner.empty?
          # `x<sup>2</sup>y` must not read as x^(2y).
          bare = inner.matches?(/\A\w+\z/) && !c.next_sibling.try { |n| n.text? && n.content.starts_with?(/\w/) }
          io << (c.name == "sup" ? '^' : '_') << (bare ? inner : "(#{inner})")
        elsif c.element?
          block = c.name == "br" || c.name.in?("td", "th") || XHTML_BLOCKS.includes?(c.name)
          io << ' ' if block
          walk.call(c)
          io << ' ' if block
        elsif c.text? || c.cdata?
          io << c.content
        end
      end
    end
    walk.call(node)
    collapse_ws(io.to_s)
  end

  def collapse_ws(s : String) : String
    s.gsub(XHTML_ASCII_WS, " ").strip
  end

  def child_named(parent : XML::Node, local : String) : XML::Node?
    parent.children.find { |c| c.element? && c.name == local }
  end

  def children_named(parent : XML::Node, local : String) : Array(XML::Node)
    parent.children.select { |c| c.element? && c.name == local }.map(&.as(XML::Node))
  end

  def text_of_child(parent : XML::Node, local : String) : String?
    if c = child_named(parent, local)
      s = render_prose(c)
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

  def parse_content_history(node : XML::Node) : Hash(String, JSON::Any)
    h = {} of String => JSON::Any
    {"Submission" => "submissions", "Contribution" => "contributions", "Modification" => "modifications"}.each do |element, key|
      rows = children_named(node, element).map do |record|
        fields = {} of String => JSON::Any
        {"Organization" => "organization", "Date" => "date", "Comment" => "comment",
         "Version" => "version", "ReleaseDate" => "release_date"}.each do |suffix, field|
          put(fields, field, text_of_child(record, "#{element}_#{suffix}"))
        end
        if element == "Modification"
          put(fields, "name", text_of_child(record, "Modification_Name"))
          put(fields, "importance", text_of_child(record, "Modification_Importance"))
        else
          put_list(fields, "names", texts_of_children(record, "#{element}_Name"))
        end
        put(fields, "type", record["Type"]?)
        JSON::Any.new(fields)
      end
      put_list(h, key, rows)
    end
    previous_names = children_named(node, "Previous_Entry_Name").compact_map do |record|
      name = render_prose(record)
      next if name.empty?
      fields = {"name" => str(name)}
      put(fields, "date", record["Date"]?)
      put(fields, "version", record["Version"]?)
      JSON::Any.new(fields)
    end
    put_list(h, "previous_entry_names", previous_names)
    h
  end

  def parse_references(node : XML::Node) : Array(JSON::Any)
    arr = [] of JSON::Any
    children_named(node, "Reference").each do |r|
      next unless rid = r["External_Reference_ID"]?
      inner = {} of String => JSON::Any
      inner["external_reference_id"] = JSON::Any.new(rid)
      if sec = r["Section"]?
        inner["section"] = JSON::Any.new(collapse_ws(sec))
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
      put(inner, "version", n["Version"]?)
      put(inner, "release_date", n["ReleaseDate"]?)
      text = render_prose(n)
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
      put(inner, "example_id", de["Demonstrative_Example_ID"]?)
      entries = [] of JSON::Any
      refs = [] of JSON::Any

      de.children.each do |c|
        next unless c.element?
        case c.name
        when "Title_Text" then put(inner, "title_text", render_prose(c))
        when "Intro_Text" then put(inner, "intro_text", render_prose(c))
        when "Body_Text"
          s = render_prose(c)
          entries << str(s) unless s.empty?
        when "Example_Code"
          rendered = CodeRenderer.render(c)
          next if rendered.empty?
          ch = {} of String => JSON::Any
          ch["code"] = JSON::Any.new(rendered)
          if nat = c["Nature"]?
            ch["nature"] = JSON::Any.new(nat)
          end
          if lang = c["Language"]?
            ch["language"] = JSON::Any.new(lang)
          end
          entries << JSON::Any.new(ch)
        when "References"
          refs.concat(parse_references(c))
        end
      end

      put_list(inner, "entries", entries)
      put_list(inner, "references", refs)
      arr << JSON::Any.new(inner) unless inner.empty?
    end
    arr
  end

  def str(s : String) : JSON::Any
    JSON::Any.new(s)
  end

  # `str` for an optional value: nil and "" leave `h[key]` unset, so absent
  # fields are omitted from the output.
  def put(h : Hash(String, JSON::Any), key : String, value : String?) : Nil
    h[key] = str(value) if value && !value.empty?
  end

  def put_list(h : Hash(String, JSON::Any), key : String, values : Array(JSON::Any)) : Nil
    h[key] = JSON::Any.new(values) unless values.empty?
  end

  # Text of every `<child>` of `parent`, e.g. each `Functional_Area`.
  def texts_of_children(parent : XML::Node, local : String) : Array(JSON::Any)
    children_named(parent, local).compact_map do |c|
      s = render_prose(c)
      str(s) unless s.empty?
    end
  end

  def put_phases(h : Hash(String, JSON::Any), node : XML::Node) : Nil
    phases = [] of JSON::Any
    custom = [] of JSON::Any
    node.children.each do |child|
      next unless child.element? && child.name.in?("Phase", "Custom_Phase")
      value = render_prose(child)
      next if value.empty?
      phases << str(value)
      if child.name == "Custom_Phase" && (domain = child["Domain"]?)
        custom << JSON::Any.new({"domain" => str(domain), "value" => str(value)})
      end
    end
    put_list(h, "phases", phases)
    put_list(h, "custom_phases", custom)
  end

  def parse_dimensions(node : XML::Node) : Array(JSON::Any)
    children_named(node, "Dimension").compact_map do |dimension|
      type = dimension["Type"]? || next
      value = render_prose(dimension)
      next if value.empty?
      JSON::Any.new({"type" => str(type), "value" => str(value)})
    end
  end

  def put_relationship_metadata(h : Hash(String, JSON::Any), node : XML::Node) : Nil
    if dimensions = child_named(node, "Dimensions")
      put_list(h, "dimensions", parse_dimensions(dimensions))
    end
    put(h, "note", text_of_child(node, "Note"))
  end

  PLATFORM_PREFIX = {
    "Language"         => "language",
    "Operating_System" => "operating_system",
    "Architecture"     => "architecture",
    "Technology"       => "technology",
    "Paradigm"         => "paradigm",
  }

  def parse_platforms(node : XML::Node) : Array(JSON::Any)
    node.children.compact_map do |c|
      next unless c.element? && (prefix = PLATFORM_PREFIX[c.name]?)
      h = {} of String => JSON::Any
      {"Name" => "name", "Class" => "class", "Prevalence" => "prevalence",
       "Version" => "version", "CPE_ID" => "cpe_id"}.each do |attr, key|
        put(h, "#{prefix}_#{key}", c[attr]?)
      end
      put(h, "note", text_of_child(c, "Note"))
      JSON::Any.new(h) unless h.empty?
    end
  end

  def parse_weakness(wn : XML::Node, id : Int32) : Hash(String, JSON::Any)
    h = {} of String => JSON::Any
    h["id"] = JSON::Any.new(id.to_i64)
    h["name"] = str(wn["Name"]? || "")
    put(h, "abstraction", wn["Abstraction"]?)
    put(h, "status", wn["Status"]?)
    put(h, "structure", wn["Structure"]?)
    put(h, "diagram", wn["Diagram"]?)

    wn.children.each do |child|
      next unless child.element?
      case child.name
      when "Description"           then put(h, "description", render_prose(child))
      when "Extended_Description"  then put(h, "extended_description", render_prose(child))
      when "Technical_Nuance"      then put(h, "technical_nuance", render_prose(child))
      when "Dimensions"            then put_list(h, "dimensions", parse_dimensions(child))
      when "Likelihood_Of_Exploit" then put(h, "likelihood_of_exploit", render_prose(child))
      when "Related_Weaknesses"
        rows = children_named(child, "Related_Weakness").map do |r|
          inner = {} of String => JSON::Any
          inner["nature"] = str(r["Nature"]? || "")
          inner["cwe_id"] = JSON::Any.new(r["CWE_ID"]?.try(&.to_i64?) || 0_i64)
          inner["view_id"] = JSON::Any.new(r["View_ID"]?.try(&.to_i64?) || 0_i64)
          put(inner, "ordinal", r["Ordinal"]?)
          put(inner, "chain_id", r["Chain_ID"]?)
          put_relationship_metadata(inner, r)
          JSON::Any.new(inner)
        end
        put_list(h, "related_weaknesses", rows)
      when "Weakness_Ordinalities"
        rows = children_named(child, "Weakness_Ordinality").map do |o|
          inner = {"ordinality" => str(text_of_child(o, "Ordinality") || "")}
          put(inner, "description", text_of_child(o, "Description"))
          JSON::Any.new(inner)
        end
        put_list(h, "ordinalities", rows)
      when "Applicable_Platforms" then put_list(h, "applicable_platforms", parse_platforms(child))
      when "Alternate_Terms"
        rows = children_named(child, "Alternate_Term").map do |t|
          inner = {"term" => str(text_of_child(t, "Term") || "")}
          put(inner, "description", text_of_child(t, "Description"))
          put_list(inner, "roles", texts_of_children(t, "Role"))
          JSON::Any.new(inner)
        end
        put_list(h, "alternate_terms", rows)
      when "Modes_Of_Introduction"
        rows = children_named(child, "Introduction").map do |i|
          inner = {} of String => JSON::Any
          put_phases(inner, i)
          put(inner, "note", text_of_child(i, "Note"))
          JSON::Any.new(inner)
        end
        put_list(h, "modes_of_introduction", rows)
      when "Common_Consequences"
        rows = children_named(child, "Consequence").map do |c|
          inner = {"scopes" => JSON::Any.new(texts_of_children(c, "Scope"))}
          put(inner, "consequence_id", c["Consequence_ID"]?)
          put_list(inner, "impacts", texts_of_children(c, "Impact"))
          put(inner, "likelihood", text_of_child(c, "Likelihood"))
          put(inner, "note", text_of_child(c, "Note"))
          JSON::Any.new(inner)
        end
        put_list(h, "common_consequences", rows)
      when "Detection_Methods"
        rows = children_named(child, "Detection_Method").map do |d|
          inner = {"method" => str(text_of_child(d, "Method") || "")}
          put(inner, "method_id", d["Detection_Method_ID"]?)
          put_phases(inner, d)
          put(inner, "description", text_of_child(d, "Description"))
          put(inner, "effectiveness", text_of_child(d, "Effectiveness"))
          put(inner, "effectiveness_notes", text_of_child(d, "Effectiveness_Notes"))
          JSON::Any.new(inner)
        end
        put_list(h, "detection_methods", rows)
      when "Potential_Mitigations"
        rows = children_named(child, "Mitigation").map do |m|
          inner = {} of String => JSON::Any
          put(inner, "mitigation_id", m["Mitigation_ID"]?)
          put_phases(inner, m)
          put(inner, "strategy", text_of_child(m, "Strategy"))
          put(inner, "description", text_of_child(m, "Description"))
          put(inner, "effectiveness", text_of_child(m, "Effectiveness"))
          put(inner, "effectiveness_notes", text_of_child(m, "Effectiveness_Notes"))
          JSON::Any.new(inner)
        end
        put_list(h, "potential_mitigations", rows)
      when "Observed_Examples"
        rows = children_named(child, "Observed_Example").map do |e|
          inner = {"reference" => str(text_of_child(e, "Reference") || "")}
          put(inner, "description", text_of_child(e, "Description"))
          put(inner, "link", text_of_child(e, "Link"))
          put_list(inner, "rationales", texts_of_children(e, "Rationale"))
          JSON::Any.new(inner)
        end
        put_list(h, "observed_examples", rows)
      when "Taxonomy_Mappings" then put_list(h, "taxonomy_mappings", parse_taxonomy_mappings(child))
      when "Related_Attack_Patterns"
        rows = children_named(child, "Related_Attack_Pattern").compact_map do |r|
          r["CAPEC_ID"]?.try(&.to_i64?).try { |i| JSON::Any.new(i) }
        end
        put_list(h, "related_attack_patterns", rows)
      when "Background_Details"     then put_list(h, "background_details", texts_of_children(child, "Background_Detail"))
      when "Functional_Areas"       then put_list(h, "functional_areas", texts_of_children(child, "Functional_Area"))
      when "Affected_Resources"     then put_list(h, "affected_resources", texts_of_children(child, "Affected_Resource"))
      when "Exploitation_Factors"   then put_list(h, "exploitation_factors", texts_of_children(child, "Exploitation_Factor"))
      when "Notes"                  then put_list(h, "notes", parse_notes(child))
      when "Demonstrative_Examples" then put_list(h, "demonstrative_examples", parse_demonstrative_examples(child))
      when "References"             then put_list(h, "references", parse_references(child))
      when "Mapping_Notes"
        mn = parse_mapping_notes(child)
        h["mapping_notes"] = JSON::Any.new(mn) unless mn.empty?
      when "Content_History"
        ch = parse_content_history(child)
        h["content_history"] = JSON::Any.new(ch) unless ch.empty?
      end
    end
    h
  end

  def collect_members(parent : XML::Node, element : String) : Array(JSON::Any)
    children_named(parent, element).compact_map do |m|
      cid = m["CWE_ID"]?.try(&.to_i64?) || next
      vid = m["View_ID"]?.try(&.to_i64?) || 0_i64
      fields = {"cwe_id" => JSON::Any.new(cid), "view_id" => JSON::Any.new(vid)}
      put_relationship_metadata(fields, m)
      JSON::Any.new(fields)
    end
  end

  def put_members(entry : Hash(String, JSON::Any), node : XML::Node) : Nil
    put_list(entry, "members", collect_members(node, "Has_Member"))
    put_list(entry, "member_of", collect_members(node, "Member_Of"))
  end

  # A `<Category>` (schema 7.x) or `<Grouping>` (schema 8.0 / CWE 5.0, which
  # retains the same IDs).
  def parse_category(cat : XML::Node, id : Int32) : Hash(String, JSON::Any)
    entry = {} of String => JSON::Any
    entry["id"] = JSON::Any.new(id.to_i64)
    entry["name"] = str(cat["Name"]? || "")
    entry["status"] = str(cat["Status"]? || "")
    cat.children.each do |child|
      next unless child.element?
      case child.name
      when "Summary"           then put(entry, "summary", render_prose(child))
      when "Relationships"     then put_members(entry, child)
      when "Notes"             then put_list(entry, "notes", parse_notes(child))
      when "Taxonomy_Mappings" then put_list(entry, "taxonomy_mappings", parse_taxonomy_mappings(child))
      when "References"        then put_list(entry, "references", parse_references(child))
      when "Mapping_Notes"
        mn = parse_mapping_notes(child)
        entry["mapping_notes"] = JSON::Any.new(mn) unless mn.empty?
      when "Content_History"
        ch = parse_content_history(child)
        entry["content_history"] = JSON::Any.new(ch) unless ch.empty?
      end
    end
    entry
  end

  def parse_view(view : XML::Node, id : Int32) : Hash(String, JSON::Any)
    entry = {} of String => JSON::Any
    entry["id"] = JSON::Any.new(id.to_i64)
    entry["name"] = str(view["Name"]? || "")
    entry["type"] = str(view["Type"]? || "")
    entry["status"] = str(view["Status"]? || "")
    view.children.each do |child|
      next unless child.element?
      case child.name
      when "Objective"  then put(entry, "objective", render_prose(child))
      when "Filter"     then put(entry, "filter", child.content.strip)
      when "Members"    then put_members(entry, child)
      when "Audience"   then put_list(entry, "audience", parse_audience(child))
      when "Notes"      then put_list(entry, "notes", parse_notes(child))
      when "References" then put_list(entry, "references", parse_references(child))
      when "Mapping_Notes"
        mn = parse_mapping_notes(child)
        entry["mapping_notes"] = JSON::Any.new(mn) unless mn.empty?
      when "Content_History"
        ch = parse_content_history(child)
        entry["content_history"] = JSON::Any.new(ch) unless ch.empty?
      end
    end
    entry
  end

  REFERENCE_FIELDS = {
    "Title" => "title", "Edition" => "edition", "Publication" => "publication",
    "Publication_Year" => "publication_year", "Publication_Month" => "publication_month",
    "Publication_Day" => "publication_day", "Publisher" => "publisher",
    "URL" => "url", "URL_Date" => "url_date", "Alt_URL" => "alt_url", "Alt_URL_Date" => "alt_url_date",
    "Access_Restrictions" => "access_restrictions",
  }

  # An empty element is absent here as everywhere else: MITRE ships at least
  # one empty `<Author></Author>` (REF-1466 in CWE 5.0), which names no one.
  def parse_external_reference(er : XML::Node, rid : String) : Hash(String, JSON::Any)
    entry = {"reference_id" => str(rid)}
    er.children.each do |c|
      next unless c.element? && (key = REFERENCE_FIELDS[c.name]?)
      put(entry, key, render_prose(c))
    end
    put_list(entry, "authors", texts_of_children(er, "Author"))
    put_list(entry, "media_types", texts_of_children(er, "Media_Type"))
    put_list(entry, "rationales", texts_of_children(er, "Rationale"))
    entry
  end

  def parse(input : String | IO, version_override : String? = nil) : Hash(String, JSON::Any)
    doc = XML.parse(input)
    # libxml2 recovers from a truncated or broken file and hands back whatever it
    # managed to read; that must never become the embedded catalog.
    if (errors = doc.errors) && !errors.empty?
      raise ArgumentError.new("malformed CWE XML: #{errors.first.message}")
    end
    root = doc.root
    raise ArgumentError.new("not a CWE catalog") unless root && root.name == "Weakness_Catalog"

    weaknesses = [] of Hash(String, JSON::Any)
    categories = [] of Hash(String, JSON::Any)
    views = [] of Hash(String, JSON::Any)
    external_refs = [] of Hash(String, JSON::Any)

    # The XML uses a versioned default namespace (`http://cwe.mitre.org/cwe-7`,
    # `…/cwe-8`); `XML::Node#name` is the local name, so navigation ignores it.
    root.children.each do |group|
      next unless group.element?
      group.children.each do |node|
        next unless node.element?
        case {group.name, node.name}
        when {"Weaknesses", "Weakness"}
          id = node["ID"]?.try(&.to_i?) || next
          weaknesses << parse_weakness(node, id)
        when {"Categories", "Category"}, {"Groupings", "Grouping"}
          id = node["ID"]?.try(&.to_i?) || next
          categories << parse_category(node, id)
        when {"Views", "View"}
          id = node["ID"]?.try(&.to_i?) || next
          views << parse_view(node, id)
        when {"External_References", "External_Reference"}
          rid = node["Reference_ID"]? || next
          external_refs << parse_external_reference(node, rid)
        end
      end
    end

    # Sort by ID for stable diffs
    weaknesses.sort_by!(&.["id"].as_i64)
    categories.sort_by!(&.["id"].as_i64)
    views.sort_by!(&.["id"].as_i64)

    top = {} of String => JSON::Any
    top["catalog_version"] = str(version_override || root["Version"]? || "unknown")
    put(top, "catalog_name", root["Name"]?)
    put(top, "catalog_date", root["Date"]?)
    top["generated_at"] = str(Time.utc.to_rfc3339)
    top["weakness_count"] = JSON::Any.new(weaknesses.size.to_i64)
    top["category_count"] = JSON::Any.new(categories.size.to_i64)
    top["view_count"] = JSON::Any.new(views.size.to_i64)
    top["external_reference_count"] = JSON::Any.new(external_refs.size.to_i64)
    top["weaknesses"] = JSON::Any.new(weaknesses.map { |h| JSON::Any.new(h) })
    top["categories"] = JSON::Any.new(categories.map { |h| JSON::Any.new(h) })
    top["views"] = JSON::Any.new(views.map { |h| JSON::Any.new(h) })
    top["external_references"] = JSON::Any.new(external_refs.map { |h| JSON::Any.new(h) })

    top
  end
end
