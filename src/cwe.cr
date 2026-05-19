# A Crystal implementation of the MITRE CWE (Common Weakness Enumeration).
#
# The CWE catalog is embedded at compile time, so lookups are instant and
# the resulting binary needs no network access or sidecar data files.
#
# ```
# w = CWE.find!("CWE-79")
# w.name                           # => "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
# w.abstraction                    # => CWE::Abstraction::Base
# w.parent_relations.map(&.cwe_id) # => [74, 74]
# w.summary                        # => "CWE-79: Improper Neutralization of Input ... (Base, Stable)"
# ```
#
# See `CWE::Catalog` for the full query API and `CWE::Weakness` for the
# fields exposed on each entry.
require "./cwe/version"
require "./cwe/error"
require "./cwe/types"
require "./cwe/weakness"
require "./cwe/category"
require "./cwe/catalog"
require "./cwe/json"

module CWE
  # The numeric portion of a CWE id, e.g. `"CWE-79"`, `"cwe-79"`, `" 79 "`,
  # or `"79"`. Returns nil if the input does not match. Whitespace around
  # the id is tolerated; embedded whitespace is not.
  def self.parse_id?(input : String) : Int32?
    s = input.strip
    return nil if s.empty?

    if md = /\A[Cc][Ww][Ee][-_:\s]?(\d+)\z/.match(s)
      md[1].to_i?
    elsif md = /\A(\d+)\z/.match(s)
      md[1].to_i?
    end
  end

  # Raising variant of `parse_id?`.
  def self.parse_id(input : String) : Int32
    parse_id?(input) || raise ParseError.new("not a CWE id: #{input.inspect}")
  end

  # Default catalog instance. The first call lazily parses the embedded JSON
  # blob; subsequent calls return the same instance.
  def self.catalog : Catalog
    Catalog.default
  end

  # Look up a weakness by integer id (e.g. `79`) or CWE string
  # (`"CWE-79"`, `"cwe-79"`, `"79"`). Returns nil if not found.
  def self.find(id : Int) : Weakness?
    catalog.find(id)
  end

  def self.find(id : String) : Weakness?
    catalog.find(id)
  end

  # Raising variants — `NotFoundError` if the id is not in the catalog,
  # `ParseError` if the string is not a CWE id.
  def self.find!(id : Int) : Weakness
    catalog.find!(id)
  end

  def self.find!(id : String) : Weakness
    catalog.find!(id)
  end

  # `CWE[X]` and `CWE[X]?` indexing.
  def self.[](id : Int) : Weakness
    catalog[id]
  end

  def self.[](id : String) : Weakness
    catalog[id]
  end

  def self.[]?(id : Int) : Weakness?
    catalog[id]?
  end

  def self.[]?(id : String) : Weakness?
    catalog[id]?
  end

  def self.includes?(id : Int) : Bool
    catalog.includes?(id)
  end

  def self.includes?(id : String) : Bool
    catalog.includes?(id)
  end

  # All weaknesses, sorted by numeric id.
  def self.all : Array(Weakness)
    catalog.all
  end

  def self.each(& : Weakness ->) : Nil
    catalog.each { |w| yield w }
  end

  def self.size : Int32
    catalog.size
  end

  # Case-insensitive substring search across name, descriptions, and
  # alternate terms.
  def self.search(query : String) : Array(Weakness)
    catalog.search(query)
  end

  def self.search_by_name(query : String) : Array(Weakness)
    catalog.search_by_name(query)
  end

  def self.with_abstraction(level : Abstraction) : Array(Weakness)
    catalog.with_abstraction(level)
  end

  def self.with_status(status : Status) : Array(Weakness)
    catalog.with_status(status)
  end

  def self.parents_of(id : Int, view_id : Int? = nil) : Array(Weakness)
    catalog.parents_of(id, view_id)
  end

  def self.children_of(id : Int, view_id : Int? = nil) : Array(Weakness)
    catalog.children_of(id, view_id)
  end

  def self.ancestors_of(id : Int, view_id : Int? = nil) : Array(Weakness)
    catalog.ancestors_of(id, view_id)
  end

  def self.descendants_of(id : Int, view_id : Int? = nil) : Array(Weakness)
    catalog.descendants_of(id, view_id)
  end

  def self.pillar_of(id : Int) : Weakness?
    catalog.pillar_of(id)
  end

  # ---- Categories ----

  def self.category(id : Int) : Category?
    catalog.category(id)
  end

  def self.category(id : String) : Category?
    catalog.category(id)
  end

  def self.category!(id : Int) : Category
    catalog.category!(id)
  end

  def self.category!(id : String) : Category
    catalog.category!(id)
  end

  def self.categories : Array(Category)
    catalog.all_categories
  end

  # ---- Views ----

  def self.view(id : Int) : View?
    catalog.view(id)
  end

  def self.view(id : String) : View?
    catalog.view(id)
  end

  def self.view!(id : Int) : View
    catalog.view!(id)
  end

  def self.view!(id : String) : View
    catalog.view!(id)
  end

  def self.views : Array(View)
    catalog.all_views
  end

  # Look up any entry by id: Weakness, Category, or View.
  def self.entry(id : Int) : Weakness | Category | View | Nil
    catalog.entry(id)
  end

  def self.entry(id : String) : Weakness | Category | View | Nil
    catalog.entry(id)
  end

  # Resolved member weaknesses of a Category or View.
  def self.members_of(id : Int) : Array(Weakness)
    catalog.members_of(id)
  end

  # The MITRE catalog version embedded in this build (e.g. `"4.20"`).
  def self.catalog_version : String
    catalog.catalog_version
  end
end
