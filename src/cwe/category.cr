require "json"

module CWE
  # An informal grouping of weaknesses. MITRE marks Categories as
  # "Mapping Prohibited" — they exist for browsing/aggregation, not for
  # assigning to a CVE. Use `Catalog#category` / `CWE.category` to look one
  # up by id.
  class Category
    include Comparable(Category)

    getter id : Int32
    getter name : String
    getter status : Status
    getter summary : String?
    getter members : Array(Member)
    getter raw_status : String?

    def initialize(@id, @name, @status = Status::Other, @summary = nil,
                   @members = [] of Member, @raw_status = nil)
    end

    def cwe_id : String
      "CWE-#{@id}"
    end

    def url : String
      "https://cwe.mitre.org/data/definitions/#{@id}.html"
    end

    def member_ids : Array(Int32)
      @members.map(&.cwe_id).uniq
    end

    def <=>(other : Category) : Int32
      @id <=> other.id
    end

    def ==(other : Category) : Bool
      @id == other.id
    end

    def hash(hasher)
      @id.hash(hasher)
    end

    def to_s(io : IO) : Nil
      io << cwe_id
    end

    def inspect(io : IO) : Nil
      io << "#<CWE::Category " << cwe_id << ' ' << @name.inspect << '>'
    end

    # A `<Has_Member>` edge — points at a weakness (or sometimes another
    # category) within a particular CWE view.
    struct Member
      include JSON::Serializable

      @[JSON::Field(key: "cweId")]
      getter cwe_id : Int32

      @[JSON::Field(key: "viewId")]
      getter view_id : Int32

      def initialize(@cwe_id, @view_id)
      end
    end
  end

  # A CWE View — a slice of the catalog organised around a stakeholder's
  # perspective (Research, Development, Architecture, Hardware Design, …).
  # Views are themselves CWE-numbered (CWE-1000, CWE-699, CWE-635, etc.).
  class View
    include Comparable(View)

    getter id : Int32
    getter name : String
    # MITRE view types: `"Graph"`, `"Slice"`, `"Explicit Slice"`, `"Implicit Slice"`.
    getter type : String?
    getter status : Status
    getter objective : String?
    getter filter : String?
    getter members : Array(Category::Member)
    getter raw_status : String?

    def initialize(@id, @name, @type = nil, @status = Status::Other,
                   @objective = nil, @filter = nil,
                   @members = [] of Category::Member, @raw_status = nil)
    end

    def cwe_id : String
      "CWE-#{@id}"
    end

    def url : String
      "https://cwe.mitre.org/data/definitions/#{@id}.html"
    end

    def member_ids : Array(Int32)
      @members.map(&.cwe_id).uniq
    end

    def <=>(other : View) : Int32
      @id <=> other.id
    end

    def ==(other : View) : Bool
      @id == other.id
    end

    def hash(hasher)
      @id.hash(hasher)
    end

    def to_s(io : IO) : Nil
      io << cwe_id
    end

    def inspect(io : IO) : Nil
      io << "#<CWE::View " << cwe_id << ' ' << @name.inspect << '>'
    end
  end
end
