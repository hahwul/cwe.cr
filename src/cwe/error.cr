module CWE
  class Error < Exception
  end

  # Raised by `CWE.parse_id` when a string does not match a CWE identifier.
  class ParseError < Error
  end

  # Raised by bang lookups (`CWE.find!`, `CWE.category!`, `CWE.view!`,
  # `CWE.external_reference!`, etc.) when the requested CWE id or `REF-` id
  # is not present in the catalog.
  class NotFoundError < Error
  end
end
