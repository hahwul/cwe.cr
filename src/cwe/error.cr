module CWE
  class Error < Exception
  end

  # Raised by `CWE.parse_id` when a string does not match a CWE identifier.
  class ParseError < Error
  end

  # Raised by bang lookups (`CWE.find!`, `Weakness#parents!`, etc.) when the
  # requested CWE id is not present in the embedded catalog.
  class NotFoundError < Error
  end
end
