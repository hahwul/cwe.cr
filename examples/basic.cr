require "../src/cwe"

# =============================================================================
# Basic lookups
# =============================================================================
# The catalog is embedded at compile time. The first `CWE.find` call lazily
# parses the embedded JSON; subsequent calls share the same `Catalog`.

puts "--- Catalog metadata ---"
puts "Catalog version: #{CWE.catalog_version}"
puts "Entries:         #{CWE.size}"

puts "\n--- Looking up CWE-79 ---"
w = CWE.find!("CWE-79")
puts "ID:          #{w.cwe_id}"
puts "Name:        #{w.name}"
puts "Abstraction: #{w.abstraction}"
puts "Status:      #{w.status}"
puts "URL:         #{w.url}"
puts "Description:"
puts "  #{w.description}"

puts "\n--- Different id formats are accepted ---"
[79, "79", "CWE-79", "cwe-79", "CWE_79"].each do |key|
  hit = key.is_a?(Int) ? CWE.find(key) : CWE.find(key)
  puts "#{key.inspect.ljust(12)} → #{hit.try(&.cwe_id)}"
end

puts "\n--- Non-existent ids ---"
puts "CWE.find(999999)    → #{CWE.find(999_999).inspect}"
puts "CWE.includes?(\"CWE-79\") → #{CWE.includes?("CWE-79")}"
