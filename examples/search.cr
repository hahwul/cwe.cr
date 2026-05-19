require "../src/cwe"

# =============================================================================
# Search and filtering
# =============================================================================

puts "--- search_by_name(\"cross-site\") ---"
CWE.search_by_name("cross-site").each do |w|
  puts "  #{w.summary}"
end

puts "\n--- search(\"buffer overflow\") full-text matches ---"
CWE.search("buffer overflow").first(5).each do |w|
  puts "  #{w.summary}"
end

puts "\n--- All Pillars (highest level of abstraction) ---"
CWE.with_abstraction(CWE::Abstraction::Pillar).each do |w|
  puts "  ▲ #{w.summary}"
end

puts "\n--- Counts by abstraction ---"
{CWE::Abstraction::Pillar, CWE::Abstraction::Class, CWE::Abstraction::Base,
 CWE::Abstraction::Variant, CWE::Abstraction::Compound}.each do |level|
  puts "  #{level.to_s.ljust(10)} #{CWE.with_abstraction(level).size}"
end

puts "\n--- Counts by status ---"
{CWE::Status::Stable, CWE::Status::Draft, CWE::Status::Incomplete,
 CWE::Status::Deprecated}.each do |s|
  puts "  #{s.to_s.ljust(12)} #{CWE.with_status(s).size}"
end
