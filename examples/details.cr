require "../src/cwe"

# =============================================================================
# Rich entry details
# =============================================================================
# Each Weakness exposes the structured fields parsed from MITRE's CSV:
# consequences, mitigations, detection methods, observed examples, taxonomy
# mappings, applicable platforms, and alternate terms.

w = CWE.find!("CWE-79")

puts "── #{w.summary} ──"
puts "URL: #{w.url}"

puts "\nAlternate terms:"
w.alternate_terms.each { |t| puts "  • #{t.term}" }

puts "\nApplicable platforms:"
w.applicable_platforms.each do |p|
  puts "  • #{p.kind}: #{p.name || p.class_label} (#{p.prevalence})"
end

puts "\nCommon consequences:"
w.common_consequences.each do |c|
  puts "  • #{c.scope}: #{c.impact}"
  puts "      #{c.note}" if c.note
end

puts "\nPotential mitigations (top 3):"
w.potential_mitigations.first(3).each_with_index(1) do |m, i|
  puts "  #{i}. [#{m.phase}] #{m.strategy || "—"}"
  puts "     #{m.description.try(&.[0..160])}..."
end

puts "\nObserved examples (CVEs):"
w.observed_examples.first(5).each do |e|
  puts "  • #{e.reference}: #{e.description.try(&.[0..120])}"
end

puts "\nTaxonomy mappings:"
w.taxonomy_mappings.each do |t|
  puts "  • #{t.taxonomy_name}: #{t.entry_id} #{t.entry_name}"
end

puts "\nRelated CAPEC attack patterns:"
puts "  #{w.capec_ids.join(", ")}"
