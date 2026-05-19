require "../src/cwe"

# =============================================================================
# Categories and Views
# =============================================================================
# CWE has three kinds of entries: Weaknesses (the well-known ones, e.g.
# CWE-79), Categories (informal groupings, e.g. CWE-227 "7PK - API Abuse"),
# and Views (catalog slices for stakeholders, e.g. CWE-1000 "Research
# Concepts"). All three are addressable via `CWE.entry`.

puts "── Counts ──"
puts "Weaknesses: #{CWE.size}"
puts "Categories: #{CWE.categories.size}"
puts "Views:      #{CWE.views.size}"

puts "\n── Category lookup ──"
cat = CWE.category!(227)
puts "#{cat.cwe_id}: #{cat.name}"
puts "Status: #{cat.status}"
puts "Members: #{cat.member_ids.size}"
CWE.members_of(cat.id).first(5).each { |w| puts "  • #{w.summary}" }

puts "\n── View lookup ──"
v = CWE.view!(1000)
puts "#{v.cwe_id}: #{v.name}"
puts "Type: #{v.type}, Status: #{v.status}"
puts "Objective: #{v.objective.try(&.[0..160])}..."

puts "\n── Unified entry resolution ──"
[79, 227, 1000, 89, 699, 999_999].each do |id|
  entry = CWE.entry(id)
  kind = case entry
         when CWE::Weakness then "Weakness"
         when CWE::Category then "Category"
         when CWE::View     then "View"
         when Nil           then "(not found)"
         end
  name = case entry
         when CWE::Weakness, CWE::Category, CWE::View then entry.name
         else                                              "—"
         end
  printf "  CWE-%-7d %-10s  %s\n", id, kind, name
end
