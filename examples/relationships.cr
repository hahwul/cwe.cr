require "../src/cwe"

# =============================================================================
# Walking the CWE hierarchy
# =============================================================================
# Each entry carries `ChildOf` / `ParentOf` / `PeerOf` / `CanPrecede` /
# `CanFollow` edges. The catalog can resolve those to other Weakness objects
# and compute transitive closures.

target = 79

puts "── CWE-#{target} relationships ──"

w = CWE.find!(target)

puts "\nDirect parents (ChildOf):"
CWE.parents_of(target).each { |p| puts "  ↑ #{p.summary}" }

puts "\nDirect children:"
CWE.children_of(target).each { |c| puts "  ↓ #{c.summary}" }

puts "\nAncestor chain (nearest first):"
CWE.ancestors_of(target).each_with_index do |a, i|
  puts "  #{"  " * i}↑ #{a.summary}"
end

puts "\nPillar:"
if pillar = CWE.pillar_of(target)
  puts "  ▲ #{pillar.summary}"
end

puts "\nPeer-of edges:"
w.peer_relations.each do |r|
  hit = CWE.find(r.cwe_id)
  puts "  ≈ CWE-#{r.cwe_id}#{hit ? ": " + hit.name : ""}"
end

puts "\nCanPrecede edges:"
w.can_precede_relations.each do |r|
  hit = CWE.find(r.cwe_id)
  puts "  → CWE-#{r.cwe_id}#{hit ? ": " + hit.name : ""}"
end
