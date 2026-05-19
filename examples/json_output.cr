require "../src/cwe"
require "json"

# =============================================================================
# JSON serialization
# =============================================================================
# Every Weakness can be emitted as JSON. The shape is stable and snake_case
# at the top level (`cweId`, `commonConsequences`, …); empty arrays and nil
# scalars are omitted.

w = CWE.find!("CWE-79")

# Compact one-line JSON:
puts w.to_json

# Pretty-printed:
puts ""
puts JSON.parse(w.to_json).to_pretty_json
