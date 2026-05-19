require "json"
require "./weakness"
require "./types"

# JSON serialization for `CWE::Weakness`.
#
# The emitted shape is stable and snake_case. Empty arrays and nil scalars
# are omitted so a serialized entry is concise. The catalog identifier
# (`"CWE-79"`) is emitted as `"cweId"` alongside the integer `"id"` for
# tooling that wants either form.
#
# ```
# JSON.parse(CWE.find!(79).to_json)["cweId"].as_s # => "CWE-79"
# ```
module CWE
  class Weakness
    def to_json(json : ::JSON::Builder) : Nil
      json.object do
        json.field "id", @id
        json.field "cweId", cwe_id
        json.field "name", @name
        json.field "url", url
        json.field "abstraction", @abstraction.to_s
        json.field "status", @status.to_s

        if d = @description
          json.field "description", d
        end
        if d = @extended_description
          json.field "extendedDescription", d
        end
        if l = @likelihood_of_exploit
          json.field "likelihoodOfExploit", l
        end

        unless @related_weaknesses.empty?
          json.field "relatedWeaknesses" do
            json.array { @related_weaknesses.each(&.to_json(json)) }
          end
        end
        unless @ordinalities.empty?
          json.field "ordinalities" do
            json.array { @ordinalities.each(&.to_json(json)) }
          end
        end
        unless @applicable_platforms.empty?
          json.field "applicablePlatforms" do
            json.array { @applicable_platforms.each(&.to_json(json)) }
          end
        end
        unless @alternate_terms.empty?
          json.field "alternateTerms" do
            json.array { @alternate_terms.each(&.to_json(json)) }
          end
        end
        unless @modes_of_introduction.empty?
          json.field "modesOfIntroduction" do
            json.array { @modes_of_introduction.each(&.to_json(json)) }
          end
        end
        unless @common_consequences.empty?
          json.field "commonConsequences" do
            json.array { @common_consequences.each(&.to_json(json)) }
          end
        end
        unless @detection_methods.empty?
          json.field "detectionMethods" do
            json.array { @detection_methods.each(&.to_json(json)) }
          end
        end
        unless @potential_mitigations.empty?
          json.field "potentialMitigations" do
            json.array { @potential_mitigations.each(&.to_json(json)) }
          end
        end
        unless @observed_examples.empty?
          json.field "observedExamples" do
            json.array { @observed_examples.each(&.to_json(json)) }
          end
        end
        unless @taxonomy_mappings.empty?
          json.field "taxonomyMappings" do
            json.array { @taxonomy_mappings.each(&.to_json(json)) }
          end
        end
        unless @related_attack_patterns.empty?
          json.field "relatedAttackPatterns" do
            json.array { @related_attack_patterns.each { |c| json.number(c) } }
          end
        end
        unless @notes.empty?
          json.field "notes" do
            json.array { @notes.each(&.to_json(json)) }
          end
        end
        unless @background_details.empty?
          json.field "backgroundDetails" do
            json.array { @background_details.each { |s| json.string(s) } }
          end
        end
        unless @functional_areas.empty?
          json.field "functionalAreas" do
            json.array { @functional_areas.each { |s| json.string(s) } }
          end
        end
        unless @affected_resources.empty?
          json.field "affectedResources" do
            json.array { @affected_resources.each { |s| json.string(s) } }
          end
        end
        unless @exploitation_factors.empty?
          json.field "exploitationFactors" do
            json.array { @exploitation_factors.each { |s| json.string(s) } }
          end
        end
      end
    end
  end
end
