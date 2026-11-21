# Build script: parses MITRE's CWE XML catalog into the compact JSON file
# that the library embeds at compile time.
#
# Usage:
#   crystal run data/build_data.cr [-- path/to/cwec_vX.Y.xml]
#
# Inputs:
#   data/cwec_vX.Y.xml — MITRE's full XML catalog, unzipped from
#                        https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
#                        (the newest `data/cwec_v*.xml` is used when no path
#                        is given). Not committed because of its size.
#
# Outputs:
#   src/cwe/data/weaknesses.json
#
# The XML is the source of truth for every entry. MITRE's CSV export (which
# this script used to read for weaknesses) drops attributes such as
# `Mitigation_ID` / `Detection_Method_ID`, never fills
# `Likelihood_Of_Exploit`, joins repeated `<Phase>`s with a space, strips
# quotes and backslashes from names, mangles values containing its `::`
# separator, and leaves out deprecated entries.
require "file_utils"
require "./catalog_xml"

ROOT     = File.expand_path("..", __DIR__)
OUT_DIR  = File.join(ROOT, "src", "cwe", "data")
OUT_PATH = File.join(OUT_DIR, "weaknesses.json")

# `cwec_v4.9.xml` sorts after `cwec_v4.20.xml` as a string, so compare the
# version numerically.
def newest_xml : String?
  Dir.glob(File.join(ROOT, "data", "cwec*.xml")).max_by? do |f|
    (File.basename(f)[/[\d.]+\d/]? || "0").split('.').map(&.to_i)
  end
end

xml_path = ARGV[0]? || newest_xml || abort "no data/cwec_v*.xml found; unzip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip into data/"
abort "missing XML: #{xml_path}" unless File.exists?(xml_path)
catalog = begin
  File.open(xml_path) do |file|
    CWE::CatalogXML.parse(file, ENV["CWE_CATALOG_VERSION"]?.try(&.strip))
  end
rescue ex : XML::Error | ArgumentError
  abort "#{xml_path}: #{ex.message}"
end

%w[weaknesses categories views external_references].each do |key|
  abort "no #{key} in #{xml_path}" if catalog[key].as_a.empty?
end

FileUtils.mkdir_p(OUT_DIR)
File.write(OUT_PATH, catalog.to_json)

puts "read #{xml_path} (CWE #{catalog["catalog_version"]})"
puts "wrote #{catalog["weakness_count"]} weaknesses, #{catalog["category_count"]} categories, #{catalog["view_count"]} views, #{catalog["external_reference_count"]} refs to #{OUT_PATH}"
puts "size: #{File.size(OUT_PATH).humanize_bytes}"
