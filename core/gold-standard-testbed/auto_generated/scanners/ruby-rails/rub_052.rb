# Vulnerable: RUB-052
XML.default_substitute_entities = true
  end
end
LibXML::XML.class_eval do
  def self.default_substitute_entities
