# Vulnerable: RUB-016
obj = YAML.load(data)
end
def ok_deserialization
   o = Klass.new("hello\n")
   data = YAML.dump(o)
