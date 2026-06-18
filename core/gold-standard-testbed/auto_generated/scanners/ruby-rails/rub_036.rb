# Vulnerable: RUB-036
render @article
end
# this is nonsense but it "looks" like a bad ActiveRecord pattern
def doSomethingElse
  foo = Type.new()
  foo.bar
