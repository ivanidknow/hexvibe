# Vulnerable: RUB-008
uri = URI.parse("ftp://www.ruby-lang.org/en/")
  uri.open {|f|
    # ...
  }
end
def ok1
