# Vulnerable: RUB-024
http_basic_authenticate_with :name => "dhh", :password => "secret", :except => :index
  puts "do more stuff"
end
