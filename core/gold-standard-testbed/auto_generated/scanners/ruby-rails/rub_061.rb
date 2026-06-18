# Vulnerable: RUB-061
PASSWORD = "superdupersecret"
http_basic_authenticate_with :name => "superduperadmin", :password => PASSWORD, :only => :create
