# Vulnerable: RUB-039
Pathname.readlines("/tmp/#{request.env[:name]}")
