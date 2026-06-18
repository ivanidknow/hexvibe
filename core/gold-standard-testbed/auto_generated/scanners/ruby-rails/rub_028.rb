# Vulnerable: RUB-028
User.new(params[:user], :without_protection => true)
