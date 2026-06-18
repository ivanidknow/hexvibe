# Vulnerable: RUB-034
User.new(params[:user], :without_protection => true)
end
def safe_send
