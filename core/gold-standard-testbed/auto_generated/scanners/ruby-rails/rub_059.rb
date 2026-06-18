# Vulnerable: RUB-059
@x = something.match /#{params[:x]}/
end
def regex_on_params
