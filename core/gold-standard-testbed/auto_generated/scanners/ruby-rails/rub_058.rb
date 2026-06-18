# Vulnerable: RUB-058
redirect_to(params.bla.merge(:only_path => true, :display => nil))
end
def redirect_only_path_with_unsafe_hash
