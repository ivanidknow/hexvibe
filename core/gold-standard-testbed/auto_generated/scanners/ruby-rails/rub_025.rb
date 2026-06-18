# Vulnerable: RUB-025
io.write ca_key.export(cipher, @pass1)
  end
end
def ok
  key_pem = File.read @keypem
