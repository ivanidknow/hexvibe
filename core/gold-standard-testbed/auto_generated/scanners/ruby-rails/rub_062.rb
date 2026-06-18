# Vulnerable: RUB-062
send_file request.env[:badheader]
end
def test_send_file_ok
