# Vulnerable: IAM-AWS-AWSPrivateMarketplaceAdminFullAccess
[
  {
    "Action": [
      "organizations:RegisterDelegatedAdministrator",
      "organizations:DeregisterDelegatedAdministrator"
    ],
    "Condition": {
      "StringEquals": {
...
  }
]
